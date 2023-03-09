"""
Pytest fixtures.
"""

import os
import re
import subprocess
from pathlib import Path
from pwd import getpwnam
from tempfile import TemporaryDirectory
from typing import Iterator

import port_for
import psycopg
import pytest
from pytest import FixtureRequest
from pytest_postgresql.config import get_config
from pytest_postgresql.executor import PostgreSQLExecutor
from pytest_postgresql.executor_noop import NoopExecutor

from pgtracer.ebpf.collector import (
    CollectorOptions,
    InstrumentationFlags,
    QueryTracerBPFCollector,
)
from pgtracer.ebpf.guc import GUCTracerBPFCollector
from pgtracer.utils import resolve_container_pid


def pytest_addoption(parser):
    """
    Add the required options to pytest.
    """
    parser.addoption(
        "--container",
        help="Set this if the backend we are testing against is "
        "running inside a container.",
    )


def pytest_configure(config):
    """
    Add used markers.
    """
    config.addinivalue_line(
        "markers", "slow: mark test as being 'slow', allowing to skip it"
    )


@pytest.fixture(scope="session")
def nonroot_postgres(request: FixtureRequest) -> Iterator[PostgreSQLExecutor]:
    """
    Returns a PostgreSQLExecutor to a newly created instance, running as the
    postgres user.

    FIXME: make the unix user used to run the instance configurable.
    """

    config = get_config(request)

    # If we have a host, use that instead of creating a new instance.
    if request.config.getoption("postgresql_host"):
        postgresql_executor = NoopExecutor(
            config.get("host"), 5432, "postgres", {}, "postgres"
        )
        postgresql_executor.unixsocketdir = None
        yield postgresql_executor
        return

    postgresql_ctl = config["exec"]

    if not os.path.exists(postgresql_ctl):
        pg_bindir = subprocess.check_output(
            ["pg_config", "--bindir"], universal_newlines=True
        ).strip()
        postgresql_ctl = os.path.join(pg_bindir, "pg_ctl")

    pg_passwd = getpwnam("postgres")

    with TemporaryDirectory() as tempdir_str:
        tmpdir = Path(tempdir_str)
        os.chown(tmpdir, pg_passwd.pw_uid, pg_passwd.pw_gid)
        pg_port = port_for.select_random()
        datadir = tmpdir / f"data-{pg_port}"
        unix_socket_dir = tmpdir / "unix-socket"
        postgresql_executor = PostgreSQLExecutor(
            executable=postgresql_ctl,
            shell=True,
            port=pg_port,
            host="localhost",
            unixsocketdir=str(unix_socket_dir),
            logfile=str(tmpdir / "pg_log"),
            dbname="postgres",
            startparams="",
            datadir=str(datadir),
        )
        postgresql_executor.VERSION_RE = re.compile(
            ".* (?P<version>\\d+((\\.\\d+)|beta\\d|rc\\d|dev))"
        )
        pid = os.fork()
        if pid == 0:
            try:
                os.setuid(pg_passwd.pw_uid)
                os.chdir(str(tmpdir))
                datadir.mkdir()
                unix_socket_dir.mkdir()
                postgresql_executor.start()
                postgresql_executor.wait_for_postgres()
            except Exception as exc:  # pylint: disable=broad-except
                print(exc)
                os._exit(1)  # pylint: disable=protected-access
            finally:
                os._exit(0)  # pylint: disable=protected-access
        else:
            pid, return_code = os.waitpid(pid, 0)
            if return_code != 0:
                raise Exception("Could not start postgresql")
            try:
                yield postgresql_executor
            finally:
                pid = os.fork()
                if pid == 0:
                    try:
                        os.setuid(pg_passwd.pw_uid)
                        postgresql_executor.stop()
                    finally:
                        os._exit(0)  # pylint: disable=protected-access
                os.waitpid(pid, 0)


@pytest.fixture
def connection(nonroot_postgres):  # pylint: disable=redefined-outer-name
    """
    Returns a connection to the temporary postgresql instance.
    """
    conn = psycopg.connect(
        port=nonroot_postgres.port,
        host=nonroot_postgres.unixsocketdir or nonroot_postgres.host,
        user=nonroot_postgres.user,
    )
    yield conn
    conn.close()


def make_collector(
    cls, connection, config, **kwargs
):  # pylint: disable=redefined-outer-name
    """
    Create a collector from a connection.
    """
    backend_pid = connection.info.backend_pid
    if config.getoption("container"):
        # If we have a container, look into it to translate the backend_pid
        # to the host namespace.
        backend_pid = resolve_container_pid(config.getoption("container"), backend_pid)
    options = cls.options_cls(**kwargs)
    collector = cls.from_pid(pid=backend_pid, options=options)
    collector.start()
    return collector


@pytest.fixture
def querytracer_factory(connection, request):
    def factory_func(**kwargs):
        kwargs.setdefault("enable_nodes_collection", True)
        return make_collector(
            QueryTracerBPFCollector, connection, request.config, **kwargs
        )

    return factory_func


@pytest.fixture
def querytracer(
    request: FixtureRequest, connection
):  # pylint: disable=redefined-outer-name
    """
    Returns a bpfcollector associated to the current connection.
    """
    collector = make_collector(
        QueryTracerBPFCollector,
        connection,
        request.config,
        enable_nodes_collection=True,
    )
    yield collector
    collector.stop()


@pytest.fixture
def querytracer_instrumented(
    request: FixtureRequest, connection
):  # pylint: disable=redefined-outer-name
    """
    Returns a bpfcollector with instrumentation turned on.
    """
    collector = make_collector(
        QueryTracerBPFCollector,
        connection,
        request.config,
        instrument_flags=InstrumentationFlags.ALL,
        enable_perf_events=True,
        enable_query_discovery=True,
        enable_nodes_collection=True,
    )
    yield collector
    collector.stop()


@pytest.fixture
def guctracer(request: FixtureRequest, connection):
    """
    Fixture returning an instance of a GUCTracer.
    """
    collector = make_collector(GUCTracerBPFCollector, connection, request.config)
    yield collector
    collector.stop()
