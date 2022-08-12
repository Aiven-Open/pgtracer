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

from pgtracer.ebpf.collector import BPF_Collector


@pytest.fixture(scope="session")
def nonroot_postgres(request: FixtureRequest) -> Iterator[PostgreSQLExecutor]:
    """
    Returns a PostgreSQLExecutor to a newly created instance, running as the
    postgres user.

    FIXME: make the unix user used to run the instance configurable.
    """

    config = get_config(request)

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
            ".* (?P<version>\\d+((\\.\\d+)|beta\\d|dev))"
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
            except Exception as e:
                os._exit(1)
            finally:
                os._exit(0)  # pylint: disable=protected-access
        else:
            pid, rv = os.waitpid(pid, 0)
            if rv != 0:
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
        host=nonroot_postgres.unixsocketdir,
        user=nonroot_postgres.user,
    )
    yield conn
    conn.close()


def make_collector(connection, **kwargs):  # pylint: disable=redefined-outer-name
    """
    Create a collector from a connection.
    """
    backend_pid = connection.info.backend_pid
    collector = BPF_Collector(pid=backend_pid, **kwargs)
    collector.start()
    return collector


@pytest.fixture
def bpfcollector(connection):  # pylint: disable=redefined-outer-name
    """
    Returns a bpfcollector associated to the current connection.
    """
    yield make_collector(connection)


@pytest.fixture
def bpfcollector_instrumented(connection):  # pylint: disable=redefined-outer-name
    """
    Returns a bpfcollector with instrumentation turned on.
    """
    yield make_collector(connection, instrument_options=2147483647)
