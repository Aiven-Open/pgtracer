"""
This module acts as a general health check for the eBPF collector.
"""
import re
from collections import defaultdict
from contextlib import ExitStack
from datetime import timedelta
from threading import Thread
from time import sleep
from unittest.mock import patch

import pytest
from flaky import flaky

from pgtracer.ebpf.collector.querytracer import (
    InstrumentationFlags,
    QueryTracerEventHandler,
)
from pgtracer.utils import timespec_to_timedelta as tstimedelta


def wait_for_collector(collector):
    """
    Wait for the collector to have at least one query.
    """
    tries = 0
    process_info = collector.event_handler.per_process_info[collector.pid]
    while len(process_info.query_history) == 0 and tries < 1000:
        tries += 1
        sleep(0.05)


def test_basic_ebf_collector(querytracer, connection):
    """
    Test the most basic functionality of the ebpf collector works.
    """
    # Now try running a query, and see if we can get it back
    with connection.execute("SELECT now()") as cur:
        querystart = cur.fetchall()[0][0].replace(microsecond=0, tzinfo=None)
    wait_for_collector(querytracer)
    assert len(querytracer.event_handler.per_process_info) == 1
    process_info = querytracer.event_handler.per_process_info[querytracer.pid]
    assert len(process_info.query_history) == 1
    query = process_info.query_history[0]
    assert query.text == "SELECT now()"
    assert query.search_path == '"$user", public'
    assert query.start_datetime.replace(microsecond=0) == querystart
    assert query.runtime is None
    assert query.instrument.need_timer.value is False
    assert query.instrument.need_bufusage.value is False
    assert query.shared_buffers_hitratio is None
    assert query.syscache_hitratio is None


def test_instrumentation(querytracer_instrumented, connection):
    """
    Test that turning instrumentation on works as expected.
    """
    connection.execute("SET track_io_timing = on")
    # We want to have at least a few system reads, so do what is necessary...
    with open("/proc/sys/vm/drop_caches", "wb") as procf:
        procf.write(b"1")

    with connection.execute("SELECT * FROM pg_attribute") as cur:
        cur.fetchall()
    wait_for_collector(querytracer_instrumented)
    assert len(querytracer_instrumented.event_handler.per_process_info) == 1
    process_info = querytracer_instrumented.event_handler.per_process_info[
        querytracer_instrumented.pid
    ]

    assert len(process_info.query_history) == 1
    query = process_info.query_history[0]
    assert query.instrument.need_timer.value is True
    assert query.instrument.need_bufusage.value is True
    assert query.runtime > timedelta(0)
    assert query.instrument.bufusage.shared_blks_hit.value > 0
    assert query.instrument.bufusage.shared_blks_read.value >= 0
    assert query.instrument.bufusage.temp_blks_read.value == 0
    assert query.instrument.bufusage.temp_blks_written.value == 0
    if connection.info.server_version >= 150000:
        assert tstimedelta(query.instrument.bufusage.temp_blk_read_time) == timedelta(0)
        assert tstimedelta(query.instrument.bufusage.temp_blk_write_time) == timedelta(
            0
        )
    # We can't make any assumptions about the hit ratios, so just ensure they
    # have some valid values.
    assert 0 <= query.shared_buffers_hitratio < 100
    # The syscache_hitratio can be negative, when we actually end up reading
    # more blocks than what is accounted for by instrumentation.
    assert query.syscache_hitratio <= 100

    # Check that we don't crash without any instrumentation whatshowever
    query.instrument = None
    assert query.shared_buffers_hitratio is None
    assert query.syscache_hitratio is None

    # Generate some temp files for fun
    process_info.query_history = []
    connection.execute("SET work_mem = '64kB'")
    with connection.execute("SELECT * FROM generate_series(1, 10000) as t"):
        pass
    wait_for_collector(querytracer_instrumented)
    query = process_info.query_history[0]
    assert query.text == "SELECT * FROM generate_series(1, 10000) as t"
    assert query.instrument.bufusage.temp_blks_read.value > 0
    assert query.instrument.bufusage.temp_blks_written.value > 0
    if connection.info.server_version >= 150000:
        assert tstimedelta(query.instrument.bufusage.temp_blk_read_time) > timedelta(0)
        assert tstimedelta(query.instrument.bufusage.temp_blk_write_time) > timedelta(0)

    # Now do the same query with a big enough work_mem to trigger some memory allocations
    connection.execute("SET work_mem = '32MB'")
    process_info.query_history = []
    with connection.execute("SELECT * FROM generate_series(1, 10000) as t") as cur:
        pass
    wait_for_collector(querytracer_instrumented)
    query = process_info.query_history[0]
    # The reparatition between sbrk / mmap and wether we move sbrk back to it's initial
    # value depends on the state of malloc and it's configuration. So best thing we can test is that "something"
    # happened
    assert query.memallocs.current_mem_peak > 0
    # We can't assert anything meaningful about total_malloc but we can at least exercise the code
    assert query.memallocs.total_malloc is not None


def test_plans(querytracer_instrumented, connection):
    """
    Test that we are able to build a plans.
    """
    with connection.execute(
        "SELECT * FROM (SELECT * FROM pg_class ORDER BY reltype LIMIT 10) t"
    ) as cur:
        cur.fetchall()
    wait_for_collector(querytracer_instrumented)
    process_info = querytracer_instrumented.event_handler.per_process_info[
        querytracer_instrumented.pid
    ]
    query = process_info.query_history[0]
    root_node = query.root_node
    NodeTag = querytracer_instrumented.metadata.enums.NodeTag
    assert root_node.tag == NodeTag.T_Limit
    assert len(root_node.children) == 1
    assert root_node.parent_node is None
    assert root_node.instrument.tuplecount.value == 10

    sort_node = list(root_node.children)[0]
    assert sort_node.tag == NodeTag.T_Sort
    assert len(sort_node.children) == 1
    assert sort_node.parent_node == root_node
    # FIXME: investigate why we can't fetch this value on ubuntu's PG11.
    if connection.info.server_version >= 120000:
        assert sort_node.instrument.tuplecount.value == 10

    seqscan_node = list(sort_node.children)[0]
    assert seqscan_node.tag == NodeTag.T_SeqScan
    assert len(seqscan_node.children) == 0
    assert seqscan_node.parent_node == sort_node


def test_explain(querytracer, connection):
    """
    Test that we are able to build a plans.
    """
    # We have some trouble with collecting instrumentation for PG < 12
    if connection.info.server_version < 120000:
        return
    cost_snippet = r"\d+\.\d+\..\d+\.\d+"
    wanted_plan = rf"""Limit \(cost={cost_snippet} rows=10 width=\d+\) \(actual time=0.000...0.000 rows=0 loops=1\)
\t-> Sort \(cost={cost_snippet} rows=\d+ width=\d+\) \(actual time=0.000...0.000 rows=0 loops=1\)
\t\t-> SeqScan \(cost={cost_snippet} rows=\d+ width=\d+\) \(actual time=0.000...0.000 rows=0 loops=1\)"""

    with connection.execute(
        "SELECT * FROM (SELECT * FROM pg_class ORDER BY reltype LIMIT 10) t"
    ) as cur:
        cur.fetchall()
    wait_for_collector(querytracer)
    assert len(querytracer.event_handler.per_process_info) == 1
    process_info = querytracer.event_handler.per_process_info[querytracer.pid]
    query = process_info.query_history[0]
    root_node = query.root_node
    assert re.match(wanted_plan, root_node.explain())


def background_query(connection, query):
    def execute_query():
        with connection.execute(query) as cur:
            cur.fetchall()

    newthread = Thread(target=execute_query)
    newthread.start()
    return newthread


@pytest.mark.slow
def test_long_query(querytracer_instrumented, connection):
    events = defaultdict(int)

    def event_handler_observer(method_name):
        original_method = getattr(QueryTracerEventHandler, method_name)

        def observe_event_handler(event_handler, bpf_collector, event, pid):
            events[method_name] += 1
            return original_method(event_handler, bpf_collector, event, pid)

        return observe_event_handler

    with ExitStack() as stack:
        for meth_name in (
            "handle_MemoryResponseNodeInstr",
            "handle_MemoryResponseQueryInstr",
        ):
            stack.enter_context(
                patch(
                    f"pgtracer.ebpf.collector.querytracer.QueryTracerEventHandler.{meth_name}",
                    event_handler_observer(meth_name),
                )
            )
        with connection.execute(
            """SELECT count(*) FROM (
            SELECT pg_sleep(0.01)
            FROM pg_class
            JOIN pg_attribute ON pg_class.oid = attrelid
            ) as s """
        ) as cur:
            cur.fetchall()
        wait_for_collector(querytracer_instrumented)
    assert events["handle_MemoryResponseQueryInstr"] > 0
    assert events["handle_MemoryResponseNodeInstr"] > 0


@pytest.mark.slow
@flaky(max_runs=5)
def test_query_discovery(querytracer_factory, connection):
    """
    Test that information is gathered during a query.
    """
    events = defaultdict(int)

    def event_handler_observer(method_name):
        original_method = getattr(QueryTracerEventHandler, method_name)

        def observe_event_handler(event_handler, bpf_collector, event, pid):
            events[method_name] += 1
            return original_method(event_handler, bpf_collector, event, pid)

        return observe_event_handler

    with ExitStack() as stack:
        for meth_name in ("handle_StackSample", "handle_MemoryNodeData"):
            stack.enter_context(
                patch(
                    f"pgtracer.ebpf.collector.querytracer.QueryTracerEventHandler.{meth_name}",
                    event_handler_observer(meth_name),
                )
            )
        thread = background_query(
            connection,
            """SELECT count(*) FROM (
            SELECT pg_sleep(0.01)
            FROM pg_class
            JOIN pg_attribute ON pg_class.oid = attrelid
            ) as s """,
        )
        # Now set up the collector.
        collector = None
        try:
            collector = querytracer_factory(
                instrument_flags=InstrumentationFlags.ALL,
                enable_perf_events=True,
                enable_query_discovery=True,
                enable_nodes_collection=True,
                sample_freq=1200,
            )
            # And wait for the query to finish
            thread.join()
            # Wait a few seconds more to make sure collector has gathered all info
            sleep(3)
        finally:
            if collector is not None:
                collector.stop()
    assert events["handle_StackSample"] > 0
    assert events["handle_MemoryNodeData"] > 0
