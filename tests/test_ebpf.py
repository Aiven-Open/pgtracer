"""
This module acts as a general health check for the eBPF collector.
"""
from datetime import timedelta
from time import sleep

from pgtracer.utils import timespec_to_timedelta as tstimedelta


def wait_for_collector(collector):
    """
    Wait for the collector to have at least one query.
    """
    tries = 0
    while len(collector.event_handler.query_history) == 0 and tries < 1000:
        tries += 1
        sleep(0.05)


def test_basic_ebf_collector(bpfcollector, connection):
    """
    Test the most basic functionality of the ebpf collector works.
    """
    # Now try running a query, and see if we can get it back
    with connection.execute("SELECT now()") as cur:
        querystart = cur.fetchall()[0][0].replace(microsecond=0, tzinfo=None)
    wait_for_collector(bpfcollector)
    assert len(bpfcollector.event_handler.query_history) == 1
    query = bpfcollector.event_handler.query_history[0]
    assert query.text == "SELECT now()"
    assert query.search_path == '"$user", public'
    assert query.start_datetime.replace(microsecond=0) == querystart
    assert query.runtime == timedelta(0)
    assert query.instrument.need_timer.value is False
    assert query.instrument.need_bufusage.value is False


def test_instrumentation(bpfcollector_instrumented, connection):
    """
    Test that turning instrumentation on works as expected.
    """
    connection.execute("SET track_io_timing = on")
    with connection.execute("SELECT * FROM pg_class") as cur:
        cur.fetchall()
    wait_for_collector(bpfcollector_instrumented)

    assert len(bpfcollector_instrumented.event_handler.query_history) == 1
    query = bpfcollector_instrumented.event_handler.query_history[0]
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

    # Generate some temp files for fun
    bpfcollector_instrumented.event_handler.query_history = []
    connection.execute("SET work_mem = '64kB'")
    with connection.execute("SELECT * FROM generate_series(1, 10000) as t"):
        pass
    wait_for_collector(bpfcollector_instrumented)
    query = bpfcollector_instrumented.event_handler.query_history[0]
    assert query.text == "SELECT * FROM generate_series(1, 10000) as t"
    assert query.instrument.bufusage.temp_blks_read.value > 0
    assert query.instrument.bufusage.temp_blks_written.value > 0
    if connection.info.server_version >= 150000:
        assert tstimedelta(query.instrument.bufusage.temp_blk_read_time) > timedelta(0)
        assert tstimedelta(query.instrument.bufusage.temp_blk_write_time) > timedelta(0)


def test_plans(bpfcollector_instrumented, connection):
    """
    Test that we are able to build a plans.
    """
    with connection.execute(
        "SELECT * FROM (SELECT * FROM pg_class ORDER BY reltype LIMIT 10) t"
    ) as cur:
        cur.fetchall()
    wait_for_collector(bpfcollector_instrumented)
    query = bpfcollector_instrumented.event_handler.query_history[0]
    root_node = query.root_node
    NodeTag = bpfcollector_instrumented.metadata.enums.NodeTag
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
