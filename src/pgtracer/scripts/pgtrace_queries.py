"""
This simple script trace queries executed by a Postgres backend.
"""

import argparse
import sys
import time
from datetime import timedelta
from typing import Any, Dict

from pgtracer.ebpf.collector import (
    BPF_Collector,
    CollectorOptions,
    InstrumentationFlags,
)
from pgtracer.ebpf.dwarf import Struct
from pgtracer.model.query import Query


def dump_dict(somedict: Dict[str, Any], indent: int = 0) -> str:
    """
    Dump a dictionary as an indented string of key / value pairs.
    """
    parts = []
    tabs = "\t" * indent
    for key, value in somedict.items():
        if isinstance(value, Struct):
            # Special case for timespec
            if value.__class__.__name__ == "timespec":
                value = timedelta(
                    seconds=value.tv_sec.value,
                    microseconds=value.tv_nsec.value / 1000,
                )
            else:
                value = value.as_dict(include_all=True)
        if isinstance(value, dict):
            part = "\n" + dump_dict(value, indent + 1)
        else:
            if hasattr(value, "value"):
                part = value.value
            else:
                part = value
        parts.append(f"{tabs}{key}: {part}")
    return "\n".join(parts)


def print_query(query: Query, options: CollectorOptions) -> None:
    """
    Print a query according to which collector options have been set.
    """
    parts = []
    start = "<unknown>"
    if query.start_datetime is not None:
        start = query.start_datetime.isoformat()
    parts.append(f"{start} {query.text}")
    mapping = {}
    mapping["search_path"] = query.search_path
    mapping["query_id"] = str(query.query_id) or "<unavailable>"
    mapping["startup_cost"] = str(query.startup_cost)
    mapping["total_cost"] = str(query.total_cost)
    mapping["plan_rows"] = str(query.plan_rows)
    if options.instrument_flags & InstrumentationFlags.TIMER:
        mapping["runtime"] = str(query.runtime)
    if options.instrument_flags & InstrumentationFlags.BUFFERS:
        mapping["written_bytes_to_disk"] = str(query.io_counters["W"])
        if query.shared_buffers_hitratio is not None:
            mapping["shared_buffers_hitratio"] = f"{query.shared_buffers_hitratio:0.2f}"
        else:
            mapping["shared_buffers_hitratio"] = None
        if query.syscache_hitratio is not None:
            mapping["syscache_hitratio"] = f"{query.syscache_hitratio:0.2f}"
        else:
            mapping["syscache_hitratio"] = None
        if query.instrument:
            mapping["buffer_usage"] = query.instrument.bufusage
    if options.instrument_flags & InstrumentationFlags.WAL and query.instrument:
        mapping["wal_usage"] = query.instrument.walusage
    print(query.text)
    print(dump_dict(mapping, 1))
    if options.enable_nodes_collection:
        print(query.root_node.explain())


def print_running_query(query: Query, first_time: bool) -> None:
    """
    Print the currently running query.
    """
    if first_time:
        print("Currently running:")
        print(query.text)
        print("Tuples produced / tuple expected")
        print("")
    print("\x1b[1A", end="")
    print("\x1b[2K", end="")
    print(f"{int(query.instrument.tuplecount.value)} / {int(query.plan_rows)}")


def main() -> None:
    """
    Entry point for the pgtrace_queries script.
    """
    parser = argparse.ArgumentParser(
        description="Dump a running backend execution plan"
    )
    parser.add_argument("pid", type=int, help="PID to connect to")
    parser.add_argument(
        "--instrument",
        "-I",
        type=str,
        default=None,
        nargs="*",
        choices=[flag.name for flag in InstrumentationFlags],
        action="extend",
        help="""Instrument flags to set. (warning: writes into backends
        memory!)""",
    )
    parser.add_argument(
        "--nodes-collection",
        "-n",
        default=False,
        action="store_true",
        help="""Collect information about individual execution nodes""",
    )

    args = parser.parse_args()
    pid = args.pid
    instrument_flags = 0
    if args.instrument:
        for flag in args.instrument:
            instrument_flags |= InstrumentationFlags[flag]
    options = CollectorOptions(
        instrument_flags=instrument_flags,
        enable_nodes_collection=args.nodes_collection,
        enable_perf_events=instrument_flags != 0,
    )
    collector = BPF_Collector.from_pid(pid, options)
    collector.start()
    total_queries = 0
    last_running_query = None
    while True:
        try:
            time.sleep(1)
            if not collector.event_handler.query_history and collector.current_query:
                print_running_query(
                    collector.current_query,
                    last_running_query is not collector.current_query,
                )
                last_running_query = collector.current_query
                continue
            last_running_query = None
            for query in collector.event_handler.query_history:
                print_query(query, options)
            total_queries += len(collector.event_handler.query_history)
            collector.event_handler.query_history = []
        except KeyboardInterrupt:
            collector.stop()
            sys.exit(0)


if __name__ == "__main__":
    main()
