"""
This simple script trace queries executed by a Postgres backend.
"""

import argparse
import sys
import time
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, Optional

from pgtracer.ebpf.collector.querytracer import (
    InstrumentationFlags,
    QueryTracerBPFCollector,
    QueryTracerOptions,
)
from pgtracer.ebpf.dwarf import Struct
from pgtracer.model.query import Query
from pgtracer.utils import timespec_to_timedelta


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
                try:
                    value = timespec_to_timedelta(value)
                except OverflowError:
                    # Ignore overflowing timespecs
                    continue
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


def print_query(query: Query, options: QueryTracerOptions) -> None:
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
    mapping["peak_mem_alloc"] = str(query.memallocs.current_mem_peak)
    if query.instrument.need_timer:
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


LINE_UP = "\033[1A"
LINE_CLEAR = "\x1b[2K"


def print_running_query(
    query: Query, print_plan: bool, first_time: bool, clear_line: int = 0
) -> int:
    """
    Print the currently running query.
    """
    nb_lines = 0
    if first_time:
        print("Currently running:")
        print(query.text)
        if not print_plan:
            print("Tuples produced / tuple expected")
            print("")
    for _ in range(clear_line):
        print(LINE_UP, end=LINE_CLEAR)
    if print_plan and query.root_node:
        plan = query.root_node.explain()
        nb_lines = len(plan.split("\n"))
        print(plan)
    else:
        print(f"{int(query.instrument.tuplecount.value)} / {int(query.plan_rows)}")
    return nb_lines


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
    options = QueryTracerOptions(
        instrument_flags=instrument_flags,
        enable_nodes_collection=args.nodes_collection,
        enable_perf_events=instrument_flags != 0,
    )
    collector = QueryTracerBPFCollector.from_pid(pid, options)
    collector.start()
    total_queries = 0
    last_running_query: Dict[int, Optional[Query]] = defaultdict(lambda: None)
    lines_to_clear = 0
    while collector.is_running:
        try:
            time.sleep(1)
            for (
                pid,
                process_info,
            ) in collector.event_handler.per_process_info.copy().items():
                if not process_info.query_history and process_info.current_query:
                    first_time = (
                        last_running_query[pid] is not process_info.current_query
                    )
                    if first_time:
                        lines_to_clear = 0
                    lines_to_clear = print_running_query(
                        process_info.current_query,
                        options.enable_nodes_collection,
                        first_time,
                        lines_to_clear,
                    )
                    last_running_query[pid] = process_info.current_query
                    continue
                last_running_query[pid] = None
                for query in process_info.query_history:
                    print_query(query, options)
                total_queries += len(process_info.query_history)
                process_info.query_history = []
        except KeyboardInterrupt:
            break
    collector.stop()
    total_processes = len(collector.event_handler.process_history) + len(
        collector.event_handler.per_process_info
    )
    print(f"Processed {total_queries} queries among {total_processes} processes")


if __name__ == "__main__":
    main()
