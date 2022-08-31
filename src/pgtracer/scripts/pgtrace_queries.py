"""
This simple script trace queries executed by a Postgres backend.
"""

import argparse
import sys
from datetime import timedelta
from typing import Any, Dict

from pgtracer.ebpf.collector import BPF_Collector
from pgtracer.ebpf.dwarf import Struct


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
        type=int,
        default=None,
        help="Instrument flags to set (warning: writes into backends memory!)",
    )

    args = parser.parse_args()
    pid = args.pid

    collector = BPF_Collector(pid, instrument_options=args.instrument)

    while True:
        try:
            collector.poll(1000)

            for query in collector.event_handler.query_history:
                parts = []
                start = "<unknown>"
                if query.start_datetime is not None:
                    start = query.start_datetime.isoformat()
                parts.append(f"{start} {query.text}")
                mapping = {}
                mapping["search_path"] = query.search_path
                if args.instrument > 0 and query.instrument:
                    mapping["runtime"] = str(query.runtime)
                    mapping["buffer_usage"] = query.instrument.bufusage
                    mapping["wal_usage"] = query.instrument.walusage
                print(query.text)
                print(dump_dict(mapping, 1))
                print(query.root_node.explain())
            collector.event_handler.query_history = []
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
