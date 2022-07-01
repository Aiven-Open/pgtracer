"""
This simple script trace queries executed by a Postgres backend.
"""

import argparse
import sys

from pgtracer.ebpf.collector import BPF_Collector


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
                mapping["runtime"] = str(query.runtime)

                for key, value in mapping.items():
                    parts.append(f"\t{key}: {value}")
                print("\n".join(parts))
                print("")
            collector.event_handler.query_history = []
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
