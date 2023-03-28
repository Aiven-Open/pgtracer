"""
This simple script reads and writes GUCs in a running PostgreSQL backend
"""
import argparse

from pgtracer.ebpf.collector.guc import GUCTracerBPFCollector, GUCTracerOptions


def main() -> None:
    """
    Entry point for the pgtrace_gucs script.
    """
    parser = argparse.ArgumentParser(
        description="Run and / or write GUCs from a running PostgreSQL backend."
    )
    parser.add_argument("pid", type=int, help="PID to connect to")

    parser.add_argument(
        "--set-guc",
        metavar="GUC=VALUE",
        dest="set_gucs",
        nargs="+",
        default=[],
        help="Set a number of GUCs in the running backend",
    )

    args = parser.parse_args()
    pid = args.pid

    # Parse the set-guc option.
    set_gucs = {}
    for keyvalue in args.set_gucs:
        key, value = keyvalue.split("=")
        set_gucs[key] = value
    options = GUCTracerOptions()

    collector = GUCTracerBPFCollector.from_pid(pid, options)
    collector.start()
    print(f"Backend is of type {str(collector.backend_type)}")
    seen = set()
    for gucname, gucvalue in set_gucs.items():
        collector.set_guc(gucname, gucvalue)
    while True:
        with collector.lock:
            for guc in collector.guc_defs.values():
                if guc.guc_name is not None:
                    seen.add(guc.guc_name)


if __name__ == "__main__":
    main()
