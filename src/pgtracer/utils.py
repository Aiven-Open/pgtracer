"""
Miscellaneous utility functions.
"""

import functools
import itertools
import re
import subprocess
from datetime import timedelta
from typing import TYPE_CHECKING, BinaryIO, Optional

from pypsutil import Process

if TYPE_CHECKING:
    from ctypes import _CData
else:
    _CData = object


def timespec_to_timedelta(timespec: _CData) -> timedelta:
    """
    Convert a timespec_t or instr_time struct to a timedelta.
    """
    # Can't really compare it to a proper class, so test on the class name
    if timespec.__class__.__name__ == "timespec":
        return timedelta(
            seconds=timespec.tv_sec.value,  # type: ignore
            microseconds=timespec.tv_nsec.value / 1000,  # type: ignore
        )
    if timespec.__class__.__name__ == "instr_time":
        return timedelta(seconds=timespec.ticks.value / 1000000000)  # type: ignore
    raise ValueError("Expecting a timespec or instr_time struct")


def timespec_to_float(timespec: _CData) -> float:
    """
    Convert a timespec_t or instr_time struct to a float representing the number of seconds.
    """
    if timespec.__class__.__name__ == "timespec":
        return float(timespec.tv_sec.value + timespec.tv_nsec.value / 1000000000)  # type: ignore
    if timespec.__class__.__name__ == "instr_time":
        return float(timespec.ticks.value / 1000000000)  # type: ignore
    raise ValueError("Expecting a timespec or instr_time struct")


NSPID_PARSING_RE = re.compile(rb"^NSpid:\s+((?:(?:\d+)\s*)+)")


def resolve_container_pid(container: str, container_pid: int) -> Optional[int]:
    """
    Resolve container_pid from the systemd-nspawn container `container`
    to a host pid.
    """
    # FIXME: this probably does not handle nested namespaces.
    completed_process = subprocess.run(
        ["machinectl", "show", container, "-p", "Leader"],
        capture_output=True,
        check=True,
    )
    container_leader_pid = int(completed_process.stdout.split(b"=")[1])
    # Now iterate over all child processes from this container.
    leader_process = Process(container_leader_pid)
    for child in leader_process.children(recursive=True):
        with open(f"/proc/{child.pid}/status", "rb") as statf:
            for line in statf:
                nspid_match = NSPID_PARSING_RE.match(line)
                if nspid_match:
                    ns_pids = list(map(int, nspid_match.group(1).strip().split(b"\t")))
                    if ns_pids[-1] == container_pid:
                        return ns_pids[0]
    return None


def readcstr(filelike: BinaryIO) -> bytes:
    """
    Read a NULL terminated C-string from a BinaryIO
    Courtesy of https://stackoverflow.com/a/32775270
    """
    toeof = iter(functools.partial(filelike.read, 1), b"")
    return b"".join(itertools.takewhile(b"\0".__ne__, toeof))
