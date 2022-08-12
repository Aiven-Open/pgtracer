"""
Miscellaneous utility functions.
"""

from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _CData
else:
    _CData = object


def timespec_to_timedelta(timespec: _CData) -> timedelta:
    """
    Convert a timespec_t struct to a timedelta.
    """
    return timedelta(
        seconds=timespec.tv_sec.value,  # type: ignore
        microseconds=timespec.tv_nsec.value / 1000,  # type: ignore
    )
