"""
Classes storing information about memory allocations.
"""

import ctypes as ct
from dataclasses import dataclass
from enum import IntEnum


# pylint: disable=invalid-name
class MemoryAllocType(IntEnum):
    """
    MemoryAllocation types.
    """

    Sbrk = 1
    Mmap = 2


class memory_account(ct.Structure):
    """
    Represents the data associated to a memory allocation or deallocation.
    """

    _fields_ = [
        ("event_type", ct.c_short),
        ("size", ct.c_longlong),
        ("kind", ct.c_short),
    ]


@dataclass
class MemoryAllocations:
    """
    Memory allocation counters.
    """

    mmap_alloc: int = 0
    mmap_free: int = 0
    sbrk_alloc: int = 0
    sbrk_free: int = 0

    current_running_mmap: int = 0
    current_running_sbrk: int = 0

    current_mem_peak: int = 0

    @property
    def mmap_total(self):
        """
        Compute the resulting mmaped total.
        """
        return self.mmap_alloc - self.mmap_free

    @property
    def sbrk_total(self):
        """
        Compute the resulting sbrk total.
        """
        return self.sbrk_alloc - self.sbrk_free

    @property
    def total_malloc(self):
        """
        Compute the total memory diff.
        """
        return self.mmap_total + self.sbrk_total

    def update(self, memory_account: memory_account):
        """
        Update the current totals.
        """
        if memory_account.kind == MemoryAllocType.Sbrk:
            self.current_running_sbrk += memory_account.size
            if memory_account.size > 0:
                self.sbrk_alloc += memory_account.size
            else:
                self.sbrk_free += -memory_account.size
        elif memory_account.kind == MemoryAllocType.Mmap:
            self.current_running_mmap += memory_account.size
            if memory_account.size > 0:
                self.mmap_alloc += memory_account.size
            else:
                self.mmap_free += -memory_account.size
        self.current_mem_peak = max(
            self.current_mem_peak, self.current_running_sbrk + self.current_running_mmap
        )
