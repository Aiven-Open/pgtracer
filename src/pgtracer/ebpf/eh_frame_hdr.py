"""
This module contains code for parsing an .eh_frame_hdr section.
"""
from __future__ import annotations

import struct
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Iterable, Optional, Tuple, no_type_check

from elftools.dwarf.callframe import CallFrameInfo
from elftools.dwarf.enums import DW_EH_encoding_flags
from elftools.elf.elffile import ELFFile

if TYPE_CHECKING:
    from elftools.dwarf.callframe import CFIEntry
    from elftools.elf.sections import Section

DW_EH_Encoding = IntEnum("DW_EH_Encoding", DW_EH_encoding_flags)  # type: ignore


class EhFrameHdr:
    """
    Parsed .eh_frame_hdr section
    """

    def __init__(self, section: Section, elffile: ELFFile):
        self.elffile = elffile
        self.section = section
        self.offset = self.section.global_offset
        self.eh_frame_hdr_start = self.section.stream.tell()
        # First read the fixed header
        (
            self.version,
            self.eh_frame_ptr_enc,
            self.fde_count_enc,
            self.table_enc,
        ) = self._unpack_from("<4B", offset=0)
        self.frame_ptr: int = self.read_value(self.eh_frame_ptr_enc)  # type: ignore
        self.fde_count: int = self.read_value(self.fde_count_enc)  # type: ignore
        self.table_start = self.section.stream.tell()
        self.dwarf_info = elffile.get_dwarf_info()
        self.cfi = CallFrameInfo(
            stream=self.dwarf_info.eh_frame_sec.stream,
            size=self.dwarf_info.eh_frame_sec.size,
            address=self.dwarf_info.eh_frame_sec.address,
            base_structs=self.dwarf_info.structs,
            for_eh_frame=True,
        )

    @no_type_check
    def read_value(
        self,
        encoding: int,
        offset: Optional[int] = None,
        relative: bool = True,
        program_counter: int = 0,
    ) -> int:
        """
        Read a value with the given encoding at the specific offset.
        Relative indicate wether the offset is relative to the start of the
        section or absolute in the ELFFile.
        program_counter is the current program counter used for DW_EH_PE_pcrel calculations.
        """
        value_enc = encoding & 0x0F
        relative_enc = encoding & 0x70
        if value_enc == DW_EH_Encoding.DW_EH_PE_absptr:
            result = self._unpack_from("@B", offset=offset, relative=relative)
        elif value_enc == DW_EH_Encoding.DW_EH_PE_udata2:
            result = self._unpack_from("@H", offset=offset, relative=relative)
        elif value_enc == DW_EH_Encoding.DW_EH_PE_sdata2:
            result = self._unpack_from("@h", offset=offset, relative=relative)
        elif value_enc == DW_EH_Encoding.DW_EH_PE_udata4:
            result = self._unpack_from("@I", offset=offset, relative=relative)
        elif value_enc == DW_EH_Encoding.DW_EH_PE_sdata4:
            result = self._unpack_from("@i", offset=offset, relative=relative)
        elif value_enc == DW_EH_Encoding.DW_EH_PE_udata8:
            result = self._unpack_from("@Q", offset=offset, relative=relative)
        elif value_enc == DW_EH_Encoding.DW_EH_PE_sdata8:
            result = self._unpack_from("@q", offset=offset, relative=relative)
        else:
            raise ValueError(f"Unknown value encoding: {value_enc}")

        result = result[0]

        if relative_enc == DW_EH_Encoding.DW_EH_PE_absptr:
            pass
        elif relative_enc == DW_EH_Encoding.DW_EH_PE_pcrel:
            result += program_counter
        elif relative_enc == DW_EH_Encoding.DW_EH_PE_datarel:
            result += self.offset
        else:
            raise ValueError(f"Pointer encoding {relative_enc} not supported")
        return result

    @no_type_check
    def get_table_entry_size(self) -> int:
        """
        Returns the size of a table entry.
        """
        enc = self.table_enc & 0x0F
        if enc in (DW_EH_Encoding.DW_EH_PE_udata2, DW_EH_Encoding.DW_EH_PE_sdata2):
            return 4
        if enc in (DW_EH_Encoding.DW_EH_PE_udata4, DW_EH_Encoding.DW_EH_PE_sdata4):
            return 8
        if enc in (DW_EH_Encoding.DW_EH_PE_udata8, DW_EH_Encoding.DW_EH_PE_sdata8):
            return 16
        if enc == DW_EH_Encoding.DW_EH_PE_omit:
            return 0
        raise ValueError(f"Invalid table encoding: {enc}")

    def _read_section(
        self, size: int, offset: Optional[int], relative: bool = False
    ) -> Any:
        """
        Read `size` bytes from the underlying stream at the given `offset`.
        relative indicates whether the given offset is relative to the
        .eh_frame_hdr section start, or absolute in the ELFFile.
        """
        stream = self.section.stream
        if offset is not None:
            if relative:
                offset = offset + self.offset
            stream.seek(offset)
        return stream.read(size)

    def _unpack_from(
        self, fmt: str, offset: Optional[int] = None, relative: bool = False
    ) -> Tuple[int, ...]:
        """
        Unpack a value read at offset according to format.
        """
        size = struct.calcsize(fmt)
        buffer = self._read_section(size, offset, relative)
        return struct.unpack_from(fmt, buffer)

    def read_entry(self, offset: Optional[int] = None) -> Tuple[int, int]:
        """
        Read a table entry at the given offset. .eh_frame_hdr table entries are
        couples of location / offset of the corresponding FDE.
        """
        loc_val: int = self.read_value(self.table_enc, offset, relative=False)
        offset_val: int = self.read_value(self.table_enc)
        return (loc_val, offset_val)

    def iter_entries(self) -> Iterable[Tuple[int, int]]:
        """
        Iter over .eh_frame_hdr table entries.
        """
        self.section.stream.seek(self.table_start)
        for _ in range(0, self.fde_count):
            yield self.read_entry()

    def find_fde(self, addrkey: int) -> Optional[CFIEntry]:
        """
        Find an antry by doing a binary search.
        """
        minidx = 0
        maxidx = self.fde_count
        size = self.get_table_entry_size()
        while True:
            idx = minidx + (maxidx - minidx) // 2
            offset = self.table_start + idx * size
            (addr, loc) = self.read_entry(offset=offset)
            # We found the looked up key, now we need to find the right tag
            if addrkey == addr or (minidx == idx and addrkey > addr):
                fde = self.cfi._parse_entry_at(
                    loc - self.cfi.address
                )  # pylint: disable=protected-access
                if addrkey < fde.header.initial_location + fde.header.address_range:
                    return fde
                # If the key is not in range, then we don't have an entry.
                return None
            if addrkey < addr:
                if maxidx == idx:
                    return None
                maxidx = idx
            elif addrkey > addr:
                minidx = idx

    @classmethod
    def load_eh_frame_hdr(cls, elf_file: ELFFile) -> Optional[EhFrameHdr]:
        """
        Load an EHFrameHDR from an ELFFile.
        """
        eh_frame_hdr = elf_file.get_section_by_name(".eh_frame_hdr")
        if eh_frame_hdr is None:
            return None

        # pylint: disable=protected-access
        eh_frame_hdr = elf_file._read_dwarf_section(
            eh_frame_hdr, relocate_dwarf_sections=True
        )
        eh_frame_hdr_data = EhFrameHdr(eh_frame_hdr, elf_file)
        return eh_frame_hdr_data
