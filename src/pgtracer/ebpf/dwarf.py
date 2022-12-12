"""
DWARF utils.

This module wraps pyelftools to provide meaningful information from DWARF
information.

It allows to dynamically access enums and structs defintions from the dwarf
files, as well as parse bytearrays extracted from memory according to those
definitions.
"""
from __future__ import annotations

import ctypes as ct
import json
import struct
from bisect import bisect_right
from collections import defaultdict
from enum import IntEnum
from functools import cached_property
from operator import attrgetter
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
)

from elftools.common.exceptions import DWARFError
from elftools.common.utils import struct_parse
from elftools.construct import Container
from elftools.construct import Struct as ConStruct
from elftools.construct import ULInt32
from elftools.dwarf import constants as dwarf_consts
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.die import DIE
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.locationlists import LocationParser
from elftools.dwarf.ranges import BaseAddressEntry, RangeEntry
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from psutil import Process

from .eh_frame_hdr import EhFrameHdr

if TYPE_CHECKING:
    from ctypes import _CData
else:
    _CData = object


class MappedRegion:
    """
    A mapped region as parsed from /proc/<pid>/maps
    """

    def __init__(
        self, path: str, start: int, end: int, real_path: Optional[Path] = None
    ):
        self.path = path
        self.start = start
        self.end = end
        self.real_path = real_path

    @cached_property
    def eh_frame_hdr(self) -> Optional[EhFrameHdr]:
        """
        Returns the eh_frame_hdr for this region.
        """
        if self.real_path is None:
            return None
        with self.real_path.open("rb") as elf:
            return EhFrameHdr.load_eh_frame_hdr(ELFFile(elf))


def get_mapped_regions(process: Process, root: Path) -> List[MappedRegion]:
    """
    Returns a list, sorted in the start region order.
    """
    mapped_regions: Dict[str, MappedRegion] = {}
    for mmap in process.memory_maps(grouped=False):
        start, end = tuple(int(part, 16) for part in mmap.addr.split("-"))
        # Update it
        mapped_region = mapped_regions.get(mmap.path)
        if mapped_region is None:
            real_path = None
            if mmap.path.startswith("/"):
                real_path = root / Path(mmap.path).relative_to("/")
                if not real_path.exists():
                    real_path = None
            mapped_region = MappedRegion(mmap.path, start, end, real_path)
            mapped_regions[mmap.path] = mapped_region
            continue
        mapped_region.start = min(mapped_region.start, start)
        mapped_region.end = max(mapped_region.end, end)
    return sorted(mapped_regions.values(), key=attrgetter("start"))


def get_actual_root(pid: int) -> Path:
    """
    Returns the actual root for a pid, as seen from the host.
    """
    with open(f"/proc/{pid}/mountinfo", "rb") as mountinfo:
        for line in mountinfo:
            components = line.split(b" ")
            mountpoint = components[4]
            if mountpoint == b"/":
                return Path(components[3].decode("utf8"))
    # Couldn't find it, just return the mounted point.
    # This won't survive a process dying.
    return Path(f"/proc/{pid}/root")


def extract_buildid(elffile: ELFFile) -> Optional[str]:
    """
    Extract the build-id from an ELF file.
    """
    buildid_section = elffile.get_section_by_name(".note.gnu.build-id")
    if buildid_section is None:
        return None
    for note in buildid_section.iter_notes():
        if note["n_type"] == "NT_GNU_BUILD_ID":
            n_desc: str = note["n_desc"]
            return n_desc
    return None


def get_size(
    to_size: Type[Union[Struct, ct._CData, DWARFPointer]], dereference: bool = True
) -> int:
    """
    Returns the size of a type.
    """
    if issubclass(to_size, Struct):
        return to_size.size()
    elif issubclass(to_size, DWARFPointer):
        if dereference:
            return get_size(to_size.pointed_type)
        return ct.sizeof(ct.c_void_p)
    else:
        return ct.sizeof(to_size)


def find_debuginfo(
    elf_file: ELFFile, root: Path = Path("/"), buildid: Optional[str] = None
) -> Optional[ELFFile]:
    """
    Find the debug information for a given program.
    Either the ELFFile contains the debug information directly, or we can use
    a .gnu_debuglink section to look it up.
    If neither work, fallback to looking up a file in /usr/lib/debug.
    """
    dwarf_info = elf_file.get_dwarf_info()
    if dwarf_info.has_debug_info:
        return elf_file

    debug_dir = root / Path("usr/lib/debug")
    debuginfod_dir = Path("~/.cache/debuginfod_client").expanduser()
    # Try to locate it using build-id
    if buildid:
        prefix, rest = buildid[:2], buildid[2:]
        debug_file = debug_dir / ".build-id" / prefix / (rest + ".debug")
        if debug_file.exists():
            return ELFFile.load_from_path(bytes(debug_file))
        # Try it for debuginfod format
        debug_file = debuginfod_dir / buildid / "debuginfo"
        if debug_file.exists():
            return ELFFile.load_from_path(bytes(debug_file))
    # Ok, try to locate it using debuglink then.
    gnu_debug_link_section = elf_file.get_section_by_name(".gnu_debuglink")
    if gnu_debug_link_section is not None:
        debuglink = bytearray()
        for char in gnu_debug_link_section.data():
            if char == 0x00:
                break
            debuglink.append(char)
        program_dir = Path(elf_file.stream.name.decode("utf8")).parent
        program_path = program_dir / debuglink.decode("utf8")
        program_path = program_path.relative_to(program_path.anchor)
        debug_file = debug_dir / program_path
        if debug_file.exists():
            return ELFFile.load_from_path(bytes(debug_file))
    return None


def die_name(die: DIE) -> Optional[str]:
    """
    Extract a DIE name as an str.
    """
    if "DW_AT_name" in die.attributes:
        name: str = die.attributes["DW_AT_name"].value.decode("utf8")
        return name
    if "DW_AT_abstract_origin" in die.attributes:
        origin = die.get_DIE_from_attribute("DW_AT_abstract_origin")
        return die_name(origin)
    return None


def die_match(die: DIE, tag: str, name: str) -> bool:
    """
    Returns wether a DIE matches the given name and tag.
    """
    if die.tag != tag:
        return False
    return die_name(die) == name


def get_location(die: DIE) -> int:
    """
    Returns the location from a DIE.
    """
    if "DW_AT_data_member_location" in die.attributes:
        attname = "DW_AT_data_member_location"
    elif "DW_AT_location" in die.attributes:
        attname = "DW_AT_location"
    else:
        raise ValueError("Don't know how to get location from DIE")
    attr = die.attributes[attname]
    assert isinstance(attr.value, int)
    return attr.value


class GDBIndex:
    # pylint: disable=invalid-name
    """
    Parse a .gdb_index section, which provides a hashtable to different symbols
    in the dwarf information.
    """

    def __init__(self, section: Section, dwarf_info: DWARFInfo):
        self.dwarf_info = dwarf_info
        self.structs = self.dwarf_info.structs
        self.section = section
        self.stream = self.section.stream
        self.offset = self.section.header["sh_offset"]
        self.header = self.parse_header()
        self.htab_entry_size = 4 * 2
        self.htab_size = (
            self.header.constant_pool_offset - self.header.symbol_table_offset
        ) // self.htab_entry_size

    def parse_header(self) -> Container:
        """
        Parse the .gdb_index_header section.
        """
        header_def = ConStruct(
            "gdb_index_header",
            ULInt32("version"),
            ULInt32("cu_offset"),
            ULInt32("types_cu_offset"),
            ULInt32("address_offset"),
            ULInt32("symbol_table_offset"),
            ULInt32("constant_pool_offset"),
        )

        return struct_parse(header_def, self.stream, self.offset)

    def _hash_symbol(self, symbol: bytes) -> ct.c_uint32:
        """
        Implements the GDB Index hashing function.
        """
        symbol = bytearray(symbol)
        ubytes = (ct.c_ubyte * len(symbol)).from_buffer(symbol)
        r = 0

        for c in ubytes:
            if c - ord("A") < 26:
                c = c | 32
            r = r * 67 + c - 113

        return ct.c_uint32(r)

    def find_symbol(self, symbol_str: str) -> List[Tuple[int, int]]:
        """
        Find a symbol in the hashtable, and returns the associated cu_vector.
        """
        symbol = symbol_str.encode("utf8")
        h = self._hash_symbol(symbol)
        step_size = ct.c_uint32(
            (
                ct.c_uint32((h.value * 17)).value
                & (ct.c_uint32(self.htab_size - 1)).value
            )
            | 1
        )
        idx = int(h.value % self.htab_size)
        str_value = None

        while str_value != symbol:
            cp_off, cv_off = self._read_htabentry_at(idx)

            if (cp_off, cv_off) == (0, 0):
                break
            str_value = self._read_string_constant_at(cp_off)
            idx = (idx + step_size.value) % self.htab_size
        cu_vector = self._read_cu_vector_at(cv_off)

        return cu_vector

    def cu_offset_by_idx(self, cu_idx: int) -> int:
        """
        Returns a cu offset from the .gdb_index section cu_offsets list.
        """
        self.stream.seek(self.offset + self.header.cu_offset + cu_idx * 16)
        cu_offset: int = struct.unpack("<Q", self.stream.read(8))[0]
        return cu_offset

    def _read_cu_vector_at(self, cv_off: int) -> List[Tuple[int, int]]:
        """
        Read a cu_vector at a specific offset.
        """
        self.stream.seek(self.offset + self.header.constant_pool_offset + cv_off)
        nb_entry = struct.unpack("<L", self.stream.read(4))[0]
        cu_vector = []
        idx_mask = 0b00000001111111111111111111111111
        zero_mask = 0b00001110000000000000000000000000
        type_mask = 0b01110000000000000000000000000000

        for _ in range(nb_entry):
            val = struct.unpack("<L", self.stream.read(4))[0]
            zero = val & zero_mask
            assert zero == 0
            cuidx = val & idx_mask
            symboltype = (val & type_mask) >> 28
            cu_vector.append((cuidx, symboltype))

        return cu_vector

    def _read_string_constant_at(self, cp_off: int) -> bytes:
        """
        Read a string constant at a specific offset.
        """
        self.stream.seek(self.offset + self.header.constant_pool_offset + cp_off)
        buf = b""

        while True:
            char = self.stream.read(1)

            if char == b"\x00":
                break
            buf += char

        return buf

    def _read_htabentry_at(self, idx: int) -> Tuple[int, int]:
        """
        Read an hash table entry at a given idex.
        """
        self.stream.seek(
            self.offset + self.header.symbol_table_offset + idx * self.htab_entry_size
        )
        fmt = "<LL"
        size = struct.calcsize(fmt)
        buf = self.stream.read(size)
        cp_off, cv_off = struct.unpack(fmt, buf)

        return cp_off, cv_off


BaseTypes: Dict[str, Optional[Type[_CData]]] = {
    "unsigned char": ct.c_ubyte,
    "short unsigned int": ct.c_ushort,
    "unsigned int": ct.c_uint,
    "long unsigned int": ct.c_ulong,
    "signed char": ct.c_byte,
    "short int": ct.c_short,
    "int": ct.c_int,
    "long int": ct.c_long,
    "char": ct.c_byte,
    "long long unsigned int": ct.c_ulonglong,
    "long long int": ct.c_longlong,
    "float": ct.c_float,
    "double": ct.c_double,
    "long double": ct.c_longdouble,
    "_Bool": ct.c_bool,
    # Explicitly unsupported types
    "__int128": None,
    "__unknown__": None,
    "__int128 unsigned": None,
}


class Enums:
    """
    Namespace for Enums found in a DWARF info

    This loads and cache enum definitions from the DWARF info.
    """

    def __init__(self, metadata: ProcessMetadata):
        self.metadata = metadata
        self._cache: Dict[str, Type[IntEnum]] = {}

    def __getattr__(self, enum_name: str) -> Optional[Type[IntEnum]]:
        """
        Lookup the enum named `enum_name` in the dwarf file, and builds a
        python IntEnum matching the C definition.
        """
        if enum_name in self._cache:
            return self._cache[enum_name]
        # Not found, find the enum definition.
        die = next(self.metadata.search_symbol("DW_TAG_enumeration_type", enum_name))
        mapping = {}

        for child in die.iter_children():
            member_name = die_name(child)
            mapping[member_name] = child.attributes["DW_AT_const_value"].value

        # Mypy complains about dynamic enums
        enum = IntEnum(enum_name, mapping)  # type: ignore
        self._cache[enum_name] = enum

        return enum


class StructMemberDefinition:
    """
    Definition of a struct member.gg

    This allows to represent the type used for parsing, and the offset in the
    parent struct.
    """

    def __init__(
        self,
        name: str,
        member_type: Type[Union[_CData, Struct, DWARFPointer]],
        offset: int,
    ):
        self.name = name
        self.member_type = member_type
        self.offset = offset

    def extract_from_struct(self, buffer_addr: int) -> Any:
        """
        Parse the member from a buffer representing the parent struct.
        """
        addr = buffer_addr + self.offset

        if issubclass(self.member_type, (Struct, DWARFPointer)):
            return self.member_type(addr)
        value = self.member_type()
        ct.pointer(value)[0] = self.member_type.from_address(addr)
        return value


class DWARFPointer:
    """
    Represents a typed Pointer.
    """

    pointed_type: Type[Union[_CData, Struct, DWARFPointer]]

    def __init__(self, pointed: int):
        self.pointed = pointed


class Struct:
    """
    Base class for a struct definition.

    Subclasses are dynamically generated from the DWARF information.
    """

    fields_defs: Dict[str, StructMemberDefinition]
    metadata: ProcessMetadata
    die: DIE
    _fully_loaded: bool = False

    def __init__(self, buffer_addr: int):
        self.buffer_addr = buffer_addr
        self.members: Dict[str, Union[_CData, Struct]] = {}
        self.as_dict(include_all=True)

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        cls.fields_defs = {}

    @classmethod
    def _get_type(
        cls, die: DIE
    ) -> Union[Type[_CData], Type[Struct], Type[DWARFPointer]]:
        typedie = die.get_DIE_from_attribute("DW_AT_type")
        while typedie.tag == "DW_TAG_typedef":
            typedie = typedie.get_DIE_from_attribute("DW_AT_type")
        typename = die_name(typedie)
        dtype: Optional[Union[Type[Struct], Type[_CData], Type[DWARFPointer]]] = None
        if typedie.tag == "DW_TAG_base_type":
            # Ignore the invalid assignation to None, since
            # an error is raised just below
            dtype = BaseTypes.get(typename)  # type: ignore
            if dtype is None:
                raise KeyError(f"Unsupported base type {typename}")
        elif typedie.tag == "DW_TAG_structure_type":
            assert typename is not None
            dtype = getattr(cls.metadata.structs, typename)
            if dtype is None:
                raise KeyError(f"Unknown struct named {typename}")
        elif typedie.tag == "DW_TAG_pointer_type":
            # Look up the type this points to.
            pointed_type = cls._get_type(typedie)
            if issubclass(pointed_type, Struct):
                dtype = pointed_type.pointer_type()
            elif issubclass(pointed_type, DWARFPointer):
                raise NotImplementedError("We don't support pointers to pointers yet")
            elif issubclass(pointed_type, _CData):
                dtype = ct.POINTER(pointed_type)
            else:
                raise NotImplementedError(
                    f"No idea how to get a pointer to {pointed_type}"
                )
        elif typedie.tag == "DW_TAG_enumeration_type":
            dtype = ct.c_int
        elif typedie.tag == "DW_TAG_const_type":
            dtype = cls._get_type(typedie)
        else:
            raise ValueError(f"Did not expect type with {typedie.tag}")
        return dtype

    @classmethod
    def _load_fields(cls, filter_fn: Optional[Callable[[DIE], bool]] = None) -> None:
        for child in cls.die.iter_children():
            if filter_fn is None or filter_fn(child):
                attrname = die_name(child)
                if attrname is None:
                    continue
                offset = get_location(child)
                child_type = cls._get_type(child)
                # Ok, now figure out what to do with the type.
                cls.fields_defs[attrname] = StructMemberDefinition(
                    attrname, child_type, offset
                )

    @classmethod
    def field_definition(cls, attrname: str) -> Optional[StructMemberDefinition]:
        """
        Returns a field definition for the given attribute.

        It is lazy-loaded from the DWARF information.
        """
        if attrname in cls.fields_defs:
            return cls.fields_defs[attrname]
        cls._load_fields(lambda die: die_name(die) == attrname)
        return cls.fields_defs[attrname]

    @classmethod
    def load_all_definitions(cls) -> None:
        """
        Load all field defintions for the struct.
        """
        if cls._fully_loaded:
            return
        cls._load_fields()

    def __getattr__(self, attrname: str) -> Any:
        """
        Load the value of attribute attrname from the payload associated to
        this struct, parsing it from the field definition.

        If called on the class itself, returns the definitions
        """
        if attrname in self.members:
            return self.members[attrname]

        field = self.field_definition(attrname)

        if field is None:
            raise KeyError(
                f"No attribute {attrname} in struct {self.__class__.__name__}"
            )
        self.members[attrname] = field.extract_from_struct(self.buffer_addr)

        return self.members[attrname]

    def as_dict(self, include_all: bool = False) -> Dict[str, Any]:
        """
        Returns the struct content as a dict.
        If include_all is True, load all field definitions from the underlying
        DWARFInfo before. Otherwise, only fields which have already been
        accessed in any instance of this Struct class will be dumped.
        """
        if include_all:
            self.load_all_definitions()
        values = {}
        for attrname in self.fields_defs:
            value = getattr(self, attrname)
            values[attrname] = value
        return values

    @classmethod
    def size(cls) -> int:
        """
        Returns the sizeof() this struct as stored in the DWARF information.
        """
        size = cls.die.attributes["DW_AT_byte_size"].value
        assert isinstance(size, int)
        return size

    @classmethod
    def pointer_type(cls) -> Type[DWARFPointer]:
        """
        Returns the pointer type pointing to this struct, creating it if it doesn't exists.
        """
        pointer_type = cls.metadata.pointer_types.get(cls)
        if pointer_type is not None:
            return pointer_type
        pointer_type = type(f"{cls.__name__}_p", (DWARFPointer,), {"pointed_type": cls})
        cls.metadata.pointer_types[cls] = pointer_type
        return pointer_type


class Structs:
    """
    Namespace for dynamically loading Struct definitions from the DWARF info.
    """

    def __init__(self, metadata: ProcessMetadata):
        self.metadata = metadata
        self.cache: Dict[str, Type[Struct]] = {}

    def __getattr__(self, attrname: str) -> Type[Struct]:
        """
        Load the struct name `attrname` from the dwarfinfo.
        """
        if attrname in self.cache:
            return self.cache[attrname]

        # Ok, build the class.
        die = next(self.metadata.search_symbol("DW_TAG_structure_type", attrname))
        cls = type(attrname, (Struct,), {"metadata": self.metadata, "die": die})
        self.cache[attrname] = cls

        return cls


class CacheJSONEncoder(json.JSONEncoder):
    """
    JSONEncoder for the naive cache: we just want to convert set to lists
    before storing them to disk.
    """

    def default(self, o: Any) -> Any:
        if isinstance(o, set):
            return list(o)
        return super().default(o)


GDB_INDEX_TYPES_MAPPING = {"DW_TAG_subprogram": 3, "DW_TAG_structure_type": 1}


class ProcessMetadata:
    # pylint: disable=invalid-name
    """
    Metadata about a process.

    This class combines information from the process itself (offsets extracted
    from memory maps) with DWARF information.
    """

    def __init__(self, process: Process, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir
        self.pid = process.pid
        self.root = Path(f"/proc/{process.pid}/root")
        self.program_raw = Path(process.exe())
        elffile = ELFFile.load_from_path(bytes(self.program))
        self.buildid = extract_buildid(elffile)
        elffile = find_debuginfo(elffile, root=self.root, buildid=self.buildid)
        if elffile is None:
            raise Exception(f"Couldn't find debug info for {self.program}")
        self.elffile = elffile
        self.dwarf_info = self.elffile.get_dwarf_info()
        self.maps = get_mapped_regions(process, get_actual_root(process.pid))
        gdb_index_section = self.elffile.get_section_by_name(".gdb_index")
        self.gdb_index: Optional[GDBIndex] = None
        self.naive_index: Dict[str, Dict[str, Set[Tuple[int, int]]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self.pointer_types: Dict[type, type] = {}
        self.symtab = self.elffile.get_section_by_name(".symtab")
        if gdb_index_section is not None:
            self.gdb_index = GDBIndex(gdb_index_section, self.dwarf_info)
            # We still build a naive index, but lazily instead of parsing
            # everything. This helps subsequent invocations...
            naive_index = self._load_naive_index()
            if naive_index is not None:
                self._merge_naive_index(naive_index)
        else:
            print(
                "WARNING: not using a gdb index... We will need to build a full index first"
            )
            self._load_or_build_naive_index()

        self.enums = Enums(self)
        self.structs = Structs(self)
        self.aranges = self.dwarf_info.get_aranges()
        self.rangelists = self.dwarf_info.range_lists()
        self.location_parser = LocationParser(self.dwarf_info.location_lists())

    def map_for_addr(self, addr: int) -> Optional[MappedRegion]:
        """
        Returns the map containing the given addr.
        """
        # In python 3.10, bisect_right accepts a key argument.
        # For now, just work on a processed thing.
        idx = bisect_right(list(map(attrgetter("start"), self.maps)), addr)
        mmap = self.maps[idx - 1]
        if mmap.start <= addr < mmap.end:
            return mmap
        return None

    @property
    def program(self) -> Path:
        """
        Returns the program as seen from our own root.
        """
        return self.root / self.program_raw.relative_to("/")

    @property
    def base_addr(self) -> int:
        """
        Returns the base address for the memory mapped for our binary.
        """
        for mmap in self.maps:
            if mmap.path == str(self.program_raw):
                return mmap.start
        raise Exception("Could not find a memory map for {self.program_raw}")

    @property
    def stack_top(self) -> int:
        """
        Returns the address of the top of the stack.
        """
        for mmap in self.maps:
            if mmap.path == "[stack]":
                return mmap.end
        raise Exception("Could not find a [stack] memory map")

    @property
    def cache_path(self) -> Optional[Path]:
        """
        Returns the cache_path for this file.
        """
        if self.buildid is None or self.cache_dir is None:
            return None
        if not self.cache_dir.exists():
            self.cache_dir.mkdir()
        return self.cache_dir / (self.buildid + ".pgtraceridx")

    def _load_naive_index(self) -> Optional[Dict[str, Dict[str, Set[Tuple[int, int]]]]]:
        """
        Load a naive index previously stored on disk.
        """
        if self.cache_path is not None and self.cache_path.exists():
            print(f"Loading naive index from {str(self.cache_path)}")
            with self.cache_path.open() as fileidx:
                filecache: Dict[str, Dict[str, Set[Tuple[int, int]]]]
                filecache = json.load(fileidx)
                return filecache
        return None

    def _dump_naive_index(self) -> None:
        """
        Store a naive index on disk.
        """
        if self.cache_path is not None:
            with self.cache_path.open("w") as fileidx:
                json.dump(self.naive_index, fileidx, cls=CacheJSONEncoder)

    def _merge_naive_index(
        self, naive_index: Dict[str, Dict[str, Set[Tuple[int, int]]]]
    ) -> None:
        for tag, symbols in naive_index.items():
            tagdict = self.naive_index[tag]
            for symbol, tuples in symbols.items():
                symbolset = tagdict[symbol]
                for die_offset, cu_offset in tuples:
                    symbolset.add((die_offset, cu_offset))

    def _load_or_build_naive_index(self) -> None:
        """
        Load a naive index from disk, building if it doesn't exists.
        """
        naive_index = self._load_naive_index()
        if naive_index is not None:
            self._merge_naive_index(naive_index)
            return
        for cu in self.dwarf_info.iter_CUs():
            for die in cu.iter_DIEs():
                name = die_name(die)
                if name is not None:
                    # Only add structs, functions and enums to the cache
                    if die.tag in (
                        "DW_TAG_enumeration_type",
                        "DW_TAG_subprogram",
                        "DW_TAG_structure_type",
                        "DW_TAG_inlined_subroutine",
                    ):
                        self.naive_index[die.tag][name].add((die.offset, cu.cu_offset))
        self._dump_naive_index()

    def search_symbol(self, tag: str, name: str) -> Generator[DIE, None, None]:
        """
        Search DIEs for symbol of type DW_TAG_{tag} and named `name`.

        Depending on what we find the debug information, use different
        strategies to lookup the symbol.
        """
        if self.gdb_index is None:
            return self._naive_die_search(tag, name)
        return self._gdbindex_die_search(tag, name)

    def _die_by_offsets(self, offsets: Tuple[int, int]) -> DIE:
        try:
            cu = self.dwarf_info.get_CU_at(offsets[1])
        except (AssertionError, DWARFError) as e:
            # If we can't parse it directly, it may be in the supplementary
            # object file.
            if self.dwarf_info.supplementary_dwarfinfo:
                cu = self.dwarf_info.supplementary_dwarfinfo.get_CU_at(offsets[1])
            else:
                raise e
        die = cu.get_DIE_from_refaddr(offsets[0])
        return die

    def _naive_die_search(self, tag: str, name: str) -> Generator[DIE, None, None]:
        """
        Implementation of search_symbol when we don't have any index.
        This is VERY slow as we need to parse every single DIE.
        """
        tag_dict = self.naive_index.get(tag, {})
        for offsets in tag_dict.get(name, []):
            die = self._die_by_offsets(offsets)
            yield die

    def _gdbindex_die_search(self, tag: str, name: str) -> Generator[DIE, None, None]:
        """
        Implementation of search_symbol when we do have .gdb_index.
        """
        # We first try to see if we cached the result.
        offsets = self.naive_index.get(tag, {}).get(name, None)
        if offsets is not None:
            for off in offsets:
                die = self._die_by_offsets(off)
                yield die
            return
        assert self.gdb_index is not None
        cu_vector = self.gdb_index.find_symbol(name)
        # The cu_vector consist of a cuidx identify which compile unit the DIE
        # is in, and the DIE type. We don't really care about the type here
        # since we check it more precisely in die_match.
        gdb_type = GDB_INDEX_TYPES_MAPPING.get(tag)
        matching_dies_offsets = set()
        matching_dies_list = []
        for (cuidx, _type) in cu_vector:
            if gdb_type is not None and gdb_type != _type:
                continue
            cu_offset = self.gdb_index.cu_offset_by_idx(cuidx)
            cu = self.dwarf_info.get_CU_at(cu_offset)

            for die in cu.iter_DIEs():
                if die_match(die, tag, name):
                    matching_dies_offsets.add((die.offset, die.cu.cu_offset))
                    matching_dies_list.append(die)
        self.naive_index[tag][name] = matching_dies_offsets
        self._dump_naive_index()
        for die in matching_dies_list:
            yield die

    def global_variable(self, variable_name: str) -> Optional[int]:
        """
        Returns the absolute address associated to a global variable.
        """
        # First, try to look it up in the symbol table
        symbol = self.symtab.get_symbol_by_name(variable_name)
        if symbol:
            return int(symbol[0]["st_value"]) + self.base_addr
        # If it fails, fallback to DWARF
        dies = self.search_symbol("DW_TAG_variable", variable_name)
        parser = DWARFExprParser(self.dwarf_info.structs)

        for die in dies:
            if "DW_AT_location" in die.attributes:
                expr = parser.parse_expr(die.attributes["DW_AT_location"].value)

                if len(expr) != 1 and expr[0].op_name != "DW_OP_addr":
                    raise ValueError("Located variable doesn't seem to be a global")

                return int(expr[0].args[0]) + self.base_addr
        return None

    def function_addresses(self, function_name: str) -> Generator[int, None, None]:
        """
        Returns the relativee addresses attached to a function.
        There can be several of them when a function is inlined for example.
        """
        dies = list(self.search_symbol("DW_TAG_subprogram", function_name))
        dies.extend(
            list(self.search_symbol("DW_TAG_inlined_subroutine", function_name))
        )
        for die in dies:
            if "DW_AT_ranges" in die.attributes:
                range_offset = die.attributes["DW_AT_ranges"].value
                rangelists = self.dwarf_info.range_lists()
                range_list = rangelists.get_range_list_at_offset(range_offset)
                base_address = 0

                for entry in range_list:
                    if isinstance(entry, BaseAddressEntry):
                        base_address = entry.base_address
                    elif isinstance(entry, RangeEntry):
                        yield base_address + entry.begin_offset
            elif "DW_AT_low_pc" in die.attributes:
                yield die.attributes["DW_AT_low_pc"].value
            # Now if the function has been inlined, look at it's call sites.

            if "DW_AT_abstract_origin" in die.attributes:
                abstract_die = die.get_DIE_from_attribute("DW_AT_abstract_origin")
                inline_attr = abstract_die.attributes.get("DW_AT_inline")

                if (
                    inline_attr is not None
                    and inline_attr.value != dwarf_consts.DW_INL_not_inlined
                ):
                    for child in die.iter_children():
                        if child.tag == "DW_TAG_GNU_call_site":
                            yield child.attributes["DW_AT_low_pc"].value
                        elif child.tag == "DW_TAG_call_site":
                            yield child.attributes["DW_AT_call_return_pc"].value

    def die_contains_addr(self, die: DIE, addr: int) -> bool:
        """
        Returns wheter the die contains the given addr.
        """
        if "DW_AT_low_pc" in die.attributes:
            low_pc = die.attributes["DW_AT_low_pc"].value
            if "DW_AT_high_pc" not in die.attributes:
                return False
            high_pc_attr = die.attributes["DW_AT_high_pc"]
            high_pc_attr_class = describe_form_class(high_pc_attr.form)
            if high_pc_attr_class == "address":
                high_pc = high_pc_attr.value
            elif high_pc_attr_class == "constant":
                high_pc = low_pc + high_pc_attr.value
            else:
                raise ValueError(f"invalid DW_AT_high_pc class: {high_pc_attr_class}")
            if low_pc <= addr < high_pc:
                return True
        elif "DW_AT_ranges" in die.attributes:
            range_offset = die.attributes["DW_AT_ranges"].value
            range_list = self.rangelists.get_range_list_at_offset(range_offset, die.cu)
            base_address = 0
            for entry in range_list:
                if isinstance(entry, BaseAddressEntry):
                    base_address = entry.base_address
                elif isinstance(entry, RangeEntry):
                    start = entry.begin_offset + base_address
                    end = entry.end_offset + base_address
                    if start <= addr < end:
                        return True
        return False

    def get_die_and_inlined_subdies_for_addr(
        self, addr: int
    ) -> Optional[Tuple[DIE, ...]]:
        """
        Returns the containing die and inlined functions DIEs for given addr.
        """
        cu_offset = self.aranges.cu_offset_at_addr(addr)
        if cu_offset is None:
            return None
        cu = self.dwarf_info.get_CU_at(cu_offset)
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_subprogram" and self.die_contains_addr(die, addr):
                # Check if we can find something an inlined subroutine in here.
                return self._recurse_die_for_addr(die, addr)
        return None

    def _recurse_die_for_addr(self, die: DIE, addr: int) -> Optional[Tuple[DIE, ...]]:
        if not self.die_contains_addr(die, addr):
            return None
        for child in die.iter_children():
            if child.tag == "DW_TAG_inlined_subroutine":
                subdies = self._recurse_die_for_addr(child, addr)
                if subdies:
                    return subdies + (die,)
        return (die,)
