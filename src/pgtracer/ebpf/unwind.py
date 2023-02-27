# pylint: disable=invalid-name
"""
This module provides access to libunwind through ctypes.
"""
from __future__ import annotations

import ctypes as ct
import ctypes.util
import platform
import re
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, List, Optional, Tuple, Type, TypeVar

from elftools.dwarf.callframe import CFARule, CFIEntry
from elftools.dwarf.die import DIE, AttributeValue
from elftools.dwarf.dwarf_expr import DWARFExprOp, DWARFExprParser
from elftools.dwarf.locationlists import BaseAddressEntry, LocationEntry, LocationExpr

from .dwarf import MappedRegion, ProcessMetadata, die_name

if TYPE_CHECKING:
    try:
        from typing import TypeAlias  # type: ignore
    except ImportError:
        from typing_extensions import TypeAlias
    CFuncPtr: TypeAlias = ct._FuncPointer  # pylint: disable=protected-access
    Pointer: TypeAlias = ct.pointer
    SimpleCData = ct._SimpleCData[Any]  # pylint: disable=protected-access
else:
    # Make pylint happy
    CFuncPtr = object()
    Pointer = List
    SimpleCData = Any


CT = TypeVar("CT", bound=SimpleCData)

ARCH = platform.machine()


def find_libunwind_version() -> Tuple[int, int]:
    """
    Returns the libunwind version.
    We try to extract this from the headers.

    TODO: maybe we should call cc to get the actual include dirs ?
    """
    include_dir_candidates = [
        Path("/usr/include/"),
        Path(f"/usr/include/{ARCH}-linux-gnu/"),
    ]
    major_re = re.compile(r"#define UNW_VERSION_MAJOR\s+(\d+)")
    minor_re = re.compile(r"#define UNW_VERSION_MINOR\s+(\d+)")
    header_filename = Path("libunwind-common.h")
    major_version = None
    minor_version = None
    found = False
    for candidate in include_dir_candidates:
        include_file = candidate / header_filename
        if include_file.exists():
            with include_file.open() as f:
                for line in f:
                    match = major_re.match(line)
                    if match:
                        found = True
                        major_version = int(match.group(1))
                        continue
                    match = minor_re.match(line)
                    if match:
                        found = True
                        minor_version = int(match.group(1))
        if found:
            break
    if major_version is None or minor_version is None:
        raise ValueError("Could not identify libunwind version !")
    return (major_version, minor_version)


LIBUNWIND_VERSION = find_libunwind_version()

UNW_PREFIX = f"_U{ARCH}_"
libname = ctypes.util.find_library(f"unwind-{ARCH}")
if libname is None:
    raise ImportError(f"Cannot load libunwind-{ARCH}")
libunwind = ct.cdll.LoadLibrary(libname)
if ARCH == "x86_64":
    UNW_TDEP_CURSOR_LEN = 127
    unw_word_t = ct.c_ulonglong
    UNW_WORD_T_FORMAT = "<Q"
    unw_tdep_fpreg_t = ct.c_longdouble
    MAX_STACK_READ = 1 << 16
    stack_array = ct.c_ubyte * MAX_STACK_READ
    REG_NAMES = [
        "rax",
        "rdx",
        "rcx",
        "rbx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "rip",
    ]
    UNW_REG_IP = REG_NAMES.index("rip")

    # This corresponds to the stack and registers captured from ebpf,
    # and is architecture specific
    class stack_data_t(ct.Structure):
        """
        Mapping of stack_data_t type, defined in ebpf code.
        """

        _fields_ = [
            ("rax", ct.c_ulong),
            ("rdx", ct.c_ulong),
            ("rcx", ct.c_ulong),
            ("rbx", ct.c_ulong),
            ("rsi", ct.c_ulong),
            ("rdi", ct.c_ulong),
            ("rbp", ct.c_ulong),
            ("rsp", ct.c_ulong),
            ("r8", ct.c_ulong),
            ("r9", ct.c_ulong),
            ("r10", ct.c_ulong),
            ("r11", ct.c_ulong),
            ("r12", ct.c_ulong),
            ("r13", ct.c_ulong),
            ("r14", ct.c_ulong),
            ("r15", ct.c_ulong),
            ("rip", ct.c_ulong),
            ("size", ct.c_ulong),
            ("start_addr", ct.c_ulong),
            ("stack", stack_array),
        ]

    class unw_tdep_proc_info_t(ct.Structure):
        """
        Mapping of unw_tdep_proc_info_t
        """

        _fields_ = [("unused", ct.c_char)]

    class unw_proc_info_t(ct.Structure):
        """
        Mapping of unw_proc_info_t type
        """

        _fields_ = [
            ("start_ip", unw_word_t),
            ("end_ip", unw_word_t),
            ("lsda", unw_word_t),
            ("handler", unw_word_t),
            ("gp", unw_word_t),
            ("flags", unw_word_t),
            ("format", ct.c_int),
            ("unwind_info_size", ct.c_int),
            ("unwind_info", ct.c_void_p),
            ("extra", unw_tdep_proc_info_t),
        ]  # FIXME; this type

else:
    raise NotImplementedError(f"Stack unwinding is not supporte for {ARCH} arch")

UNW_INFO_FORMAT_REMOTE_TABLE = 2
UNW_ENOINFO = 10
UNW_EINVAL = 8
UNW_ESTOPUNWIND = 5


def unw_func(funcname: str) -> CFuncPtr:
    """
    Returns the CPointer function of that name. Depending on the architecture,
    the function names are not the same.
    """
    return getattr(libunwind, f"{UNW_PREFIX}{funcname}")


class unw_dyn_remote_table_info_t(ct.Structure):
    """
    Mapping of unw_dyn_remote_table_info_t type.
    """

    _fields_ = [
        ("name_ptr", unw_word_t),
        ("segbase", unw_word_t),
        ("table_len", unw_word_t),
        ("table_data", unw_word_t),
    ]


# We have to define the fields after the class, as it is a self-referencing
# type.
class unw_dyn_info_t(ct.Structure):
    """
    Mapping of unw_dyn_info_t type.
    """


# Libunwind does not preserve perfect ABI compatibility.
load_offset_field = []
if LIBUNWIND_VERSION >= (1, 6):
    load_offset_field = [("load_offset", unw_word_t)]

unw_dyn_info_t._fields_ = [  # pylint: disable=protected-access
    ("next", ct.POINTER(unw_dyn_info_t)),
    ("prev", ct.POINTER(unw_dyn_info_t)),
    ("start_ip", unw_word_t),
    ("end_ip", unw_word_t),
    ("gp", unw_word_t),
    ("format", ct.c_int32),
    ("pad", ct.c_int32),
    *load_offset_field,
    ("rti", unw_dyn_remote_table_info_t)  # Supposed to be an union, but we will
    # only ever use this one.
]

unw_regnum_t = ct.c_int
unw_fpreg_t = unw_tdep_fpreg_t
# Opaque type
unw_addr_space_t = ct.c_void_p

# Definition of function types
FIND_PROC_INFO_FUNCTYPE = ct.CFUNCTYPE(
    ct.c_int,  # Return value
    unw_addr_space_t,
    unw_word_t,
    ct.POINTER(unw_proc_info_t),
    ct.c_int,
    ct.c_void_p,
)
PUT_UNWIND_INFO_FUNCTYPE = ct.CFUNCTYPE(
    None, unw_addr_space_t, ct.POINTER(unw_proc_info_t), ct.c_void_p
)
GET_DYN_INFO_LIST_ADDR_FUNCTYPE = ct.CFUNCTYPE(
    ct.c_int, unw_addr_space_t, ct.POINTER(unw_word_t), ct.c_void_p
)
ACCESS_MEM_FUNCTYPE = ct.CFUNCTYPE(
    ct.c_int,
    unw_addr_space_t,
    unw_word_t,
    ct.POINTER(unw_word_t),
    ct.c_int,
    ct.c_void_p,
)
ACCESS_REG_FUNCTYPE = ct.CFUNCTYPE(
    ct.c_int,
    unw_addr_space_t,
    unw_regnum_t,
    ct.POINTER(unw_word_t),
    ct.c_int,
    ct.c_void_p,
)
ACCESS_FPREG_FUNCTYPE = ct.CFUNCTYPE(
    ct.c_int,
    unw_addr_space_t,
    unw_regnum_t,
    ct.POINTER(unw_fpreg_t),
    ct.c_int,
    ct.c_void_p,
)
GET_PROC_NAME_FUNCTYPE = ct.CFUNCTYPE(
    ct.c_int,
    unw_addr_space_t,
    unw_word_t,
    ct.c_char_p,
    ct.c_size_t,
    ct.POINTER(unw_word_t),
    ct.c_void_p,
)

create_addr_space = unw_func("create_addr_space")
create_addr_space.restype = ct.c_void_p
create_addr_space.argtypes = [ct.c_void_p, ct.c_int]

init_remote = unw_func("init_remote")
init_remote.restype = ct.c_int
init_remote.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_int]


dwarf_search_unwind_table = unw_func("dwarf_search_unwind_table")
dwarf_search_unwind_table.restype = ct.c_int
dwarf_search_unwind_table.argtypes = [
    unw_addr_space_t,
    unw_word_t,
    ct.POINTER(unw_dyn_info_t),
    ct.POINTER(unw_proc_info_t),
    ct.c_int,
    ct.c_void_p,
]


class unw_cursor_t(ct.Structure):
    """
    Mapping of unw_cursor_t type.
    """

    _fields_ = [("opaque", unw_word_t * UNW_TDEP_CURSOR_LEN)]


step = unw_func("step")
step.restype = ct.c_int
step.argtypes = [ct.POINTER(unw_cursor_t)]

get_reg = unw_func("get_reg")
get_reg.restype = ct.c_int
get_reg.argtypes = [ct.POINTER(unw_cursor_t), unw_regnum_t, ct.POINTER(unw_word_t)]


class unw_accesors(ct.Structure):
    """
    Mapping of unw_accessors type.
    """

    _fields_ = [
        ("find_proc_info", FIND_PROC_INFO_FUNCTYPE),
        ("put_unwind_info", PUT_UNWIND_INFO_FUNCTYPE),
        ("get_dyn_info_list_addr", GET_DYN_INFO_LIST_ADDR_FUNCTYPE),
        ("access_mem", ACCESS_MEM_FUNCTYPE),
        ("access_reg", ACCESS_REG_FUNCTYPE),
        ("access_fpreg", ACCESS_FPREG_FUNCTYPE),
        ("resume", ct.c_void_p),  # Unused
        ("get_proc_name", GET_PROC_NAME_FUNCTYPE),
    ]


class Frame:
    """
    A stack frame.
    """

    def __init__(
        self,
        stack: ct._CData,
        ip: int,
        die: DIE,
        start_addr: int,
        processmetadata: ProcessMetadata,
        cursor: unw_cursor_t,
        prev_frame: Optional[Frame] = None,
        next_frame: Optional[Frame] = None,
    ):
        self.stack = stack
        self.ip = ip
        self.die = die

        self.start_addr = start_addr
        self.processmetadata = processmetadata
        # We don't keep the cursor itself, we make a copy instead.
        self.cursor = unw_cursor_t()
        ct.pointer(self.cursor)[0] = cursor
        self.prev_frame = prev_frame
        self.next_frame = next_frame

    @cached_property
    def fde(self) -> Optional[CFIEntry]:
        """
        Returns the FDE associated with this call frame.
        """
        region = self.region
        if region is None:
            return None
        v_ip = self.ip - region.start
        if region.eh_frame_hdr is None:
            return None
        fde = region.eh_frame_hdr.find_fde(v_ip)
        return fde

    @cached_property
    def _expr_parser(self) -> DWARFExprParser:
        """
        DWARF Expr parser.
        """
        return DWARFExprParser(self.processmetadata.dwarf_info.structs)

    @cached_property
    def cfa_rule(self) -> Optional[CFARule]:
        """
        Returns the CFA rule associated with this call frame.
        """
        if self.fde is None:
            return None
        for row in reversed(self.fde.get_decoded().table):
            if row["pc"] < self.ip - self.region.start:
                return row["cfa"]
        return None

    @cached_property
    def cfa(self) -> Optional[int]:
        """
        Compute the CFA for this call frame.
        """
        if self.cfa_rule is None:
            return None
        cfa_reg_value = unw_word_t(0)
        get_reg(self.cursor, self.cfa_rule.reg, ct.byref(cfa_reg_value))
        return cfa_reg_value.value + self.cfa_rule.offset - self.start_addr  # type: ignore

    @cached_property
    def region(self) -> MappedRegion:
        """
        Return the MappedRegion correspoding to this Frame's IP.
        """
        region = self.processmetadata.map_for_addr(self.ip)
        if region is None:
            raise ValueError("This frame could not be associated to a region.")
        return region

    @cached_property
    def function_name(self) -> Optional[str]:
        """
        Returns the function name associated to this frame's DIE
        """
        if self.die is None:
            return None
        return die_name(self.die)

    def _get_parsed_expr_for_attribute(self, argnum: int) -> List[DWARFExprOp]:
        """
        Returns a list of parsed DwarfEXPROp for the attribute corresponding to the
        argnum'th argument.
        """
        curargnum = 0
        if self.die is None:
            return []
        for subdie in self.die.iter_children():
            if subdie.tag == "DW_TAG_formal_parameter":
                curargnum += 1
                if curargnum == argnum:
                    locattr = subdie.attributes["DW_AT_location"]
                    return self._get_parsed_exprs_from_loc(subdie, locattr)
        return []

    def _get_parsed_exprs_from_loc(
        self, die: DIE, locattr: AttributeValue
    ) -> List[DWARFExprOp]:
        """
        Returns a list of parsed DWARFExprOp for a given attribute.
        """
        expr = None
        loc = self.processmetadata.location_parser.parse_from_attribute(
            locattr, die.cu.header.version, die
        )
        if isinstance(loc, LocationExpr):
            expr = loc.loc_expr
        else:
            base_address = die.cu.get_top_DIE().attributes["DW_AT_low_pc"].value
            expr = None
            for entry in loc:
                if isinstance(entry, BaseAddressEntry):
                    base_address = entry.base_address
                elif isinstance(entry, LocationEntry):
                    start = entry.begin_offset + base_address
                    end = entry.end_offset + base_address
                    if start <= (self.ip - self.region.start) <= end:
                        expr = entry.loc_expr
                        break
                else:
                    raise NotImplementedError(
                        f"Location entries of type {type(entry)} are not supported"
                    )
        if expr is None:
            raise ValueError("Could not find LocationExpr in attr {locattr}")
        parsed_exprs: List[DWARFExprOp] = self._expr_parser.parse_expr(expr)
        return parsed_exprs

    def fetch_arg(self, argnum: int, ctype: Type[CT]) -> CT:
        """
        Fetch the argument number argnum, interpreting it as a ctype.
        """
        # We have all the registers set up correctly, fetch things directly.
        rv: CT
        if self.cfa is None:
            # Fetch the argument directly from the register
            argreg = unw_word_t(0)
            ARGNUM_TO_REGNUM = {1: 5, 2: 4, 3: 1, 4: 2, 5: 8}
            get_reg(self.cursor, ARGNUM_TO_REGNUM[argnum], ct.byref(argreg))
            return ctype(argreg.value)
        expr = self._get_parsed_expr_for_attribute(argnum)
        dwarf_stack: List[CT] = []
        for op in expr:
            rv = self.eval_expr(op, ctype, dwarf_stack)
        return rv

    def _read_arg_from_stack(self, offset: int, ctype: Type[CT]) -> CT:
        """
        Read an argument of givent type at the given offset from the stack.
        """
        assert 0 <= offset < len(self.stack)  # type: ignore
        return ctype.from_buffer(bytearray(self.stack)[offset:])  # type: ignore

    def eval_expr(
        self, expr: DWARFExprOp, ctype: Type[CT], dwarf_stack: List[CT]
    ) -> CT:
        """
        Eval simple expressions.
        """
        # It's a register
        if self.die is None:
            raise ValueError("No DIE could be found for frame {self}")
        if expr.op_name == "DW_OP_fbreg":
            # If we are an inlined subroutine, lookup the parent frame base.
            die = self.die
            while die.tag == "DW_TAG_inlined_subroutine":
                if self.next_frame is None:
                    raise Exception("Cannot find parent frame of inlined subroutine")
                die = self.next_frame.die
            frameexpr = self.processmetadata.location_parser.parse_from_attribute(
                die.attributes["DW_AT_frame_base"],
                self.die.cu.header.version,
                self.die,
            )
            parsed_expr = self._expr_parser.parse_expr(frameexpr.loc_expr)
            for item in parsed_expr:
                base_value = self.eval_expr(item, ct.c_int, dwarf_stack)  # type: ignore
            offset = base_value.value + expr.args[0]
            return self._read_arg_from_stack(offset, ctype)
        if expr.op_name == "DW_OP_call_frame_cfa":
            return ctype(self.cfa)
        if expr.op_name == "DW_OP_entry_value":
            # We evaluate the expression in the calling frame.
            for op in expr.args[0]:
                if self.next_frame is None:
                    raise Exception(
                        "Cannot find parent frame for evaluation of entry point"
                    )
                rv = self.next_frame.eval_expr(op, ctype, dwarf_stack)
            dwarf_stack.append(rv)
            return ctype(0)
        if expr.op_name == "DW_OP_stack_value":
            return dwarf_stack[-1]
        if expr.op_name.startswith("DW_OP_reg"):
            regnum = expr.op - 0x50
            val = unw_word_t(0)
            get_reg(self.cursor, regnum, ct.byref(val))
            return ctype(val.value)
        raise NotImplementedError(f"Unsupported expr type: {expr.op_name}")


class UnwindAddressSpace:
    """
    A virtual address space for use by libunwind.
    """

    def __init__(self, capture: stack_data_t, processmetadata: ProcessMetadata):
        self.capture = capture
        self.registers: List[ct.c_ulonglong] = [
            ct.c_ulonglong(getattr(self.capture, name)) for name in REG_NAMES
        ]
        self.processmetadata = processmetadata
        self.accessors = unw_accesors(
            find_proc_info=FIND_PROC_INFO_FUNCTYPE(self.find_proc_info),
            put_unwind_info=PUT_UNWIND_INFO_FUNCTYPE(self.put_unwind_info),
            get_dyn_info_list_addr=GET_DYN_INFO_LIST_ADDR_FUNCTYPE(
                self.get_dyn_info_list_addr
            ),
            access_mem=ACCESS_MEM_FUNCTYPE(self.access_mem),
            access_reg=ACCESS_REG_FUNCTYPE(self.access_reg),
            access_fpreg=ACCESS_FPREG_FUNCTYPE(self.access_reg),
            get_proc_name=GET_PROC_NAME_FUNCTYPE(self.get_proc_name),
        )

        # 0 takes the default byteorder
        self.unw_addr_space = create_addr_space(ct.byref(self.accessors), 0)
        if self.unw_addr_space == 0:
            raise Exception("Something bad happened in create_addr_space")
        self.unw_cursor = unw_cursor_t()
        retval = init_remote(
            ct.byref(self.unw_cursor), self.unw_addr_space, 0
        )  # Don't use the opaque pointer for now
        if retval != 0:
            raise Exception("Something bad happened in init_remote")

    def find_proc_info(
        self,
        addr_space: unw_addr_space_t,
        ip: int,
        pip: Pointer[unw_proc_info_t],
        need_unwind_info: ct.c_int,
        arg: ct.c_void_p,
    ) -> int:
        # pylint: disable=unused-argument,too-many-arguments
        """
        Implementation of libunwind find_proc_info callback.
        """
        # Find the top of the elfile.
        mmap = self.processmetadata.map_for_addr(ip)

        if mmap is None or mmap.eh_frame_hdr is None:
            return -UNW_ESTOPUNWIND
        pip[0] = unw_proc_info_t()
        dynamic_info = unw_dyn_info_t(
            start_ip=mmap.start,
            end_ip=mmap.end,
            format=UNW_INFO_FORMAT_REMOTE_TABLE,
        )
        dynamic_info.rti.name_ptr = 0
        # We only consider one specific binary. The virtual address space will
        # then consist of the actual stack and we will consider that the
        # eh_frame_hdr and everything else is located after that.
        dynamic_info.rti.segbase = mmap.start + mmap.eh_frame_hdr.offset
        dynamic_info.rti.table_data = (
            mmap.start + mmap.eh_frame_hdr.table_start + mmap.eh_frame_hdr.offset
        )
        dynamic_info.rti.table_len = (mmap.eh_frame_hdr.fde_count * 8) // ct.sizeof(
            unw_word_t
        )
        ret: int = dwarf_search_unwind_table(
            addr_space, ip, ct.byref(dynamic_info), pip, need_unwind_info, None
        )
        return ret

    def put_unwind_info(
        self,
        addr_space: unw_addr_space_t,
        pip: Pointer[unw_proc_info_t],
        arg: ct.c_void_p,
    ) -> None:
        """
        Implementation of libunwind put_unwind_info callback.
        """
        # pylint: disable=unused-argument
        return

    def get_dyn_info_list_addr(
        self,
        addr_space: unw_addr_space_t,
        dilap: Pointer[unw_word_t],
        arg: ct.c_void_p,
    ) -> int:
        """
        Implementation of libunwind get_dyn_info_list_addr callback.
        """
        # pylint: disable=unused-argument
        return -UNW_ENOINFO

    def access_mem(
        self,
        addr_space: unw_addr_space_t,
        addr: int,
        valp: Pointer[unw_word_t],
        write: int,
        arg: ct.c_void_p,
    ) -> int:
        """
        Implementation of libunwind access_mem callback.
        """
        # pylint: disable=unused-argument,too-many-arguments
        # We only support either file-mapped addresses, or addresses
        # refering to the stack.
        region = self.processmetadata.map_for_addr(addr)
        if region is None:
            return -UNW_EINVAL
        if region.path == "[stack]":
            stack_idx = addr - self.capture.start_addr
            if stack_idx >= self.capture.size:
                return -UNW_EINVAL
            if write == 0:
                valp[0] = unw_word_t.from_buffer(
                    bytearray(self.capture.stack[stack_idx : stack_idx + 8])
                )
            else:
                self.capture.stack[stack_idx] = valp.contents
            return 0

        # It's from the ELFFile itself.
        if region.real_path:
            if write == 0:
                with region.real_path.open("rb") as f:
                    f.seek(addr - region.start)
                    valp[0] = unw_word_t.from_buffer(
                        bytearray(f.read(ct.sizeof(unw_word_t)))
                    )
                    return 0
            return -UNW_EINVAL

        # It's from anywhere else: return EINVAL
        return -UNW_EINVAL

    def access_reg(
        self,
        addr_space: unw_addr_space_t,
        regnum: int,
        valp: Pointer[unw_word_t],
        write: int,
        arg: ct.c_void_p,
    ) -> int:
        """
        Implementation of libunwind access_reg callback.
        """
        # pylint: disable=unused-argument,too-many-arguments
        if write == 0:
            valp[0] = unw_word_t(self.registers[regnum].value)
        else:
            self.registers[regnum] = valp.contents
        return 0

    def access_fpreg(
        self,
        addr_space: unw_addr_space_t,
        regnum: unw_regnum_t,
        fpvalp: Pointer[unw_fpreg_t],
        write: ct.c_int,
        arg: ct.c_void_p,
    ) -> int:
        """
        Implementation of libunwind access_fpreg callback.
        """
        # pylint: disable=unused-argument,too-many-arguments
        return -UNW_EINVAL

    def get_proc_name(
        self,
        addr_space: unw_addr_space_t,
        addr: unw_word_t,
        bufp: ct.c_char_p,
        buf_len: ct.c_size_t,
        offp: Pointer[unw_word_t],
        arg: ct.c_void_p,
    ) -> int:
        """
        Implementation of libunwind get_proc_name callback.
        """
        # pylint: disable=unused-argument,too-many-arguments
        return -UNW_EINVAL

    def ip(self) -> int:
        """
        Return the instruction pointer from the unwind cursor.
        """
        ip = unw_word_t(0)
        get_reg(self.unw_cursor, UNW_REG_IP, ct.byref(ip))
        return ip.value

    def dies_for_ip(self) -> Tuple[DIE, ...]:
        """
        Return a tuple of DIEs for a given ip.
        """
        ip = self.ip()
        region = self.processmetadata.map_for_addr(ip)
        if region is None:
            return (None,)
        if region.path == str(self.processmetadata.program_raw):
            dies = self.processmetadata.get_die_and_inlined_subdies_for_addr(
                ip - region.start
            )
            if dies is not None:
                return dies
        return (None,)

    def frames(self) -> Generator[Frame, None, None]:
        """
        Returns the list of frames for this stack.
        """
        cur = ct.byref(self.unw_cursor)
        prev_frame = None
        while True:
            # Extract the IP
            ip = self.ip()
            for die in self.dies_for_ip():
                # The cursor is copied by the frame, no need to
                # worry about it
                cur_frame = Frame(
                    self.capture.stack,
                    ip,
                    die,
                    self.capture.start_addr,
                    self.processmetadata,
                    self.unw_cursor,
                    prev_frame=prev_frame,
                )
                if prev_frame is not None:
                    prev_frame.next_frame = cur_frame
                    yield prev_frame
                prev_frame = cur_frame
            if step(cur) <= 0:
                break
        if prev_frame is not None:
            yield prev_frame
