"""
Workhorse for pgtracer.

The BPFCollector works by combining two things:
    - an ebpf program loaded in to the kernel, which is built on the fly
    - DWARF information extracted from the executable (or a separate debug
      symbols file).
"""
from __future__ import annotations

import ctypes as ct
import os
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from threading import Lock, Thread
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, TypeVar, Union

from bcc import BPF, USDT, PerfSWConfig, PerfType
from bcc import __version__ as bcc_version
from bcc import lib as bcclib
from pypsutil import Process

from ...model import MemoryAllocType, Query
from ..dwarf import DWARFPointer, ProcessMetadata, Struct, get_size
from ..unwind import stack_data_t
from .c_defs import *
from .utils import CODE_BASE_PATH, defines_dict_to_c, intenum_to_c, load_c_file

BCC_VERSION_TUPLE = tuple(int(part) for part in bcc_version.split("."))


class InvalidStateException(Exception):
    """
    Invalid State of a BPFCollector Exception.

    This Exception occurs when an operation is performed on a BPFCollector
    which is not in the prerequisite state.
    """


# pylint: disable=invalid-name
class EventHandler:
    """
    Base class for handling events.

    The handle_event method dispatched to handle_{EventType} methods if they
    exist. This acts mostly as a namespace to not pollute the BPFCollector
    class itself.
    """

    def __init__(self) -> None:
        pass

    def handle_event(self, bpf_collector: BPFCollector, event: ct._CData) -> int:
        """
        Handle an event from EBPF ringbuffer.
        Every event should be tagged with a short int as the first member to
        handle it's type. It is then dispatched to the appropriate method,
        which will be able to make sense of the actual struct.
        """
        # All events should be tagged with the event's type
        event_stub = ct.cast(event, ct.POINTER(event_base)).contents
        event_type_name = EventType(event_stub.event_type).name
        pid = event_stub.pid
        method_name = f"handle_{event_type_name}"
        method: Callable[[BPFCollector, ct._CData, int], int] = getattr(
            self, method_name
        )
        return method(bpf_collector, event, pid)

    # pylint: disable=unused-argument
    def handle_ProcessExit(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle ProcessExit event.
        """
        return bpf_collector.cleanup_process(pid)

    # pylint: disable=unused-argument
    def handle_ProcessFork(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle ProcessEnter event.
        """
        return bpf_collector.setup_process(pid)


@dataclass
class CollectorOptions:
    """
    Base class for BPFCollector Options.
    """

    enable_perf_events: bool = True
    sample_freq: int = 1200


T = TypeVar("T", bound="BPFCollector")


class BPFCollector:
    """
    Workhorse for pgtracer.

    This class allows the user to load an EBPF program dynamically generated
    using supplied options and extracted metadata about the Postgres
    executable.
    """

    options_cls: Type[CollectorOptions] = CollectorOptions
    event_handler_cls: Type[EventHandler] = EventHandler

    ExecEndFuncs = [
        "ExecEndAgg",
        "ExecEndAppend",
        "ExecEndBitmapAnd",
        "ExecEndBitmapHeapScan",
        "ExecEndBitmapIndexScan",
        "ExecEndBitmapOr",
        "ExecEndCteScan",
        "ExecEndCustomScan",
        "ExecEndForeignScan",
        "ExecEndFunctionScan",
        "ExecEndGather",
        "ExecEndGatherMerge",
        "ExecEndGroup",
        "ExecEndHash",
        "ExecEndHashJoin",
        "ExecEndIncrementalSort",
        "ExecEndIndexOnlyScan",
        "ExecEndIndexScan",
        "ExecEndLimit",
        "ExecEndLockRows",
        "ExecEndMaterial",
        "ExecEndMemoize",
        "ExecEndMergeAppend",
        "ExecEndMergeJoin",
        "ExecEndModifyTable",
        "ExecEndNamedTuplestoreScan",
        "ExecEndNode",
        "ExecEndNestLoop",
        "ExecEndProjectSet",
        "ExecEndRecursiveUnion",
        "ExecEndResult",
        "ExecEndSampleScan",
        "ExecEndSeqScan",
        "ExecEndSetOp",
        "ExecEndSort",
        "ExecEndSubqueryScan",
        "ExecEndTableFuncScan",
        "ExecEndTidRangeScan",
        "ExecEndTidScan",
        "ExecEndUnique",
        "ExecEndValuesScan",
        "ExecEndWindowAgg",
        "ExecEndWorkTableScan",
    ]

    def __init__(
        self,
        metadata: ProcessMetadata,
        options: Optional[CollectorOptions] = None,
        include_children: bool = False,
    ):
        if options is None:
            options = self.options_cls()
        self.options = options
        self.include_children = include_children
        self.anon_map_fds: Dict[int, int] = {}
        self.ppid: Optional[int]
        if include_children:
            self.pid = -1
            self.ppid = metadata.pid
        else:
            self.pid = metadata.pid
            self.ppid = None

        self.metadata = metadata
        self.program = str(self.metadata.program).encode("utf8")
        # Old bcc version don't support global usdt probes, so disable
        # memory tracking in that case
        if self.include_children is False or BCC_VERSION_TUPLE >= (0, 19, 0):
            self.usdt_ctx = USDT(metadata.pid)
            self.enable_usdt_probes(self.usdt_ctx)
        else:
            self.usdt_ctx = None
        self.bpf = self.prepare_bpf()
        self.setup_bpf_state()
        self.event_handler: EventHandler = self.event_handler_cls()
        self.update_struct_defs()
        self.is_running = False
        self.current_query: Optional[Query] = None
        self.background_thread: Optional[Thread] = None
        self.lock = Lock()
        self.sample_freq = options.sample_freq
        self.backend_type: Optional[IntEnum] = None

    @classmethod
    def from_pid(
        cls: Type[T], pid: int, options: CollectorOptions = CollectorOptions()
    ) -> T:
        """
        Build a BPFCollector from a pid.
        """
        # FIXME: make this configurable
        cache_dir = Path("~/.cache").expanduser() / "pgtracer"
        process = Process(pid=pid)
        # Check if we are given the postmaster pid, or a backend.
        # If our parent is itself a postgres process, then we are instrumenting the whole backend.
        pprocess = process.parent()
        include_children = bool(
            pprocess and pprocess.name() not in ("postgres", "postmaster")
        )
        processmetadata = ProcessMetadata(process, cache_dir=cache_dir)
        return cls(processmetadata, options, include_children=include_children)

    def update_struct_defs(self) -> None:
        """
        Update the ctypes struct definitions from the DWARF metadata.

        Some C structs used in EBPF must match what is defined by Postgres:
        so we build the class dynamically after the DWARF file has been loaded.
        """
        global instrument_type  # pylint: disable=global-statement
        instrument_type = ct.c_byte * self.metadata.structs.Instrumentation.size()
        # Update global struct definitions with actual sizes
        portal_data.update_fields(
            {
                "query": ct.c_char * MAX_QUERY_LENGTH,
                "instrument": instrument_type,
                "search_path": ct.c_char * MAX_SEARCHPATH_LENGTH,
            }
        )
        planstate_data.update_fields({"instrument": instrument_type})
        stack_sample.update_fields({"portal_data": portal_data})

    @property
    def constant_defines(self) -> Dict[str, int]:
        """
        Returns a list of constants to add to the ebpf program as #define
        directives.
        """
        constants = {
            "STACK_TOP_ADDR": self.metadata.stack_top,
            # TODO: find a way to extract those ?
            "POSTGRES_EPOCH_JDATE": 2451545,
            "UNIX_EPOCH_JDATE": 2440588,
            "SECS_PER_DAY": 86400,
            # TODO: make those configurable ?
            "MAX_QUERY_NUMBER": 10,
            "MAX_QUERY_LENGTH": MAX_QUERY_LENGTH,
            "MAX_STACK_READ": 4096,
            "MAX_SEARCHPATH_LENGTH": MAX_SEARCHPATH_LENGTH,
            "EVENTRING_PAGE_SIZE": 1024,
            "MEMORY_REQUEST_MAXSIZE": MEMORY_REQUEST_MAXSIZE,
            "MEMORY_PATH_SIZE": MEMORY_PATH_SIZE,
            "LIBBCC_MAJOR_VERSION": BCC_VERSION_TUPLE[0],
            "LIBBCC_MINOR_VERSION": BCC_VERSION_TUPLE[1],
            "LIBBCC_PATCH_VERSION": BCC_VERSION_TUPLE[2],
        }
        if self.ppid is not None:
            constants["POSTMASTER_PID"] = self.ppid
        else:
            constants["PID"] = self.pid
        return constants

    @property
    def struct_offsets_defines(self) -> Dict[str, int]:
        """
        Build C-Code for the eBPF code to easily access named members in
        structs.

        We read the offset in a struct for known members, so that the eBPF code
        can read those members from the Postgres struct.

        This is necessary because we can't include Postgres headers in the eBPF
        code.
        """
        # Returns a normalized way of DEFINING struct offsets
        s = self.metadata.structs

        return {
            f"STRUCT_{struct}_OFFSET_{member}": getattr(s, struct)
            .field_definition(member)
            .offset
            for struct, member in (
                ("Node", "type"),
                ("Plan", "type"),
                ("Plan", "startup_cost"),
                ("Plan", "total_cost"),
                ("Plan", "plan_rows"),
                ("Plan", "plan_width"),
                ("Plan", "parallel_aware"),
                ("PlannedStmt", "queryId"),
                ("PlanState", "instrument"),
                ("PlanState", "plan"),
                ("PlanState", "type"),
                ("PlanState", "lefttree"),
                ("PlanState", "righttree"),
                ("PortalData", "creation_time"),
                ("PortalData", "queryDesc"),
                ("QueryDesc", "instrument_options"),
                ("QueryDesc", "planstate"),
                ("QueryDesc", "sourceText"),
                ("QueryDesc", "plannedstmt"),
            )
        }

    def make_global_variables_enum(self) -> Type[IntEnum]:
        """
        Create an IntEnum mapping global variables names to their address in
        the program.
        """
        mapping = {}

        for key in ("ActivePortal", "namespace_search_path"):
            mapping[key] = self.metadata.global_variable(key)
        # Mypy complains about dynamic enums
        globalenum = IntEnum("GlobalVariables", mapping)  # type: ignore

        return globalenum

    def make_struct_sizes_dict(self) -> Dict[str, int]:
        """
        Create a dictionary mapping struct name to their bytesize.

        Once again, this is because we can't include Postgres header and call
        "sizeof".
        """
        mapping = {}

        for key in ("Instrumentation",):
            mapping[f"STRUCT_SIZE_{key}"] = getattr(self.metadata.structs, key).size()

        return mapping

    def _attach_uprobe(self, function_name: str, ebpf_function: str) -> None:
        """
        Helper to attach a uprobe executing `ebpf_function` at every
        `function_name` location.
        """
        for addr in self.metadata.function_addresses(function_name):
            self.bpf.attach_uprobe(
                name=self.program,
                fn_name=ebpf_function.encode("utf8"),
                addr=addr,
                pid=self.pid,
            )

    def _attach_uretprobe(self, function_name: str, ebpf_function: str) -> None:
        """
        Helper to attach a uretprobe executing `ebpf_function` at every
        `function_name` location.
        """
        # TODO: make sure multiple addresses work too
        for addr in self.metadata.function_addresses(function_name):
            self.bpf.attach_uretprobe(
                name=self.program,
                fn_name=ebpf_function.encode("utf8"),
                addr=addr,
                pid=self.pid,
            )

    def background_polling(self, refresh_rate: int) -> None:
        """
        Run the polling in the background.
        """
        while self.is_running:
            self.bpf.ring_buffer_poll(refresh_rate)
            sleep(refresh_rate / 1000.0)

    def attach_probes(self) -> None:
        """
        Attach the required probes for this collector.
        """
        if self.options.enable_perf_events:
            self.bpf.attach_perf_event(
                ev_type=PerfType.SOFTWARE,
                ev_config=PerfSWConfig.CPU_CLOCK,
                fn_name=b"perf_event",
                pid=self.pid,
                sample_freq=self.sample_freq,
            )

    def enable_usdt_probes(self, usdt: USDT) -> None:
        """
        Enable USDT probes.
        """

    def start(self) -> None:
        """
        Starts the bpf collector.
        """

        if self.is_running:
            raise InvalidStateException("BPF Collector is already running")
        print("Starting eBPF collector...")
        self.bpf[b"event_ring"].open_ring_buffer(self._handle_event)
        self.attach_probes()
        self.is_running = True
        self.background_thread = Thread(target=self.background_polling, args=(100,))
        self.background_thread.start()
        print("eBPF collector started")

    def stop(self) -> None:
        """
        Stop polling the collector.
        """
        self.is_running = False
        if self.background_thread:
            self.background_thread.join()
            self.background_thread = None
            for pid, fd in self.anon_map_fds.items():  # pylint: disable=invalid-name
                os.close(fd)
                try:
                    del self.bpf[b"pid_queues"][ct.c_int(pid)]
                except KeyError:
                    pass
            self.bpf.cleanup()

    # pylint: disable=unused-argument
    def _handle_event(self, cpu: int, data: ct._CData, size: int) -> int:
        """
        Callback for the ring_buffer_poll. We actually dispatch this to the
        `EventHandler`
        """
        # Returning a negative value aborts polling
        if not self.is_running:
            return -1
        return self.event_handler.handle_event(self, data)

    def _optional_code(self) -> str:
        """
        Load additional code, depending on options or the specific
        Collector type.
        """
        buf = ""
        if self.options.enable_perf_events:
            buf += load_c_file("perf.c")
        return buf

    def build_memory_request(
        self,
        event_type: EventType,
        request_id: Id128,
        base_addr: int,
        base_type: Type[Union[ct._CData, Struct, DWARFPointer]],
        path: List[str],
    ) -> memory_request:
        """
        Build a memory request from a request_id, a base_addr, a known base_type living
        at this addr and a path describing which fields to follow to the final memory location.

        The fields definitions are extracted from the debug symbols.
        """
        memory_path = (ct.c_ulonglong * MEMORY_PATH_SIZE)()
        # We have the base address, the path, and finally an offset 0 to read the memory itself.
        mempath_length = len(path) + 1
        assert mempath_length <= MEMORY_PATH_SIZE
        memory_path[0] = base_addr
        current_type = base_type
        current_idx = 0
        for part in path:
            # If we follow a pointer, add a new item to the underlying path.
            # Otherwise, just add to the previous type.
            if issubclass(current_type, DWARFPointer):
                current_type = current_type.pointed_type
                current_idx += 1
                memory_path[current_idx] = 0
            if issubclass(current_type, Struct):
                attr = current_type.field_definition(part)
                if attr is None:
                    raise AttributeError(f"Type {current_type} has no field {attr}")
                current_type = attr.member_type
                memory_path[current_idx] += attr.offset
            else:
                raise AttributeError(
                    f"Cannot dereference field {part} from type {current_type}"
                )
        # For convenience, support the last field as a pointer.
        if issubclass(current_type, DWARFPointer) or current_type == ct.c_char_p:
            memory_path[current_idx + 1] = 0
            mempath_length += 1
        size = get_size(current_type, dereference=True)

        return memory_request(
            event_type=event_type,
            request_id=request_id,
            path_size=mempath_length,
            size=size,
            memory_path=memory_path,
        )

    def send_memory_request(self, pid: int, request: memory_request) -> None:
        """
        Sends a memory request to the ebpf program.
        """
        try:
            map_id = self.bpf[b"pid_queues"][ct.c_int(pid)]
        except KeyError:
            # If we don't have a map for this process, we can't send memory requests.
            return
        map_fd = bcclib.bpf_map_get_fd_by_id(map_id)
        ret = bcclib.bpf_update_elem(map_fd, 0, ct.byref(request), 0)
        if ret < 0:
            raise ValueError("Something went wrong while sending a memory request")

    def preprocess_code(self, buf: str) -> str:
        """
        Preprocess code for things macro are not allowed to do with BCC.
        """
        if self.include_children:
            buf = buf.replace(
                "##CHECK_POSTMASTER##",
                """{ 
                u64 ppid; 
                struct task_struct* task_p = (struct task_struct*)bpf_get_current_task(); 
                struct task_struct* parent_task_p = task_p->real_parent; 
                ppid = parent_task_p->tgid; 
                if (ppid != POSTMASTER_PID) 
                    return 0; 
                };""",
            )
        else:
            buf = buf.replace("##CHECK_POSTMASTER##", "")
        return buf

    def prepare_bpf(self) -> BPF:
        """
        Generate the eBPF program, both from static code and dynamically
        generated defines and enums.
        """
        buf = defines_dict_to_c(self.constant_defines)
        buf += defines_dict_to_c(self.struct_offsets_defines)
        buf += defines_dict_to_c(self.make_struct_sizes_dict())
        buf += intenum_to_c(EventType)
        buf += intenum_to_c(MemoryAllocType)
        buf += intenum_to_c(self.make_global_variables_enum())
        buf += load_c_file("program.c")
        buf += self._optional_code()
        # Ok, now workaround some limitations of the macro system with bcc and implement our own.
        buf = self.preprocess_code(buf)
        # Add the code directory as include dir
        cflags = [f"-I{CODE_BASE_PATH}"]
        # Suppress some common warnings depending on bcc / kernel combinations
        cflags.append("-Wno-macro-redefined")
        cflags.append("-Wno-ignored-attributes")
        # Only enable global memory probe if bcc version is recent enough
        kwargs: Dict[str, Any] = {}
        if self.include_children and BCC_VERSION_TUPLE >= (0, 19, 0):
            kwargs["attach_usdt_ignore_pid"] = True
            kwargs["usdt_contexts"] = [self.usdt_ctx]
        bpf = BPF(text=buf.encode("utf8"), cflags=cflags, debug=0, **kwargs)
        return bpf

    def setup_bpf_state(self) -> None:
        """
        Setup the initial BPF State
        """
        if self.pid > 0:
            self.setup_process(self.pid)

    def setup_process(self, pid: int) -> int:
        """
        Callback when a new process is created.
        """
        if self.options.enable_perf_events:
            new_map = bcclib.bcc_create_map(
                BPF_MAP_TYPE_QUEUE, None, 0, ct.sizeof(memory_request), 1024, 0
            )
            self.bpf[b"pid_queues"][ct.c_int(pid)] = ct.c_int(new_map)
            self.anon_map_fds[pid] = new_map
        return 0

    def cleanup_process(self, pid: int) -> int:
        """
        Callback when a process exits.
        """
        # If we instrument a single pid, exit
        if self.pid == pid:
            print(f"Process {pid} is terminating, stopping collection")
            self.stop()
        else:
            try:
                if pid in self.anon_map_fds:
                    try:
                        del self.bpf[b"pid_queues"][ct.c_int(pid)]
                    except KeyError:
                        pass
                    os.close(self.anon_map_fds[pid])
            except KeyError:
                return 0
        return 0
