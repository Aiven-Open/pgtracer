"""
Workhorse for pgtracer.

The BPFCollector works by combining two things:
    - an ebpf program loaded in to the kernel, which is built on the fly
    - DWARF information extracted from the executable (or a separate debug
      symbols file).
"""
from __future__ import annotations

import ctypes as ct
from enum import IntEnum
from pathlib import Path
from threading import Lock, Thread
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from bcc import BPF
from psutil import Process

from ..model import Query
from .dwarf import ProcessMetadata
from .unwind import stack_data_t


def intenum_to_c(intenum: Type[IntEnum]) -> str:
    """
    Generate C code defining an enum corresponding to a Python IntEnum.
    """
    buf = f"enum {intenum.__name__} {{\n"
    members = []

    for member in intenum:
        members.append(f"{intenum.__name__}{member.name} = {member.value}")
    buf += ",\n".join(members)
    buf += "\n};\n"

    return buf


def defines_dict_to_c(defines_dict: Dict[str, Any]) -> str:
    """
    Generate a string of C #define directives from a mapping.
    """
    return (
        "\n".join(f"#define {key} {value}" for key, value in defines_dict.items())
        + "\n"
    )


CODE_BASE_PATH = Path(__file__).parent / "code"


def load_c_file(filename: str) -> str:
    """
    Loads a C file from the package code directory.
    """
    filepath = CODE_BASE_PATH / filename
    with filepath.open() as cfile:
        return cfile.read()


# pylint: disable=invalid-name
class EventType(IntEnum):
    """
    EventTypes generated by the EBPF code.
    """

    ExecutorRun = 1
    ExecutorFinish = 2
    DropPortalEnter = 3
    DropPortalReturn = 4
    ExecProcNodeFirst = 5
    ExecEndNode = 6
    KBlockRqIssue = 7


class portal_key(ct.Structure):
    """
    Maps the EBPF-defined struct "portal_key".
    This struct acts a key for a given portal instance, identified by it's pid
    and creation_time.
    """

    _fields_ = [("pid", ct.c_ulong), ("creation_time", ct.c_ulong)]

    def as_tuple(self) -> Tuple[int, int]:
        """
        Returns the struct as tuple.
        """
        return self.pid, self.creation_time


instrument_type = ct.c_byte * 0


class StubStructure(ct.Structure):
    """
    StubStructure definition, which actual fields must be updated at runtime.
    """

    _protofields: List[Tuple[str, Type[ct._CData]]] = []

    @classmethod
    def update_fields(cls, fields: Dict[str, Type[ct._CData]]) -> None:
        """
        Update the structure fields.
        """
        if hasattr(cls, "_fields_"):
            # We are not allowed to update it. But if all updated values are
            # the same as the first update, we don't care.
            fields_dict = dict(cls._fields_)  # type: ignore
            for key, value in fields.items():
                if fields_dict[key] != value:
                    raise ValueError("Cannot update a struct more than once.")
            return
        fields_dict = dict(cls._protofields)
        fields_dict.update(fields)
        cls._fields_ = list(fields_dict.items())


class portal_data(StubStructure):
    """
    Represents the portal_data associated to a portal.
    """

    _protofields = [
        ("event_type", ct.c_short),
        ("portal_key", portal_key),
        ("query", ct.c_char * 2048),
        ("instrument", instrument_type),
        ("search_path", ct.c_char * 1024),
    ]


class io_req_data(ct.Structure):
    """
    Represents the io_req_data coming from instrumenting the kernel.
    """

    _fields_ = [
        ("event_type", ct.c_short),
        ("rwbs", ct.c_char * 8),
        ("bytes", ct.c_ulonglong),
    ]


class plan_data(ct.Structure):
    """
    Represents the data associated with a PlanNode.
    """

    _fields_ = [
        ("plan_addr", ct.c_ulonglong),
        ("plan_tag", ct.c_int),
        ("startup_cost", ct.c_double),
        ("total_cost", ct.c_double),
        ("plan_rows", ct.c_double),
        ("plan_width", ct.c_int),
        ("parallel_aware", ct.c_bool),
    ]


class planstate_data(StubStructure):
    """
    Represents the data associated to a PlanState node.
    """

    _protofields = [
        ("event_type", ct.c_short),
        ("portal_key", portal_key),
        ("planstate_addr", ct.c_ulonglong),
        ("planstate_tag", ct.c_int),
        ("plan_data", plan_data),
        ("instrument", instrument_type),
        ("stack_capture", stack_data_t),
    ]


class EventHandler:
    """
    Base class for handling events.

    The handle_event method dispatched to handle_{EventType} methods if they
    exist. This acts mostly as a namespace to not pollute the BPFCollector
    class itself.
    """

    def __init__(self) -> None:
        self.query_cache: Dict[Tuple[int, int], Query] = {}
        self.query_history: List[Query] = []
        self.last_portal_key: Optional[Tuple[int, int]] = None
        self.current_executor: Optional[Tuple[int, int]] = None

    def handle_event(self, bpf_collector: BPF_Collector, event: ct._CData) -> int:
        """
        Handle an event from EBPF ringbuffer.
        Every event should be tagged with a short int as the first member to
        handle it's type. It is then dispatched to the appropriate method,
        which will be able to make sense of the actual struct.
        """
        # All events should be tagged with the event's type
        event_type = ct.cast(event, ct.POINTER(ct.c_short)).contents.value
        event_type_name = EventType(event_type).name
        method_name = f"handle_{event_type_name}"
        method: Callable[[BPF_Collector, ct._CData], int] = getattr(self, method_name)

        if method:
            return method(bpf_collector, event)

        return 0

    def handle_ExecutorRun(self, bpf_collector: BPF_Collector, event: ct._CData) -> int:
        """
        Handle ExecutorRun event. This event is produced by an uprobe on
        standard_ExecutorRun. See executorstart_enter in program.c.

        We record the fact that a query started, extracting relevant metadata
        already present at the query start.
        """
        event = ct.cast(event, ct.POINTER(portal_data)).contents
        key = event.portal_key.as_tuple()
        self.current_executor = event.portal_key.as_tuple()
        if key not in self.query_cache:
            self.query_cache[key] = Query.from_event(bpf_collector.metadata, event)
        else:
            self.query_cache[key].update(bpf_collector.metadata, event)
        return 0

    def handle_ExecutorFinish(
        self, bpf_collector: BPF_Collector, event: ct._CData
    ) -> int:
        """
        Handle ExecutorFinish event.
        """
        event = ct.cast(event, ct.POINTER(portal_data)).contents
        key = event.portal_key.as_tuple()
        if self.current_executor:
            self.current_executor = None
        if key in self.query_cache:
            self.query_cache[event.portal_key.as_tuple()].update(
                bpf_collector.metadata, event
            )
        return 0

    def handle_DropPortalEnter(
        self, bpf_collector: BPF_Collector, event: ct._CData
    ) -> int:
        """
        Handle DropPortalEnter event. This event is produced by a uprobe on
        DropPortal. See protaldrop_enter in program.c.

        PortalDrop is called whenever a query is finished: once the last row
        has been read in the case of a single query, or when the cursor is
        closed in the case of a cursor.

        Since PortalDrop is responsbile for cleaning up the portal, we record
        the instrumentation and other data about the query here, and remember
        it's identifier. Only once we return from DropPortal will we actually
        clean up the query from our current cache, and append it to history.
        """
        event = ct.cast(event, ct.POINTER(portal_data)).contents
        self.last_portal_key = event.portal_key.as_tuple()
        if self.last_portal_key in self.query_cache:
            self.query_cache[self.last_portal_key].update(bpf_collector.metadata, event)
        return 0

    # pylint: disable=unused-argument
    def handle_DropPortalReturn(
        self, bpf_collector: BPF_Collector, event: ct._CData
    ) -> int:
        """
        Handle DropPortalReturn event. This event is produced by an uretprobe on
        DropPortal. See protaldrop_return in program.c.

        We remove the query from the internal cache  and append it to history.
        """
        event = ct.cast(event, ct.POINTER(portal_data)).contents
        if self.last_portal_key is not None:
            if self.last_portal_key in self.query_cache:
                query = self.query_cache[self.last_portal_key]
                self.query_history.append(query)
                del self.query_cache[self.last_portal_key]
            self.last_portal_key = None
        self.current_executor = None
        return 0

    def handle_ExecProcNodeFirst(
        self, bpf_collector: BPF_Collector, event: ct._CData
    ) -> int:
        """
        Handle ExecProcNodeFirst event. This event is produced by a uprobe on
        ExecProcNodeFirst.

        The goal here is to build a plan tree for the query.
        """
        event = ct.cast(event, ct.POINTER(planstate_data)).contents
        query = self.query_cache.get(event.portal_key.as_tuple())
        if query is None:
            # We don't know this query: maybe it started running before us ?
            return 0
        query.add_node_from_event(bpf_collector.metadata, event)
        return 0

    def handle_ExecEndNode(self, bpf_collector: BPF_Collector, event: ct._CData) -> int:
        """
        Handle ExecEndNode event. This event is produced by a uprobe on
        ExecEndNode's implementations.

        Once the executor node is destroyed, we want to collect it's
        instrumentation data if any.
        """
        event = ct.cast(event, ct.POINTER(planstate_data)).contents
        if self.last_portal_key is None:
            return 0
        query = self.query_cache.get(self.last_portal_key)
        if query is None:
            return 0
        node = query.nodes.get(event.planstate_addr)
        if node is None:
            return 0
        instrument_addr = ct.addressof(event.instrument)
        instrument = bpf_collector.metadata.structs.Instrumentation(instrument_addr)
        instrument.nloops = ct.c_double(instrument.nloops.value + 1)  # type: ignore
        node.instrument = instrument
        return 0

    def handle_KBlockRqIssue(
        self, bpf_collector: BPF_Collector, event: ct._CData
    ) -> int:
        """
        Handle KBlockRqIssue event. This event is produced by a kernel
        tracepoint on block_rq_issue.

        This serves to keep a count of block IO performed by a device, which
        can be useful to compute "real" cache hit ratio.
        """
        event = ct.cast(event, ct.POINTER(io_req_data)).contents
        # We try to attach it to a specific query.
        # If we don't have one, don't bother
        if not self.current_executor:
            return 0
        query = self.query_cache.get(self.current_executor)
        if query is None:
            return 0
        if b"R" in event.rwbs:
            query.io_counters["R"] += event.bytes
        elif b"W" in event.rwbs:
            query.io_counters["W"] += event.bytes
        return 0


class BPF_Collector:
    """
    Workhorse for pgtracer.

    This class allows the user to load an EBPF program dynamically generated
    using supplied options and extracted metadata about the Postgres
    executable.
    """

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
        pid: int,
        instrument_options: Optional[int] = None,
        enable_plans_collection: bool = True,
    ):
        self.pid = pid
        self.process = Process(self.pid)
        # FIXME: make this configurable
        cache_dir = Path("~/.cache").expanduser() / "pgtracer"
        self.metadata = ProcessMetadata(self.process, cache_dir=cache_dir)
        self.program = str(self.metadata.program).encode("utf8")
        self.enable_plans_collection = enable_plans_collection
        self.instrument_options = instrument_options
        self.bpf = self.prepare_bpf()
        self.event_handler: EventHandler = EventHandler()
        self.update_struct_defs()
        self.is_running = False
        self.lock = Lock()

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
                "query": ct.c_char * 2048,
                "instrument": instrument_type,
                "search_path": ct.c_char * 1024,
            }
        )
        planstate_data.update_fields({"instrument": instrument_type})

    @property
    def constant_defines(self) -> Dict[str, int]:
        """
        Returns a list of constants to add to the ebpf program as #define
        directives.
        """
        constants = {
            "PID": self.pid,
            "STACK_TOP_ADDR": self.metadata.stack_top,
            # TODO: find a way to extract those ?
            "POSTGRES_EPOCH_JDATE": 2451545,
            "UNIX_EPOCH_JDATE": 2440588,
            "SECS_PER_DAY": 86400,
            # TODO: make those configurable ?
            "MAX_QUERY_NUMBER": 10,
            "MAX_QUERY_LENGTH": 2048,
            "MAX_STACK_READ": 4096,
            "MAX_SEARCHPATH_LENGTH": 1024,
            "EVENTRING_PAGE_SIZE": 1024,
        }

        # USER_INSTRUMENT_OPTIONS is defined only if the user wants to
        # inconditonally turn on instrumentation.
        if self.instrument_options:
            constants["USER_INSTRUMENT_OPTIONS"] = self.instrument_options

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
                ("PlanState", "instrument"),
                ("PlanState", "plan"),
                ("PlanState", "type"),
                ("PortalData", "creation_time"),
                ("PortalData", "queryDesc"),
                ("QueryDesc", "instrument_options"),
                ("QueryDesc", "planstate"),
                ("QueryDesc", "sourceText"),
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

    def start(self) -> None:
        """
        Start the ebpf collector:
         - attach uprobes/uretprobes
         - open the ringbuffer.
        """
        print("Starting eBPF collector...")
        self.bpf[b"event_ring"].open_ring_buffer(self._handle_event)
        self._attach_uprobe("PortalDrop", "portaldrop_enter")
        self._attach_uretprobe("PortalDrop", "portaldrop_return")
        self._attach_uprobe("standard_ExecutorStart", "executorstart_enter")
        self._attach_uprobe("standard_ExecutorRun", "executorrun_enter")
        self._attach_uprobe("ExecutorFinish", "executorfinish_enter")
        if self.enable_plans_collection:
            self._attach_uprobe("ExecProcNodeFirst", "execprocnodefirst_enter")
            for func in self.ExecEndFuncs:
                self._attach_uprobe(func, "execendnode_enter")
        self.is_running = True
        background_thread = Thread(target=self.background_polling, args=(100,))
        background_thread.start()
        print("eBPF collector started")

    def stop(self) -> None:
        """
        Stop polling the collector.
        """
        self.is_running = False

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
        buf = ""
        if self.enable_plans_collection:
            buf += load_c_file("plan.c")
        buf += load_c_file("block_rq.c")
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
        buf += intenum_to_c(self.make_global_variables_enum())
        buf += load_c_file("program.c")
        buf += self._optional_code()
        # Add the code directory as include dir
        cflags = [f"-I{CODE_BASE_PATH}"]
        # Suppress some common warnings depending on bcc / kernel combinations
        cflags.append("-Wno-macro-redefined")
        cflags.append("-Wno-ignored-attributes")
        bpf = BPF(text=buf.encode("utf8"), cflags=cflags, debug=0)
        return bpf
