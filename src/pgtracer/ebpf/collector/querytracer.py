"""
BPF Collector tracing queries.
"""
from __future__ import annotations

import ctypes as ct
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from bcc import USDT

from pgtracer.ebpf.dwarf import ProcessMetadata
from pgtracer.model.plan import PlanState
from pgtracer.model.query import Query

from ...model import PlanState, Query, memory_account
from . import BPFCollector, CollectorOptions, EventHandler, EventType
from .c_defs import (
    Id128,
    io_req_data,
    memory_response,
    planstate_data,
    portal_data,
    stack_sample,
)
from .utils import load_c_file


class InstrumentationFlags(IntEnum):
    """
    Instrumentation flags.

    Mimic the InstrumentOption enum from PG.
    We define it statically here as it can be used from options.
    """

    TIMER = 1 << 0
    BUFFERS = 1 << 1
    ROWS = 1 << 2
    WAL = 1 << 3
    ALL = 0x7FFFFFFF  # INT32 Max


@dataclass
class QueryTracerOptions(CollectorOptions):
    """
    Dataclass for QueryTracerBPFCollector options.
    """

    instrument_flags: int = 0
    enable_nodes_collection: bool = False
    enable_query_discovery: bool = True


# pylint: disable=invalid-name
class QueryTracerEventHandler(EventHandler):
    """
    EventHandler for QueryTracer.
    """

    def __init__(self) -> None:
        self.query_cache: Dict[Tuple[int, int], Query] = {}
        self.query_history: List[Query] = []
        self.last_portal_key: Optional[Tuple[int, int]] = None
        self.current_executor: Optional[Tuple[int, int]] = None
        self.next_request_id = 0

    def _process_portal_data(
        self, bpf_collector: BPFCollector, event: portal_data, pid: int
    ) -> int:
        """
        Process the portal data. This is used both when a query starts, and when we see
        the first live query during query discovery.
        """
        key = event.portal_key.as_tuple()
        self.current_executor = event.portal_key.as_tuple()

        if key not in self.query_cache:
            self.query_cache[key] = Query.from_event(bpf_collector.metadata, event)
        else:
            self.query_cache[key].update(bpf_collector.metadata, event)
        bpf_collector.current_query = self.query_cache[key]
        # If perf events are enabled, start watching the query instrumentation.
        if bpf_collector.options.enable_perf_events:
            structs = bpf_collector.metadata.structs
            # FIXME: this should go to a helper method, taking the
            # full path in C notation
            request = bpf_collector.build_memory_request(
                EventType.MemoryResponseQueryInstr,
                event.portal_key,
                event.query_addr,
                structs.QueryDesc,
                ["planstate", "instrument"],
            )
            bpf_collector.send_memory_request(pid, request)
        return 0

    def handle_ExecutorRun(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle ExecutorRun event. This event is produced by an uprobe on
        standard_ExecutorRun. See executorstart_enter in program.c.

        We record the fact that a query started, extracting relevant metadata
        already present at the query start.
        """
        if bpf_collector.options.enable_perf_events:
            bpf_collector.bpf[b"discovery_enabled"][ct.c_int(1)] = ct.c_bool(False)
            bpf_collector.bpf[b"discovery_enabled"][ct.c_int(2)] = ct.c_bool(False)
        event = ct.cast(event, ct.POINTER(portal_data)).contents
        return self._process_portal_data(bpf_collector, event, pid)

    # pylint: disable=unused-argument
    def handle_ExecutorFinish(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle ExecutorFinish event.
        """
        event = ct.cast(event, ct.POINTER(portal_data)).contents
        key = event.portal_key.as_tuple()
        if self.current_executor:
            self.current_executor = None
            bpf_collector.current_query = None
        if key in self.query_cache:
            self.query_cache[event.portal_key.as_tuple()].update(
                bpf_collector.metadata, event
            )
        return 0

    # pylint: disable=unused-argument
    def handle_DropPortalEnter(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
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
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
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
        bpf_collector.current_query = None
        return 0

    def handle_ExecProcNodeFirst(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
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
        if bpf_collector.options.enable_perf_events:
            request = bpf_collector.build_memory_request(
                EventType.MemoryResponseNodeInstr,
                Id128.from_int(event.planstate_addr),
                event.planstate_addr,
                bpf_collector.metadata.structs.PlanState,
                ["instrument"],
            )
            bpf_collector.send_memory_request(pid, request)
        return 0

    def handle_ExecEndNode(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
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
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
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

    def handle_MemoryResponseQueryInstr(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle MemoryResponseQueryInstr

        We lookup the request_id, and update the given counters if needed.
        """
        ev = ct.cast(event, ct.POINTER(memory_response)).contents

        if not self.current_executor:
            return 0
        # We have a memory response for the whole query
        query = self.query_cache.get(ev.request_id.as_tuple(), None)
        if query:
            instr = bpf_collector.metadata.structs.Instrumentation(ev.payload_addr)
            query.instrument = instr
            # Load all fields from the underlying memory.
            instr.as_dict(include_all=True)
            # Re-send the same request for continuous monitoring
            request = bpf_collector.build_memory_request(
                EventType.MemoryResponseQueryInstr,
                ev.request_id,
                query.addr,
                bpf_collector.metadata.structs.QueryDesc,
                ["planstate", "instrument"],
            )

            bpf_collector.send_memory_request(pid, request)
        return 0

    def handle_MemoryResponseNodeInstr(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle MemoryResponseNodeInstr produced as a response to some memory_request.
        """
        if not self.current_executor:
            return 0
        query = self.query_cache.get(self.current_executor, None)
        ev = ct.cast(event, ct.POINTER(memory_response)).contents
        nodeid = ev.request_id.as_int()
        # We have a memory response for an individual node
        if query is not None and nodeid is not None:
            node = query.nodes.get(nodeid)
            if node is not None:
                instr = bpf_collector.metadata.structs.Instrumentation(ev.payload_addr)
                node.instrument = instr
                # Re-send the same request for continuous monitoring
                request = bpf_collector.build_memory_request(
                    EventType.MemoryResponseNodeInstr,
                    Id128.from_int(nodeid),
                    nodeid,
                    bpf_collector.metadata.structs.PlanState,
                    ["instrument"],
                )
                bpf_collector.send_memory_request(pid, request)
        return 0

    def handle_MemoryNodeData(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle MemoryNodeData produced as a response for a memory_request.
        """
        if not self.current_executor:
            return 0
        ev = ct.cast(event, ct.POINTER(planstate_data)).contents
        query = self.query_cache.get(self.current_executor, None)
        if query is not None:
            node = query.add_node_from_event(bpf_collector.metadata, ev)
            if ev.lefttree and ev.lefttree not in query.nodes:
                leftchild = PlanState(ev.lefttree)
                leftchild.parent_node = node
                query.nodes[ev.lefttree] = leftchild
                node.children[leftchild] = None
                self._gather_node_info(bpf_collector, ev.lefttree, pid)
            if ev.righttree and ev.righttree not in query.nodes:
                rightchild = PlanState(ev.righttree)
                rightchild.parent_node = node
                query.nodes[ev.righttree] = rightchild
                node.children[rightchild] = None
                self._gather_node_info(bpf_collector, ev.righttree, pid)
        return 0

    def _gather_node_info(
        self, bpf_collector: BPFCollector, nodeaddr: int, pid: int
    ) -> None:
        """
        Send memory requests to gather information about a specific node.
        """
        req = bpf_collector.build_memory_request(
            EventType.MemoryNodeData,
            Id128.from_int(nodeaddr),
            nodeaddr,
            bpf_collector.metadata.structs.PlanState,
            [],
        )
        bpf_collector.send_memory_request(pid, req)

    def handle_StackSample(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle StackSample events produced during perf sampling.
        """
        ev = ct.cast(event, ct.POINTER(stack_sample)).contents
        _, creation_time = ev.portal_data.portal_key.as_tuple()
        if creation_time:
            self._process_portal_data(bpf_collector, ev.portal_data, pid)
        bpf_collector.bpf[b"discovery_enabled"][ct.c_int(1)] = ct.c_bool(False)
        if bpf_collector.current_query:
            # Now add the nodes from the stacktrace
            bpf_collector.current_query.add_nodes_from_stack(
                bpf_collector.metadata, ev.stack_data
            )
            # And add memory_requests to gather their information.
            for node in bpf_collector.current_query.nodes.values():
                if node.is_stub and node.addr:
                    self._gather_node_info(bpf_collector, node.addr, pid)
        return 0

    def handle_MemoryAccount(
        self, bpf_collector: BPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle MemoryAccount events produced by malloc instrumentation.
        """
        ev = ct.cast(event, ct.POINTER(memory_account)).contents
        if bpf_collector.current_query:
            bpf_collector.current_query.memallocs.update(ev)
        return 0


class QueryTracerBPFCollector(BPFCollector):
    """
    BPF Collector tracing queries and optionally individual nodes.
    """

    options_cls = QueryTracerOptions
    event_handler_cls = QueryTracerEventHandler

    def __init__(
        self,
        metadata: ProcessMetadata,
        options: Optional[QueryTracerOptions] = None,
        include_children: bool = False,
    ):
        self.options: QueryTracerOptions
        self.event_handler: QueryTracerEventHandler
        super().__init__(metadata, options, include_children)

    def attach_probes(self) -> None:
        super().attach_probes()
        self._attach_uprobe("PortalDrop", "portaldrop_enter")
        self._attach_uretprobe("PortalDrop", "portaldrop_return")
        self._attach_uprobe("standard_ExecutorStart", "executorstart_enter")
        self._attach_uprobe("standard_ExecutorRun", "executorrun_enter")
        self._attach_uprobe("ExecutorFinish", "executorfinish_enter")
        self._attach_uprobe("mmap", "mmap_enter")
        self.bpf.attach_uprobe(
            name="c", sym="mmap", fn_name=b"mmap_enter", pid=self.pid
        )
        self.bpf.attach_uprobe(
            name="c", sym="munmap", fn_name=b"munmap_enter", pid=self.pid
        )
        if self.options.enable_nodes_collection:
            self._attach_uprobe("ExecProcNodeFirst", "execprocnodefirst_enter")
            for func in self.ExecEndFuncs:
                self._attach_uprobe(func, "execendnode_enter")

    def enable_usdt_probes(self, usdt: USDT) -> None:
        usdt.enable_probe(probe="libc:memory_sbrk_less", fn_name="sbrk_less")
        usdt.enable_probe(probe="libc:memory_sbrk_more", fn_name="sbrk_more")

    @property
    def constant_defines(self) -> Dict[str, int]:
        constants = super().constant_defines
        # USER_INSTRUMENT_FLAGS is defined only if the user wants to
        # inconditonally turn on instrumentation.
        if self.options.instrument_flags:
            constants["USER_INSTRUMENT_FLAGS"] = self.options.instrument_flags
        if self.options.enable_query_discovery:
            if not self.ppid:
                constants["ENABLE_QUERY_DISCOVERY"] = True
        return constants

    def _optional_code(self) -> str:
        buf = super()._optional_code()
        if self.options.enable_nodes_collection:
            buf += load_c_file("plan.c")
        buf += load_c_file("block_rq.c")
        buf += load_c_file("memusage.c")
        return buf

    def setup_bpf_state(self) -> None:
        # FIXME: get rid of those magic numbers.
        super().setup_bpf_state()
        if self.options.enable_perf_events:
            self.bpf[b"discovery_enabled"][ct.c_int(1)] = ct.c_bool(
                self.options.enable_query_discovery
            )
            self.bpf[b"discovery_enabled"][ct.c_int(2)] = ct.c_bool(
                self.options.enable_query_discovery
            )
