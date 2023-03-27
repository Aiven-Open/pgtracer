"""
This module contains definitions for representing PostgreSQL queries.
"""
from __future__ import annotations

import ctypes as ct
from collections import defaultdict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, Optional

from ..ebpf.unwind import UnwindAddressSpace, stack_data_t
from ..utils import timespec_to_timedelta
from .memory import MemoryAllocations
from .plan import PlanState

if TYPE_CHECKING:
    from ..ebpf.collector import planstate_data, portal_data
    from ..ebpf.dwarf import ProcessMetadata


FUNCTION_ARGS_MAPPING = {
    "ExecProcNodeFirst": 1,
    "ExecProcNodeInstr": 1,
    "ExecProcNode": 1,
    "ExecAgg": 1,
    "ExecAppend": 1,
    "ExecBitmapAnd": 1,
    "ExecBitmapHeapScan": 1,
    "ExecBitmapIndexScan": 1,
    "ExecBitmapOr": 1,
    "ExecCteScan": 1,
    "ExecCustomScan": 1,
    "ExecForeignScan": 1,
    "ExecFunctionScan": 1,
    "ExecGather": 1,
    "ExecGatherMerge": 1,
    "ExecGroup": 1,
    "ExecHash": 1,
    "ExecHashJoin": 1,
    "ExecIncrementalSort": 1,
    "ExecIndexOnlyScan": 1,
    "ExecIndexScan": 1,
    "ExecLimit": 1,
    "ExecLockRows": 1,
    "ExecMaterial": 1,
    "ExecMemoize": 1,
    "ExecMergeAppend": 1,
    "ExecMergeJoin": 1,
    "ExecModifyTable": 1,
    "ExecNamedTuplestoreScan": 1,
    "ExecNestLoop": 1,
    "ExecProjectSet": 1,
    "ExecRecursiveUnion": 1,
    "ExecResult": 1,
    "ExecSampleScan": 1,
    "ExecSeqScan": 1,
    "ExecSetOp": 1,
    "ExecSort": 1,
    "ExecSubqueryScan": 1,
    "ExecTableFuncScan": 1,
    "ExecTidRangeScan": 1,
    "ExecTidScan": 1,
    "ExecUnique": 1,
    "ExecValuesScan": 1,
    "ExecWindowAgg": 1,
    "ExecWorkTableScan": 1,
    "MultiExecHash": 1,
    "MultiExecBitmapIndexScan": 1,
    "MultiExecBitmapAnd": 1,
    "MultiExecBitmapOr": 1,
}


class Query:
    """
    A PostgreSQL Query.
    """

    def __init__(
        self,
        *,
        addr: int,
        query_id: int,
        startup_cost: float,
        total_cost: float,
        plan_rows: float,
        startts: Optional[float] = None,
        text: Optional[str] = None,
        # Instrumentation is a dynamically generated class, no way to check it
        instrument: Any = None,
        search_path: Optional[str] = None,
    ):
        self.addr = addr
        self.query_id = query_id
        self.startup_cost = startup_cost
        self.total_cost = total_cost
        self.plan_rows = plan_rows
        self.startts = startts
        self.text = text
        self.instrument = instrument
        self.search_path = search_path
        self.nodes: Dict[int, PlanState] = {}
        self.io_counters: Dict[str, int] = defaultdict(lambda: 0)
        self.memallocs: MemoryAllocations = MemoryAllocations()

    @property
    def root_node(self) -> PlanState:
        """
        Returns the plan's root node.
        """
        root_candidates = [
            node for node in self.nodes.values() if node.parent_node is None
        ]
        if len(root_candidates) == 0:
            raise ValueError("Invalid plan, we have no root node when we expect 1")
        if len(root_candidates) > 1:
            # In that case, we need to build a "fake" parent node.
            root_node = PlanState(None)
            root_node.children = {c: None for c in root_candidates}
        else:
            root_node = root_candidates[0]
        return root_node

    @classmethod
    def from_event(cls, metadata: ProcessMetadata, event: portal_data) -> Query:
        """
        Build a query from portal_data event generated by eBPF.
        """
        instrument_addr = ct.addressof(event.instrument)
        instrument = metadata.structs.Instrumentation(instrument_addr)
        search_path = None
        if event.search_path:
            search_path = event.search_path.decode("utf8")
        _, creation_time = event.portal_key.as_tuple()
        return cls(
            addr=event.query_addr,
            query_id=event.query_id,
            startup_cost=event.startup_cost,
            total_cost=event.total_cost,
            plan_rows=event.plan_rows,
            startts=creation_time,
            text=event.query.decode("utf8"),
            instrument=instrument,
            search_path=search_path,
        )

    def update(self, metadata: ProcessMetadata, event: portal_data) -> None:
        """
        Update the query from an eBPF portal_data event.
        """
        instrument_addr = ct.addressof(event.instrument)
        instrument = metadata.structs.Instrumentation(instrument_addr)
        if instrument.running:
            self.instrument = instrument
        _, creation_time = event.portal_key.as_tuple()
        self.startts = creation_time or self.startts
        self.text = event.query.decode("utf-8") or self.text
        search_path = event.search_path.decode("utf8")
        self.search_path = search_path or self.search_path

    @property
    def start_datetime(self) -> Optional[datetime]:
        """
        Returns the creation timestamp of the portal associated to this query.
        """
        if self.startts is None:
            return None
        return datetime.fromtimestamp(self.startts / 1000000)

    @property
    def runtime(self) -> Optional[timedelta]:
        """
        Returns the query's top-node total runtime.
        """
        if self.instrument:
            return timespec_to_timedelta(self.instrument.counter)
        return None

    @property
    def shared_buffers_hitratio(self) -> Optional[float]:
        """
        Returns the hit ratio from the shared buffers.
        """
        if self.instrument is None:
            return None
        bufusage = self.instrument.bufusage
        total_blks = bufusage.shared_blks_hit.value + bufusage.shared_blks_read.value
        # If we didn't read any block, hit ratio is None
        if total_blks == 0:
            return None
        return float(bufusage.shared_blks_hit.value / total_blks * 100)

    @property
    def syscache_hitratio(self) -> Optional[float]:
        """
        Returns the system's hit ratio.
        """
        if self.instrument is None:
            return None
        bufusage = self.instrument.bufusage
        # FIXME: don't assume a fixed block size, either pass it as an option
        # or query the actual value from the DB
        BLKSIZE = 8192
        total_blks = (
            bufusage.shared_blks_read.value
            + bufusage.local_blks_read.value
            + bufusage.temp_blks_read.value
        )
        total_bytes = total_blks * BLKSIZE
        if total_bytes == 0:
            return None
        bytes_hit = total_bytes - self.io_counters["R"]
        return float(bytes_hit / total_bytes * 100)

    def add_nodes_from_stack(
        self,
        metadata: ProcessMetadata,
        stack: stack_data_t,
        start_at: int = 0,
        base_node: Optional[PlanState] = None,
    ) -> None:
        """
        Process a capture stack to add node stubs to this query.
        """
        addr_space = UnwindAddressSpace(stack, metadata)
        nodes = self.nodes
        cur_node = base_node
        for idx, frame in enumerate(addr_space.frames()):
            if idx < start_at:
                continue
            if frame.function_name in FUNCTION_ARGS_MAPPING:
                argnum = FUNCTION_ARGS_MAPPING[frame.function_name]
                parent_addr = frame.fetch_arg(argnum, ct.c_ulonglong).value
                if cur_node and parent_addr == cur_node.addr:
                    continue
                parent_node = nodes.get(parent_addr)
                if parent_node is None:
                    parent_node = PlanState(parent_addr)
                    nodes[parent_addr] = parent_node
                if cur_node:
                    cur_node.parent_node = parent_node
                    parent_node.children[cur_node] = None
                # The parent_node is already not a stub, meaning its ancestors
                # have been resolved. Stop walking the frame here
                if not parent_node.is_stub:
                    break
                cur_node = parent_node

    def add_node_from_event(
        self, metadata: ProcessMetadata, event: planstate_data
    ) -> PlanState:
        """
        Add a node from planstate_data event to this query plantree.
        We walk the stack up to understand where the nodes are located relative
        to each other.
        """
        nodes = self.nodes
        addr = event.planstate_addr
        planstate = nodes.get(addr)
        if planstate is None:
            planstate = PlanState(addr)
            nodes[addr] = planstate
        planstate.update(metadata, event)
        if not planstate.is_stub:
            return planstate
        self.add_nodes_from_stack(
            metadata, event.stack_capture, start_at=1, base_node=planstate
        )
        planstate.is_stub = False
        return planstate
