"""
This module contains definitions for representing PostgreSQL plans.
"""
from __future__ import annotations

import ctypes as ct
from typing import TYPE_CHECKING, Dict, Optional

from ..ebpf.collector.c_defs import plan_data, planstate_data
from ..ebpf.dwarf import ProcessMetadata, Struct
from ..utils import timespec_to_float

if TYPE_CHECKING:
    from enum import IntEnum


def explain_dict_to_str(parts: Dict[str, str]) -> str:
    """
    Format a dict in the commonly used key=value format.
    """
    return " ".join(f"{key}={value}" for key, value in parts.items())


class PlanState:
    """
    Information collected from a PostgreSQL PlanState Node.
    """

    def __init__(self, addr: Optional[int]):
        self.addr = addr
        self.tag: Optional[IntEnum] = None
        self.instrument: Optional[Struct] = None
        self.parent_node: Optional[PlanState] = None
        self.plan_data: Optional[plan_data] = None
        self.is_stub = True
        # We're using a Dict as poor man's OrderedSet
        self.children: Dict[PlanState, None] = {}

    def update(self, metadata: ProcessMetadata, event: planstate_data) -> None:
        """
        Update a Planstate from an event planstate_data.
        """
        instrument_addr = ct.addressof(event.instrument)
        tag = metadata.enums.NodeTag(event.plan_data.plan_tag)  # type: ignore
        self.tag = tag
        self.instrument = metadata.structs.Instrumentation(instrument_addr)
        self.plan_data = plan_data()
        ct.pointer(self.plan_data)[0] = event.plan_data

    @property
    def title(self) -> str:
        """
        Return the node's title.
        """
        if self.tag is None:
            return "???"
        prefix = ""
        if self.plan_data and self.plan_data.parallel_aware:
            prefix = "Parallel "
        buf = f"{prefix}{str(self.tag.name[2:])}"
        # TODO: add additional information here
        return buf

    @property
    def cost(self) -> str:
        """
        Returns the "cost" section formatted similarly to PostgreSQL explain
        """
        if self.plan_data is None:
            parts = {"cost": "?..?", "rows": "?", "width": "?"}
        else:
            parts = {
                "cost": f"{self.plan_data.startup_cost:.2f}..{self.plan_data.total_cost:.2f}",
                "rows": f"{int(self.plan_data.plan_rows)}",
                "width": f"{int(self.plan_data.plan_width)}",
            }
        return f"({explain_dict_to_str(parts)})"

    @property
    def actual(self) -> str:
        """
        Returns the "actual" section formatted similarly to PostgreSQL explain.
        """
        if self.instrument is None:
            parts = {"time": "?..?", "rows": "?", "loops": "?"}
        else:
            total = timespec_to_float(self.instrument.counter)
            parts = {
                "time": f"{(self.instrument.firsttuple.value * 1000):0.3f}...{(total * 1000):0.3f}",
                "rows": f"{int(self.instrument.tuplecount.value)}",
                "loops": f"{int(self.instrument.nloops.value)}",
            }
        return f"(actual {explain_dict_to_str(parts)})"

    @property
    def buffers(self) -> str:
        """
        Returns the "buffers" section formatted similarly to PostgreSQL
        explain.
        """
        if self.instrument is None:
            return ""
        bufusage_dict = self.instrument.bufusage.as_dict(include_all=True)
        parts = {}
        for key, value in bufusage_dict.items():
            if isinstance(value, (ct.c_long,)) and value.value != 0:
                parts[key] = str(value.value)
        if not parts:
            return ""
        return f"Buffers: {explain_dict_to_str(parts)}"

    def explain(self, indent_level: int = 0) -> str:
        """
        Format the plan represented by this node similarly to PostgreSQL
        explain.
        """
        if indent_level == 0:
            prefix = ""
        else:
            prefix = "\t" * indent_level + "-> "
        buf = f"{prefix}{self.title} {self.cost} {self.actual}"
        buffer_line = self.buffers
        if buffer_line:
            buf += "\n" + "\t" * (indent_level + 1) + buffer_line
        for child in self.children:
            buf += "\n"
            buf += child.explain(indent_level + 1)
        return buf
