"""
This module contains definitions for representing PostgreSQL queries.
"""
from __future__ import annotations

import ctypes as ct
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .collector import portal_data
    from .dwarf import ProcessMetadata


class Query:
    """
    A PostgreSQL Query.
    """

    def __init__(
        self,
        *,
        startts: Optional[float] = None,
        text: Optional[str] = None,
        # Instrumentation is dynamically generated class, no way to check it
        instrument: Any = None,
        search_path: Optional[str] = None,
    ):
        self.startts = startts
        self.text = text
        self.instrument = instrument
        self.search_path = search_path

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
        return cls(
            startts=event.portal_key.creation_time,
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
        self.startts = event.portal_key.creation_time or self.startts
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
            return timedelta(
                seconds=self.instrument.counter.tv_sec.value,
                microseconds=self.instrument.counter.tv_nsec.value / 1000,
            )
        return None
