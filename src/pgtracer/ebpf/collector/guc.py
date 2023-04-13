"""
This module defines the collector for getting / setting GUC.
"""
from __future__ import annotations

import ctypes as ct
import struct
from dataclasses import dataclass
from typing import Any, BinaryIO, Dict, Optional, Tuple, Type

from elftools.elf.elffile import ELFFile

from ...utils import readcstr
from ..dwarf import ProcessMetadata, Struct
from . import BPFCollector, CollectorOptions, EventHandler
from .c_defs import event_base
from .utils import load_c_file

GUC_MAX_LENGTH = 128


# pylint: disable=invalid-name
class guc_request(ct.Structure):
    """
    A request to set a guc.
    """

    _fields_ = [
        ("guc_location", ct.c_ulonglong),
        ("guc_size", ct.c_int),
        ("payload", ct.c_byte * GUC_MAX_LENGTH),
    ]


# pylint: disable=invalid-name
class guc_response(ct.Structure):
    """
    A response to a guc_request.
    """

    _fields_ = [
        ("event", event_base),
        ("guc_location", ct.c_ulonglong),
        ("status", ct.c_bool),
    ]


class GUCTracerOptions(CollectorOptions):
    """
    Dataclass for GUCTracerBPFCollector options.
    """

    sample_freq: int = 3000
    guc_to_watch: Dict[str, str] = {}


class GUCTracerEventHandler(EventHandler):
    """
    EventHandler for the GUCTracerBPFCollector.
    """

    def __init__(self) -> None:
        super().__init__()
        self.pending_names_req: Dict[int, GUCDefinition] = {}

    # pylint: disable=invalid-name
    def handle_GUCResponse(
        self, bpf_collector: GUCTracerBPFCollector, event: ct._CData, pid: int
    ) -> int:
        """
        Handle GUCResponse messages.
        """
        event = ct.cast(event, ct.POINTER(guc_response)).contents
        guc_def, value = bpf_collector.pending_guc_sets.pop(event.guc_location)
        if event.status:
            print(
                f"GUC {guc_def.guc_name}@{event.guc_location} has been successfully set to {value}"
            )
        else:
            print(
                f"GUC {guc_def.guc_name}@{event.guc_location} has failed to be set to {value}"
            )
        return 0


@dataclass
class GUCDefinition:
    """
    A GUC definition, extracted from the binary.
    """

    guc_type: str
    guc_name: str
    guc_location: int


class GUCTracerBPFCollector(BPFCollector):
    """
    BPF Collector tracing GUCs and potentially modifying them.
    """

    options_cls = GUCTracerOptions
    event_handler_cls = GUCTracerEventHandler

    GUC_TABLE_TYPE_TO_VARIABLE = {
        "config_bool": "ConfigureNamesBool",
        "config_int": "ConfigureNamesInt",
        "config_real": "ConfigureNamesReal",
        "config_string": "ConfigureNamesString",
        "config_enum": "ConfigureNamesEnum",
    }

    def __init__(
        self,
        metadata: ProcessMetadata,
        options: Optional[CollectorOptions] = None,
        include_children: bool = False,
    ):
        if include_children:
            raise NotImplementedError(
                "GUC Tracer does not support attaching to the whole cluster."
            )
        self.options: CollectorOptions
        self.guc_defs: Dict[str, GUCDefinition] = {}
        self.pending_guc_sets: Dict[int, Tuple[GUCDefinition, Any]] = {}
        # We must not rely on the debug symbol elffile, but instead the one
        # from the executable itself
        with ELFFile.load_from_path(metadata.program) as elf:
            reladyn = elf.get_section_by_name(".rela.dyn")
            self.relocations: Dict[int, int] = {
                reloc["r_offset"]: reloc["r_addend"]
                for reloc in reladyn.iter_relocations()
            }
        self.ready = False
        super().__init__(metadata, options)

    def _relocate_addr(self, addr: int) -> int:
        """
        Relocate an address from the .rela.dyn section information.
        """
        if addr in self.relocations:
            return self.relocations[addr]
        return 0

    def _load_one_gucdef(
        self, addr: int, gucdef_type: Type[Struct], binfile: BinaryIO
    ) -> Optional[GUCDefinition]:
        """
        Load one GUC definition from the binary
        """
        # First lookup it's name. We could just use the base address
        # since it's the first member but better make it correct
        gen_definition = gucdef_type.field_definition("gen")
        if gen_definition is None:
            raise ValueError(
                f"Could not find member gen in struct {gucdef_type.__name__}"
            )
        name_definition = gen_definition.member_type.field_definition("name")  # type: ignore
        if name_definition is None:
            raise ValueError(
                f"Could not find member name in struct {gen_definition.member_type.__name__}"
            )
        name_pointer_addr = addr + gen_definition.offset + name_definition.offset
        # Now lookup the relocation information for that address
        reloced_addr = self._relocate_addr(name_pointer_addr)
        if reloced_addr == 0:
            return None
        # Now we can read the data from the binary
        binfile.seek(reloced_addr)
        guc_bname = readcstr(binfile)
        guc_name = guc_bname.decode("utf8")
        # Now relocate the GUC global variable address
        variable_definition = gucdef_type.field_definition("variable")
        if variable_definition is None:
            raise ValueError(
                f"Could not find member variable in struct {gucdef_type.__name__}"
            )

        variable_pointer_addr = addr + variable_definition.offset
        reloced_addr = self._relocate_addr(variable_pointer_addr)
        return GUCDefinition(
            guc_name=guc_name,
            guc_type=gucdef_type.__name__.replace("config_", ""),
            guc_location=reloced_addr + self.metadata.base_addr,
        )

    def _load_guc_defs_from_binary(self) -> None:
        """
        Load GUC definitions from the binary executable.
        """
        with open(self.metadata.program, "rb") as programbin:
            for typname, variable_name in self.GUC_TABLE_TYPE_TO_VARIABLE.items():
                deftype = getattr(self.metadata.structs, typname)
                typsize = deftype.size
                variable_addr = self.metadata.global_variable(variable_name)
                if variable_addr is None:
                    raise ValueError(
                        f"Could not locate global variable {variable_name}"
                    )
                addr = variable_addr - self.metadata.base_addr

                # Now iterate over the entries.
                while True:
                    guc = self._load_one_gucdef(addr, deftype, programbin)
                    if guc is None:
                        break
                    self.guc_defs[guc.guc_name] = guc
                    addr += typsize

    def set_guc(self, guc_name: str, guc_value: str) -> None:
        """
        Send a request to set a GUC to a specific value.
        """
        guc_def = self.guc_defs[guc_name]
        guc_c_value: Optional[bytes] = None
        if guc_def.guc_type != "int":
            raise NotImplementedError("We only support ints for now.")
        guc_c_value = struct.pack("i", int(guc_value))
        guc_ct_value: ct._CData = ct.create_string_buffer(guc_c_value, GUC_MAX_LENGTH)
        guc_ct_value = ct.cast(
            guc_ct_value, ct.POINTER(ct.c_byte * GUC_MAX_LENGTH)
        ).contents
        guc_req = guc_request(
            ct.c_ulonglong(guc_def.guc_location), guc_size=4, payload=guc_ct_value
        )
        self.pending_guc_sets[guc_def.guc_location] = guc_def, guc_value
        self.bpf[b"gucs_to_set"].push(guc_req)

    def setup_bpf_state(self) -> None:
        super().setup_bpf_state()
        # Build a mapping of GUC names to variables addresses
        self._load_guc_defs_from_binary()

    @property
    def constant_defines(self) -> Dict[str, int]:
        constants = super().constant_defines
        constants["GUC_MAX_LENGTH"] = GUC_MAX_LENGTH
        return constants

    def attach_probes(self) -> None:
        super().attach_probes()
        # Attach at various not-too-intrusive points.
        self._attach_uretprobe("BeginCommand", "process_guc_uprobe")
        self._attach_uretprobe("printtup", "process_guc_uprobe")

        self._attach_uretprobe("launcher_determine_sleep", "process_guc_uprobe")
        self._attach_uretprobe("vacuum_delay_point", "process_guc_uprobe")

    def _optional_code(self) -> str:
        buf = super()._optional_code()
        buf += load_c_file("gucset.c")
        return buf
