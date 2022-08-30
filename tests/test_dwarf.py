"""
This module tests some utilities from the dwarf module.
"""

import ctypes as ct
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from pgtracer.ebpf.dwarf import ProcessMetadata, Struct, StructMemberDefinition
from pgtracer.ebpf.eh_frame_hdr import EhFrameHdr

TEST_BINARY = Path(__file__).parent / "test_bins" / "test.elf"
TEST_EXEC_BINARY = Path(__file__).parent / "test_bins" / "test_stack.main"


class MockProcess:
    """
    Mock a psutil.Process.
    """

    def __init__(self, binary):
        self.binary = binary

    def exe(self):
        """
        Returns a constant binary string.
        """
        return self.binary

    @property
    def pid(self):
        """
        Returns self pid. We only need an existing pid...
        """
        return os.getpid()


class TestProcessMetadata(TestCase):
    """
    Test the dwarf helpers in ProcessMetadata.
    """

    @patch("pgtracer.ebpf.dwarf.get_mapped_regions", lambda process, root: [])
    def setUp(self):
        self.process_meta = ProcessMetadata(MockProcess(TEST_BINARY))
        self.exec_process_meta = ProcessMetadata(MockProcess(TEST_EXEC_BINARY))

    def test_struct(self):
        """
        Test the struct parsing helper.
        """
        structs = self.process_meta.structs

        StructA = structs.StructA  # pylint: disable=invalid-name
        self.assertTrue(issubclass(StructA, Struct))
        self.assertEqual(StructA.size(), 16)

        a_int = StructA.field_definition("a_int")
        self.assertIsInstance(a_int, StructMemberDefinition)
        self.assertEqual(a_int.offset, 0)
        self.assertEqual(a_int.member_type, ct.c_int)

        a_float = StructA.field_definition("a_float")
        self.assertEqual(a_float.offset, 4)
        self.assertEqual(a_float.member_type, ct.c_float)

        a_charp = StructA.field_definition("a_charp")
        self.assertEqual(a_charp.offset, 8)
        self.assertEqual(a_charp.member_type, ct.c_void_p)

        StructB = structs.StructB  # pylint: disable=invalid-name

        b_structa = StructB.field_definition("b_structa")
        self.assertEqual(b_structa.offset, 0)
        self.assertEqual(b_structa.member_type, StructA)

        b_structap = StructB.field_definition("b_structap")
        self.assertEqual(b_structap.offset, StructA.size())
        self.assertEqual(b_structap.member_type, ct.c_void_p)

        b_structbp = StructB.field_definition("b_structbp")
        self.assertEqual(b_structbp.offset, StructA.size() + 8)
        self.assertEqual(b_structbp.member_type, ct.c_void_p)

    def test_eh_frame_hdr(self):
        """
        The the eh_frame_hdr parser.
        """
        eh_frame_hdr = EhFrameHdr.load_eh_frame_hdr(self.exec_process_meta.elffile)
        all_entries = list(eh_frame_hdr.iter_entries())
        assert len(all_entries) == 5
        assert eh_frame_hdr.fde_count == 5
        assert eh_frame_hdr.find_fde(0) == None
        assert eh_frame_hdr.find_fde(0xFFFFFFFFF) == None
        assert eh_frame_hdr.find_fde(4412).header.initial_location == 4409

    def test_die_contains_addr(self):
        dw = self.exec_process_meta.dwarf_info
        all_cus = list(dw.iter_CUs())
        # CU at index 3 as a DW_AT_ranges attribute
        cu = all_cus[3]
        die = cu.get_top_DIE()
        assert self.exec_process_meta.die_contains_addr(die, 4096)
        assert self.exec_process_meta.die_contains_addr(die, 4100)
        assert not self.exec_process_meta.die_contains_addr(die, 4095)
        assert not self.exec_process_meta.die_contains_addr(die, 4118)
