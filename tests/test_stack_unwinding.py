"""
This module tests the frame unwinding code.
"""
import ctypes as ct
import subprocess
from pathlib import Path
from unittest import TestCase

from bcc import BPF
from bcc.libbcc import lib as libbcc
from pypsutil import Process

from pgtracer.ebpf.collector import CODE_BASE_PATH
from pgtracer.ebpf.dwarf import ProcessMetadata, die_name
from pgtracer.ebpf.unwind import MAX_STACK_READ, UnwindAddressSpace, stack_data_t

TEST_EBPF_PROGRAM = """
/*
 * Fill in placeholders for generated defines
 */
#define EVENTRING_PAGE_SIZE 1024
#include "ebpf_maps.h"
#include "stack.h"

int capture_stack_enter(struct pt_regs *ctx)
{
    struct stack_data_t* stack_data = event_ring.ringbuf_reserve(sizeof(struct
    stack_data_t));
    int i = 0, ret = 0;
    u64 maxread = MAX_STACK_READ;
    if (!stack_data)
        return -1;
    while(stack_data && i < 10)
    {
        ret = capture_stack(ctx, stack_data, maxread);
        i++;
        maxread = maxread / 2;
    }
    event_ring.ringbuf_submit(stack_data, 0);
}
"""


class TestStackUnwinding(TestCase):
    def setUp(self):
        self.captured_data = []

    def tearDown(self):
        for k, v in list(self.ebpf.uprobe_fds.items()):
            self.ebpf.detach_uprobe_event(k)

    def _capture_data(self, cpu, data, size):
        content = stack_data_t()
        ct.pointer(content)[0] = ct.cast(data, ct.POINTER(stack_data_t)).contents
        self.captured_data.append(content)

    def test_simple_call_stack(self):
        # Load an eBPF program which will capture stacks.
        binpath = Path(__file__).parent / "test_bins" / "test_stack.main"

        # Run the program.
        program = subprocess.Popen([binpath], stdin=subprocess.PIPE)
        # Now get the stack base address for the program.
        pm = ProcessMetadata(Process(program.pid))
        bpf_prog = f"#define STACK_TOP_ADDR {pm.stack_top}\n"
        bpf_prog += f"#define MAX_STACK_READ {MAX_STACK_READ}\n"
        bpf_prog += TEST_EBPF_PROGRAM

        self.ebpf = BPF(
            text=bpf_prog.encode("utf8"),
            cflags=[f"-I{CODE_BASE_PATH}"],
        )
        self.ebpf.attach_uprobe(
            name=str(binpath).encode("utf8"),
            fn_name=b"capture_stack_enter",
            sym=b"func_1",
        )
        self.ebpf.attach_uprobe(
            name=str(binpath).encode("utf8"),
            fn_name=b"capture_stack_enter",
            sym=b"func_2",
        )
        self.ebpf[b"event_ring"].open_ring_buffer(self._capture_data)
        # Ok, now everything is ready for the program to actually run.
        program.communicate(input=b"C")
        # Now that the ebpf program has been loaded, run the executable and
        # check the output.
        self.ebpf.ring_buffer_poll()
        assert len(self.captured_data) == 2

        # First stack should be:
        # (???) libc
        #   main
        #    func_2
        adress_space = UnwindAddressSpace(self.captured_data[0], pm)
        frames = list(adress_space.frames())
        assert len(frames) == 3
        assert frames[0].region.path == str(binpath)
        assert die_name(frames[0].die) == "func_2"
        assert frames[1].region.path == str(binpath)
        assert die_name(frames[1].die) == "main"
        libname = Path(frames[2].region.path)
        # Remove all suffixes
        while libname.suffix != ".so":
            libname = libname.with_suffix("")
        assert libname.name == "libc.so"
        assert frames[2].die is None

        # Second stack should be:
        # (???) libc
        #   main
        #    func_2
        #      func_1
        adress_space = UnwindAddressSpace(self.captured_data[1], pm)
        frames = list(adress_space.frames())
        assert len(frames) == 4
        assert frames[0].region.path == str(binpath)
        assert die_name(frames[0].die) == "func_1"
        assert frames[1].region.path == str(binpath)
        assert die_name(frames[1].die) == "func_2"
        assert frames[2].region.path == str(binpath)
        assert die_name(frames[2].die) == "main"
        libname = Path(frames[3].region.path)
        # Remove all suffixes
        while libname.suffix != ".so":
            libname = libname.with_suffix("")
        assert libname.name == "libc.so"
        assert frames[3].die is None

        # Check the argument values
        assert frames[0].fetch_arg(1, ct.c_int).value == 11
        assert frames[0].fetch_arg(2, ct.c_int).value == 22
        assert frames[1].fetch_arg(1, ct.c_int).value == 10
        assert frames[1].fetch_arg(2, ct.c_int).value == 20
