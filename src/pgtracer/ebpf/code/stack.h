#ifndef STACK_H
#define STACK_H
#include <linux/sched.h>

#if defined(__x86_64__)
struct stack_data_t {
	u64 rax;
	u64 rdx;
	u64 rcx;
	u64 rbx;
	u64 rsi;
	u64 rdi;
	u64 rbp;
	u64 rsp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rip;
	u64 size;
	u64 start_addr;
	char stack[MAX_STACK_READ]; // Dynamically injected using defines
};

/*
 * Capture the current stack and register values.
 */
static inline int capture_stack(struct pt_regs *ctx, struct stack_data_t *stack_data, u64 max_read)
{
	int ret = 0;
	stack_data->rax = ctx->ax;
	stack_data->rdx = ctx->dx;
	stack_data->rcx = ctx->cx;
	stack_data->rbx = ctx->bx;
	stack_data->rsi = ctx->si;
	stack_data->rdi = ctx->di;
	stack_data->rbp = ctx->bp;
	stack_data->rsp = ctx->sp;
	stack_data->r8 = ctx->r8;
	stack_data->r9 = ctx->r9;
	stack_data->r10 = ctx->r10;
	stack_data->r11 = ctx->r11;
	stack_data->r12 = ctx->r12;
	stack_data->r13 = ctx->r13;
	stack_data->r14 = ctx->r14;
	stack_data->r15 = ctx->r15;
	stack_data->rip = ctx->ip;
	stack_data->start_addr = stack_data->rsp;
	stack_data->size = (STACK_TOP_ADDR - stack_data->rsp);
	if (stack_data->size > max_read)
		stack_data->size = max_read;
	ret = bpf_probe_read_user(&stack_data->stack,
							  stack_data->size,
							  (void *) (stack_data->rsp));
	if (ret != 0)
	{
		stack_data->size = 0;
	}
	return ret;
}
#elif defined(__aarch64__)
struct stack_data_t {
    u64 x0;
    u64 x1;
    u64 x2;
    u64 x3;
    u64 x4;
    u64 x5;
    u64 x6;
    u64 x7;
    u64 x8;
    u64 x9;
    u64 x10;
    u64 x11;
    u64 x12;
    u64 x13;
    u64 x14;
    u64 x15;
    u64 x16;
    u64 x17;
    u64 x18;
    u64 x19;
    u64 x20;
    u64 x21;
    u64 x22;
    u64 x23;
    u64 x24;
    u64 x25;
    u64 x26;
    u64 x27;
    u64 x28;
    u64 x29; // frame pointer
    u64 x30; // link register
    u64 sp; // stack pointer
    u64 pc; // program counter
    u64 size;
    u64 start_addr;
    char stack[MAX_STACK_READ]; // Dynamically injected using defines
};

/*
 * Capture the current stack and register values.
 */
static inline int capture_stack(struct pt_regs *ctx, struct stack_data_t *stack_data, u64 max_read)
{
    int ret = 0;
    stack_data->x0 = ctx->regs[0];
    stack_data->x1 = ctx->regs[1];
    stack_data->x2 = ctx->regs[2];
    stack_data->x3 = ctx->regs[3];
    stack_data->x4 = ctx->regs[4];
    stack_data->x5 = ctx->regs[5];
    stack_data->x6 = ctx->regs[6];
    stack_data->x7 = ctx->regs[7];
    stack_data->x8 = ctx->regs[8];
    stack_data->x9 = ctx->regs[9];
    stack_data->x10 = ctx->regs[10];
    stack_data->x11 = ctx->regs[11];
    stack_data->x12 = ctx->regs[12];
    stack_data->x13 = ctx->regs[13];
    stack_data->x14 = ctx->regs[14];
    stack_data->x15 = ctx->regs[15];
    stack_data->x16 = ctx->regs[16];
    stack_data->x17 = ctx->regs[17];
    stack_data->x18 = ctx->regs[18];
    stack_data->x19 = ctx->regs[19];
    stack_data->x20 = ctx->regs[20];
    stack_data->x21 = ctx->regs[21];
    stack_data->x22 = ctx->regs[22];
    stack_data->x23 = ctx->regs[23];
    stack_data->x24 = ctx->regs[24];
    stack_data->x25 = ctx->regs[25];
    stack_data->x26 = ctx->regs[26];
    stack_data->x27 = ctx->regs[27];
    stack_data->x28 = ctx->regs[28];
    stack_data->x29 = ctx->regs[29];
    stack_data->x30 = ctx->regs[30];
    stack_data->sp = ctx->sp;
    stack_data->pc = ctx->pc;
    stack_data->start_addr = stack_data->sp;
    stack_data->size = (STACK_TOP_ADDR - stack_data->sp);
    if (stack_data->size > max_read)
        stack_data->size = max_read;
    ret = bpf_probe_read_user(&stack_data->stack,
                              stack_data->size,
                              (void *) (stack_data->sp));
    if (ret != 0)
    {
        stack_data->size = 0;
    }
    return ret;
}
#endif // Arch

#endif // STACK_H
