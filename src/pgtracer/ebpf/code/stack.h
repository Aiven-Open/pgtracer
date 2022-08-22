#ifndef STACK_H
#define STACK_H
#include <linux/sched.h>

struct stack_data_t {
    short event_type;
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

static inline void capture_stack(struct pt_regs *ctx, struct stack_data_t *stack_data)
{
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
    if (stack_data->size > MAX_STACK_READ)
        stack_data->size = MAX_STACK_READ;
    if(!bpf_probe_read_user(&stack_data->stack,
							stack_data->size,
							(void *) (stack_data->rsp)))
        stack_data->size = 0;
    return;
}

#endif
