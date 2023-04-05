#include "ebpf_maps.h"
#include "stack.h"
#include "linux/sched.h"
#include "utils.h"
#include "data.h"

#define offsetof(type, member)  __builtin_offsetof (type, member)


struct memory_account_t {
	event_base event_base;
	long long size;
	short kind;
};


static inline int send_memory_account(long long size, short kind)
{
	struct memory_account_t *account = event_ring.ringbuf_reserve(sizeof(struct memory_account_t));
	if (!account)
		return 1;
	fill_event_base(&(account->event_base), EventTypeMemoryAccount);
	account->size = size;
	account->kind = kind;
	event_ring.ringbuf_submit(account, 0);
	return 0;
}

/*
 * sbrk moves are instrumented through the convenient tracepoints.
 */
int sbrk_more(struct pt_regs *ctx)
{
    ##CHECK_POSTMASTER##
	size_t size;
	bpf_usdt_readarg(2, ctx, &size);
	return send_memory_account(size, MemoryAllocTypeSbrk);
}

int sbrk_less(struct pt_regs *ctx)
{
    ##CHECK_POSTMASTER##
	size_t size;
	bpf_usdt_readarg(2, ctx, &size);
	return send_memory_account(-size, MemoryAllocTypeSbrk);
}

/* 
 * glibc doesn't offer tracepoints for mmap, so instrument the functions directly.
 */

int mmap_enter(struct pt_regs *ctx)
{
	##CHECK_POSTMASTER##
	size_t size = PT_REGS_PARM2(ctx);
	return send_memory_account(size, MemoryAllocTypeMmap);
}

int munmap_enter(struct pt_regs *ctx)
{
	##CHECK_POSTMASTER##
	size_t size = PT_REGS_PARM2(ctx);
	return send_memory_account(-size, MemoryAllocTypeMmap);
}
