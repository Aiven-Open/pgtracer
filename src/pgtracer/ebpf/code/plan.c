#include "data.h"
#include "utils.h"
#include "stack.h"

int execprocnodefirst_enter(struct pt_regs *ctx);
int execendnode_enter(struct pt_regs *ctx);

/* 
 * On each first execution of a node, send the node information to the client
 * side
 */
int execprocnodefirst_enter(struct pt_regs *ctx)
{
	##CHECK_POSTMASTER##
	struct planstate_data_t *node;
	node = event_ring.ringbuf_reserve(sizeof(struct planstate_data_t));
	if (!node)
		return 0;
	fill_event_base(&(node->event_base), EventTypeExecProcNodeFirst);
	record_node((void *) PT_REGS_PARM1(ctx), node, ctx, true);
	event_ring.ringbuf_submit(node, 0);
	return 0;
}

/*
 * On each node teardown, send the node information to the client side (again)
 */
int execendnode_enter(struct pt_regs *ctx)
{
	##CHECK_POSTMASTER##
	struct planstate_data_t *node;
	node = event_ring.ringbuf_reserve(sizeof(struct planstate_data_t));
	if (!node)
		return 0;
	fill_event_base(&(node->event_base), EventTypeExecEndNode);
	record_node((void *) PT_REGS_PARM1(ctx), node, ctx, true);
	event_ring.ringbuf_submit(node, 0);
	return 0;
}

