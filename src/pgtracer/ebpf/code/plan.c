#include "data.h"
#include "utils.h"
#include "stack.h"

int execprocnodefirst_enter(struct pt_regs *ctx);
int execendnode_enter(struct pt_regs *ctx);

struct plan_data_t {
	u64 plan_addr;
	int plan_tag;
	double startup_cost;
	double total_cost;
	double plan_rows;
	int plan_width;
	bool parallel_aware;
};

struct planstate_data_t {
	short event_type;
	struct portal_key_t portal_key;
	u64 planstate_addr;
	int planstate_tag;
	struct plan_data_t plan_data;
	char instrument[STRUCT_SIZE_Instrumentation]; // Dynamically injected using defines
	struct stack_data_t stack_capture;
};


/*
 * Record information about a PlanStateNode
 */
static inline void record_node(void * nodeaddr, struct planstate_data_t *node,
							   struct pt_regs *ctx)
{
	void *portal;
	void *instrument;
	void *planaddr;
	bpf_probe_read_user(&portal,
						sizeof(void*),
						(void *) GlobalVariablesActivePortal);
	node->portal_key = get_portal_key(portal);
	node->planstate_addr = (u64) nodeaddr;
	capture_stack(ctx, &node->stack_capture, MAX_STACK_READ);

	/* Read the associated Plan node, and it's estimates */
	bpf_probe_read_user(&planaddr,
						sizeof(void *),
						OffsetFrom(nodeaddr, PlanState, plan));
	node->plan_data.plan_addr = (u64) planaddr;
	bpf_probe_read_user(&node->plan_data.plan_tag,
						sizeof(int),
						OffsetFrom(planaddr, Plan, type));
	bpf_probe_read_user(&node->plan_data.startup_cost,
						sizeof(double),
						OffsetFrom(planaddr, Plan, startup_cost));
	bpf_probe_read_user(&node->plan_data.total_cost,
						sizeof(double),
						OffsetFrom(planaddr, Plan, total_cost));
	bpf_probe_read_user(&node->plan_data.plan_rows,
						sizeof(double),
						OffsetFrom(planaddr, Plan, plan_rows));
	bpf_probe_read_user(&node->plan_data.plan_width,
						sizeof(int),
						OffsetFrom(planaddr, Plan, plan_width));
	bpf_probe_read_user(&node->plan_data.parallel_aware,
						sizeof(bool),
						OffsetFrom(planaddr, Plan, parallel_aware));
	/* Read the PlanState node data */
	bpf_probe_read_user(&node->planstate_tag,
						sizeof(int),
						OffsetFrom(nodeaddr, PlanState, type));
	bpf_probe_read_user(&instrument,
						sizeof(void *),
						OffsetFrom(nodeaddr, PlanState, instrument));
	if (instrument)
	{
		bpf_probe_read_user(&node->instrument,
							STRUCT_SIZE_Instrumentation,
							instrument);
	}
}


/* 
 * On each first execution of a node, send the node information to the client
 * side
 */
int execprocnodefirst_enter(struct pt_regs *ctx)
{
	struct planstate_data_t *node;
	node = event_ring.ringbuf_reserve(sizeof(struct planstate_data_t));
	if (!node)
		return 0;
	node->event_type = EventTypeExecProcNodeFirst;
	record_node((void *) PT_REGS_PARM1(ctx), node, ctx);
	event_ring.ringbuf_submit(node, 0);
	return 0;
}

/*
 * On each node teardown, send the node information to the client side (again)
 */
int execendnode_enter(struct pt_regs *ctx)
{
	struct planstate_data_t *node;
	node = event_ring.ringbuf_reserve(sizeof(struct planstate_data_t));
	if (!node)
		return 0;
	node->event_type = EventTypeExecEndNode;
	record_node((void *) PT_REGS_PARM1(ctx), node, ctx);
	event_ring.ringbuf_submit(node, 0);
	return 0;
}

