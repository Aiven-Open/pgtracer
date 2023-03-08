#ifndef UTILS_H
#define UTILS_H
#define EPOCH_OFFSET ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY)

#define Offset(structname, member) (STRUCT_ ## structname ## _OFFSET_ ## member)
#define OffsetFrom(pointer, structname, member) ((void *) (pointer + Offset(structname, member)))

#include "data.h"

/* Clamp a value to a max value, and make the eBPF verifier happy. */
#define clamp_umax(VAR, UMAX)						\
	asm volatile (							\
		"if %0 <= %[max] goto +1\n"				\
		"%0 = %[max]\n"						\
		: "+r"(VAR)						\
		: [max]"i"(UMAX)					\
	)


static u64 pgts_to_unixts(u64 pgts)
{
	ulong secs = (ulong) pgts / 1000000;
	uint microsecs = (uint) pgts % 1000000;
	return (secs + EPOCH_OFFSET) * 1000000 + microsecs;
}


// Handle code related to the portal information capture
static inline Id128 get_portal_key(void * portal)
{
	Id128 ret;
	u64 creation_time;
	__builtin_memset(&ret, 0, sizeof(ret));
	ret.u1 = bpf_get_current_pid_tgid();
	bpf_probe_read_user(&creation_time,
						sizeof(u64),
						OffsetFrom(portal, PortalData, creation_time));
	ret.u2 = pgts_to_unixts(creation_time);
	return ret;
}

static inline void fill_portal_data(void * queryDesc, struct portal_data_t* event)
{
	void *sourceText;
	void *planstate;
	void *instrument;
	void *plannedStmt;
	void *plan;
	int ret;
	event->queryAddr = (u64) queryDesc;
	bpf_probe_read_user(&sourceText,
						sizeof(void *),
						OffsetFrom(queryDesc, QueryDesc, sourceText));
	bpf_probe_read_user_str(&event->query,
							MAX_QUERY_LENGTH,
							(void *) sourceText);
	ret = bpf_probe_read_user(&plannedStmt,
							  sizeof(void *),
							  OffsetFrom(queryDesc, QueryDesc, plannedstmt));
	if (plannedStmt && ret == 0)
	{
		bpf_probe_read_user(&event->query_id,
							sizeof(u64),
							OffsetFrom(plannedStmt, PlannedStmt, queryId));
	}
	ret = bpf_probe_read_user(&planstate,
						sizeof(void *),
						OffsetFrom(queryDesc, QueryDesc, planstate));
	if (planstate && ret == 0)
	{
		ret = bpf_probe_read_user(&plan, sizeof(void *),
								  OffsetFrom(planstate, PlanState, plan));
		if (plan && ret == 0)
		{
			bpf_probe_read_user(&event->startup_cost,
								sizeof(double),
								OffsetFrom(plan, Plan, startup_cost));
			bpf_probe_read_user(&event->total_cost,
								sizeof(double),
								OffsetFrom(plan, Plan, total_cost));
			bpf_probe_read_user(&event->plan_rows,
								sizeof(double),
								OffsetFrom(plan, Plan, plan_rows));
		}
		ret = bpf_probe_read_user(&instrument,
							sizeof(void *),
							OffsetFrom(planstate, PlanState, instrument));
		if (instrument && ret == 0)
		{
			bpf_probe_read_user(&event->instrument,
								STRUCT_SIZE_Instrumentation,
								instrument);
		}
	}
}

static inline void init_portal_data(struct portal_data_t* event)
{
	event->event_type = 0;
	event->query[0] = 0;
	event->instrument[0] = 0;
	event->search_path[0] = 0;
}

/*
 * Record information about a PlanStateNode
 */
static inline void record_node(void * nodeaddr, struct planstate_data_t *node,
							   struct pt_regs *ctx, bool need_capture_stack)
{
	void *portal;
	void *instrument;
	void *planaddr;
	bpf_probe_read_user(&portal,
						sizeof(void*),
						(void *) GlobalVariablesActivePortal);
	node->portal_key = get_portal_key(portal);
	node->planstate_addr = (u64) nodeaddr;
	if (need_capture_stack)
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
	bpf_probe_read_user(&node->lefttree,
						sizeof(void *),
						OffsetFrom(nodeaddr, PlanState, lefttree));
	bpf_probe_read_user(&node->righttree,
						sizeof(void *),
						OffsetFrom(nodeaddr, PlanState, righttree));
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
#endif
