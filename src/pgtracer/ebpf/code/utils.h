#ifndef UTILS_H
#define UTILS_H
#define EPOCH_OFFSET ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY)

#define Offset(structname, member) (STRUCT_ ## structname ## _OFFSET_ ## member)
#define OffsetFrom(pointer, structname, member) ((void *) (pointer + Offset(structname, member)))

#include "data.h"

static u64 pgts_to_unixts(u64 pgts)
{
	ulong secs = (ulong) pgts / 1000000;
	uint microsecs = (uint) pgts % 1000000;
	return (secs + EPOCH_OFFSET) * 1000000 + microsecs;
}


// Handle code related to the portal information capture
static inline struct portal_key_t get_portal_key(void * portal)
{
	struct portal_key_t ret;
	u64 creation_time;
	__builtin_memset(&ret, 0, sizeof(ret));
	ret.pid = bpf_get_current_pid_tgid();
	ret.creation_time = 0;
	bpf_probe_read_user(&creation_time,
						sizeof(u64),
						OffsetFrom(portal, PortalData, creation_time));
	ret.creation_time = pgts_to_unixts(creation_time);
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

#endif
