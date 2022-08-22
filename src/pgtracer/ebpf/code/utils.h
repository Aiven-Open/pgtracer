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
	bpf_probe_read_user(&sourceText,
						sizeof(void *),
						OffsetFrom(queryDesc, QueryDesc, sourceText));
	bpf_probe_read_user_str(&event->query,
							MAX_QUERY_LENGTH,
							(void *) sourceText);
	bpf_probe_read_user(&planstate,
						sizeof(void *),
						OffsetFrom(queryDesc, QueryDesc, planstate));
	if (planstate)
	{
		bpf_probe_read_user(&instrument,
							sizeof(void *),
							OffsetFrom(planstate, PlanState, instrument));
		if (instrument)
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
