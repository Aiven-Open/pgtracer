#include <linux/sched.h>
#include "data.h"
#include "utils.h"

int executorstart_enter(struct pt_regs *ctx)
{
    void *queryDesc = (void *) PT_REGS_PARM1(ctx);
    void *sourceText;
    void *portaladdr;
	void *search_path;
    struct portal_data_t *event;
    bpf_probe_read_user(&portaladdr,
						sizeof(void*),
						(void *) GlobalVariablesActivePortal);
    struct portal_key_t key = get_portal_key(portaladdr);
    event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
    if (!event)
        return 1;
    bpf_probe_read_user(&sourceText,
						sizeof(void *),
						OffsetFrom(queryDesc, QueryDesc, sourceText));
    bpf_probe_read_user_str(&event->query, MAX_QUERY_LENGTH, sourceText);
    event->event_type = EventTypeExecutorStart;
    event->portal_key = key;

	bpf_probe_read_user(&search_path, sizeof(void *), GlobalVariablesnamespace_search_path);
	bpf_probe_read_user_str(&event->search_path, MAX_SEARCHPATH_LENGTH,
							search_path);
    event_ring.ringbuf_submit(event, 0);
    return 0;
}

int portaldrop_return(struct pt_regs *ctx)
{
    struct portal_data_t *event;
    struct portal_key_t key = {0};
    event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
    if (!event)
        return 1;

    event->event_type = EventTypeDropPortalReturn;
    event->portal_key = key;
    event_ring.ringbuf_submit(event, 0);
    return 0;
}

int portaldrop_enter(struct pt_regs *ctx)
{
    void *portal =  (void *) PT_REGS_PARM1(ctx);
    void *queryDesc;
    void *sourceText;
	void *planstate;
	void *instrument;
    struct portal_key_t key = get_portal_key((void *) portal);
    struct portal_data_t *event;
    event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
    if (!event)
        return 1;
    bpf_probe_read_user(&queryDesc,
						sizeof(void *),
						OffsetFrom(portal, PortalData, queryDesc));
    bpf_probe_read_user(&sourceText,
						sizeof(void *),
						OffsetFrom(queryDesc, QueryDesc, sourceText));
    bpf_probe_read_user_str(&event->query,
							MAX_QUERY_LENGTH,
							(void *) sourceText);
	bpf_probe_read_user(&planstate,
						sizeof(void *),
						OffsetFrom(queryDesc, QueryDesc, planstate));
	/* Read and copy queryDesc->planstate->instrument */
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
    event->event_type = EventTypeDropPortalEnter;
    event->portal_key = key;
    event_ring.ringbuf_submit(event, 0);
    return 0;
}

#ifdef USER_INSTRUMENT_OPTIONS
/*
 * If the user requested it, overwrite the querydesc instrument options with
 * the config value.
 */
int createquerydesc_ret(struct pt_regs *ctx)
{
    uint64_t querydesc = PT_REGS_RC(ctx);
	void * options_addr = OffsetFrom(querydesc, QueryDesc, instrument_options);
    int instr_options;
    bpf_probe_read_user(&instr_options,
						sizeof(int),
						options_addr);
    instr_options |= USER_INSTRUMENT_OPTIONS;
    bpf_probe_write_user(options_addr, &instr_options, sizeof(int));
	return 0;
}

#endif
