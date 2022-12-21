#include <linux/sched.h>
#include "ebpf_maps.h"
#include "data.h"
#include "utils.h"

static int override_instrument_options(void * querydesc);

int executorstart_enter(struct pt_regs *ctx)
{
	void *queryDesc = (void *) PT_REGS_PARM1(ctx);
#ifdef USER_INSTRUMENT_FLAGS
	override_instrument_options(queryDesc);
#endif
	return 0;
}

int executorrun_enter(struct pt_regs *ctx)
{
	void *queryDesc = (void *) PT_REGS_PARM1(ctx);
	void *sourceText;
	void *portaladdr;
	void *search_path;
	void *plan;

	struct portal_data_t *event;
	bpf_probe_read_user(&portaladdr,
						sizeof(void*),
						(void *) GlobalVariablesActivePortal);
	Id128 key = get_portal_key(portaladdr);
	event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
	if (!event)
		return 1;
	event->event_type = EventTypeExecutorRun;
	event->portal_key = key;
	fill_portal_data(queryDesc, event);
	bpf_probe_read_user(&search_path, sizeof(void *), (void *) GlobalVariablesnamespace_search_path);
	bpf_probe_read_user_str(&event->search_path, MAX_SEARCHPATH_LENGTH,
							search_path);
	event_ring.ringbuf_submit(event, 0);
	return 0;
}

int executorfinish_enter(struct pt_regs *ctx)
{
	void *portal;
	void *queryDesc = (void *) PT_REGS_PARM1(ctx);
	struct portal_data_t *event;
	Id128 key;
	bpf_probe_read_user(&portal,
						sizeof(void*),
						(void *) GlobalVariablesActivePortal);

	key = get_portal_key((void*) portal);
	event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
	if (!event)
		return 1;
	init_portal_data(event);
	fill_portal_data(queryDesc, event);
	event->event_type = EventTypeExecutorFinish;
	event->portal_key = key;
	event_ring.ringbuf_submit(event, 0);
	return 0;
}

int portaldrop_return(struct pt_regs *ctx)
{
	struct portal_data_t *event;
	Id128 key = {0};
	event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
	if (!event)
		return 1;
	init_portal_data(event);
	event->event_type = EventTypeDropPortalReturn;
	event->portal_key = key;
	event_ring.ringbuf_submit(event, 0);
	return 0;
}

int portaldrop_enter(struct pt_regs *ctx)
{
	void *portal =  (void *) PT_REGS_PARM1(ctx);
	Id128 key = get_portal_key(portal);
	struct portal_data_t *event;
	void *queryDesc;
	event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
	if (!event)
		return 1;
	init_portal_data(event);
	bpf_probe_read_user(&queryDesc, sizeof(void *),
						OffsetFrom(portal, PortalData, queryDesc));
	fill_portal_data(queryDesc, event);
	event->event_type = EventTypeDropPortalEnter;
	event->portal_key = key;
	event_ring.ringbuf_submit(event, 0);
	return 0;
}

#ifdef USER_INSTRUMENT_FLAGS
static int override_instrument_options(void * querydesc)
{
	void * options_addr = OffsetFrom(querydesc, QueryDesc, instrument_options);
	int instr_options;
	bpf_probe_read_user(&instr_options,
						sizeof(int),
						options_addr);
	instr_options |= USER_INSTRUMENT_FLAGS;
	return bpf_probe_write_user(options_addr, &instr_options, sizeof(int));
}
#endif

#ifdef CAPTURE_PLANS
#include "plan.h"
#endif
