#include <linux/sched.h>
#include "ebpf_maps.h"
#include "data.h"
#include "utils.h"

static int override_instrument_options(void * querydesc);

int executorstart_enter(struct pt_regs *ctx)
{
	##CHECK_POSTMASTER##
	void *queryDesc = (void *) PT_REGS_PARM1(ctx);
#ifdef USER_INSTRUMENT_FLAGS
	override_instrument_options(queryDesc);
#endif
	return 0;
}

int executorrun_enter(struct pt_regs *ctx)
{
	u64 ppid; 
	##CHECK_POSTMASTER##
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
	fill_event_base(&(event->event_base), EventTypeExecutorRun);
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
	##CHECK_POSTMASTER##
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
	fill_event_base(&(event->event_base), EventTypeExecutorFinish);
	event->portal_key = key;
	event_ring.ringbuf_submit(event, 0);
	return 0;
}

int portaldrop_return(struct pt_regs *ctx)
{
	##CHECK_POSTMASTER##
	struct portal_data_t *event;
	Id128 key = {0};
	event = event_ring.ringbuf_reserve(sizeof(struct portal_data_t));
	if (!event)
		return 1;
	init_portal_data(event);
	fill_event_base(&(event->event_base), EventTypeDropPortalReturn);
	event->portal_key = key;
	event_ring.ringbuf_submit(event, 0);
	return 0;
}

int portaldrop_enter(struct pt_regs *ctx)
{
	##CHECK_POSTMASTER##
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
	fill_event_base(&(event->event_base), EventTypeDropPortalEnter);
	event->portal_key = key;
	event_ring.ringbuf_submit(event, 0);
	return 0;
}

/* When instrumenting a whole cluster, we also trace new processes.
 * Additionally, specific collectors can embed code in here.
 */
#ifdef POSTMASTER_PID
TRACEPOINT_PROBE(sched, sched_process_fork)
{
	u32 pid = args->parent_pid;
	if (args->parent_pid != POSTMASTER_PID)
		return 0;
	struct event_base *event;
	event = event_ring.ringbuf_reserve(sizeof (struct event_base));
	if (!event)
		return 1;
	event->pid = args->child_pid;
	event->event_type = EventTypeProcessFork;
	event_ring.ringbuf_submit(event, 0);
	return 0;
}
#endif

TRACEPOINT_PROBE(sched, sched_process_exit)
{
	##CHECK_POSTMASTER##
#ifdef PID
	if (bpf_get_current_pid_tgid() >> 32 != PID)
		return 1;
#endif
	struct event_base *event;
	event = event_ring.ringbuf_reserve(sizeof (struct event_base));
	if (!event)
		return 1;
	fill_event_base(event, EventTypeProcessExit);
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
