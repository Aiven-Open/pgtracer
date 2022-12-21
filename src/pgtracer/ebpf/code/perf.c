#include "ebpf_maps.h"
#include "stack.h"
#include "uapi/linux/bpf_perf_event.h"
#include "utils.h"

struct memory_request_t {
	short event_type;
    Id128 requestId;
	int path_size;
    u64 size;
	u64 memory_path[MEMORY_PATH_SIZE];
};

struct memory_response_t {
	short event_type;
    Id128 requestId;
    char payload[MEMORY_REQUEST_MAXSIZE];
};

/* 
 * We embed the whole portal_data_t 
 */
struct stack_sample_t {
	struct portal_data_t portal_data;
	struct stack_data_t stack_data;
};

# define QUERY_DISCOVERY_KEY 1
# define NODE_DISCOVERY_KEY 2
BPF_HASH(discovery_enabled, int, bool, 2);

BPF_QUEUE(memory_requests, struct memory_request_t, 1024);

/*
 * This code is run on perf event, with a specific frequency.
 * What we want is to be able to read specific memory locations whenever the perf
 * event is triggered.
 *
 * Userland code pushes memory locations to read to the memory_requests queues,
 * and sends the responses back through the same event_ringbuffer used
 * everywhere.
 */
int perf_event(struct bpf_perf_event_data *ctx)
{
    struct memory_request_t request;
	struct memory_response_t *response;
	u64 size;
	u64 memory_location;
	int i = 0;
	int j;
#ifdef ENABLE_QUERY_DISCOVERY
	int key = QUERY_DISCOVERY_KEY;
	bool *need_discovery;
	need_discovery = discovery_enabled.lookup(&key);
	bool need_query = (need_discovery && *need_discovery);
	key = NODE_DISCOVERY_KEY;
	need_discovery = discovery_enabled.lookup(&key);
	bool need_node = (need_discovery && *need_discovery);
	if (need_query || need_node)
	{
		void *activeportal = 0;
		bpf_probe_read_user(&activeportal,
							sizeof(void*),
							(void *) GlobalVariablesActivePortal);
		/* Only proceed if we have a current query. */
		if(activeportal != 0)
		{
			struct stack_sample_t *stack_sample = event_ring.ringbuf_reserve(sizeof(struct stack_sample_t));

			/* 
			 * If we can't allocate for the stack sample, we keep going to the memory request code.
			 */
			if (stack_sample)
			{
				stack_sample->portal_data.event_type = EventTypeStackSample;
				if (need_query)
				{
					void *queryDesc = 0;
					bpf_probe_read_user(&queryDesc, sizeof(void *),
										OffsetFrom(activeportal, PortalData, queryDesc));
					fill_portal_data(queryDesc, &stack_sample->portal_data);
					stack_sample->portal_data.portal_key = get_portal_key(activeportal);
				}
				if (need_node)
				{
					capture_stack(&(ctx->regs), &(stack_sample->stack_data), MAX_STACK_READ);
				}
				event_ring.ringbuf_submit(stack_sample, 0);
			}
		}
	}
#endif
	while (i < 5)
	{

		/* No more requests to process. */
		if (memory_requests.pop(&request) < 0)
		{
			return 0;
		}
		size = request.size;
		/* We treat those specially, as we have the opportunity to gather a bunch of
		 * data at the same time.
		 */
		if (request.event_type == EventTypeMemoryNodeData)
		{
			struct planstate_data_t *response = event_ring.ringbuf_reserve(sizeof(struct planstate_data_t));
			if (!response)
				return 1;
			response->event_type = EventTypeMemoryNodeData;
			record_node((void *) request.memory_path[0], response, NULL, false);
			event_ring.ringbuf_submit(response, 0);
			i++;
			continue;
		}
		response = event_ring.ringbuf_reserve(sizeof(struct memory_response_t));
		if (!response)
			return 1;

		response->event_type = request.event_type;
		if (size >= MEMORY_REQUEST_MAXSIZE)
			size = MEMORY_REQUEST_MAXSIZE;
		/*
		 * request.path_size can't be greater than MEMORY_PATH_SIZE,
		 * but the eBPF verifier doesn't know this.
		 */
		memory_location = 0;
		j = 0;
		/* Chase pointers as needed */
		while(j < request.path_size - 1 && j < MEMORY_PATH_SIZE)
		{
			if (memory_location != 0)
			{
				if(bpf_probe_read_user(&memory_location, sizeof(u64),
													  (void *) memory_location))
				{
					/* We failed to read here, so bail out. */
					event_ring.ringbuf_discard(response, 0);
					return 0;
				}
			}
			memory_location = request.memory_path[j] + memory_location;
			j++;
		}
		if (bpf_probe_read_user(&response->payload, size, (void *) memory_location))
		{
			event_ring.ringbuf_discard(response, 0);
		} else {
			response->requestId = request.requestId;
			event_ring.ringbuf_submit(response, 0);
		}
		i++;
	}
	return 0;
}
