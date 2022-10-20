#include "ebpf_maps.h"

struct memory_request_t {
    int requestId;
	int path_size;
    u64 size;
	u64 memory_path[MEMORY_PATH_SIZE];
};

struct memory_response_t {
	short event_type;
    int requestId;
    char payload[MEMORY_REQUEST_MAXSIZE];
};


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
	while (i < 5)
	{
		response = event_ring.ringbuf_reserve(sizeof(struct memory_response_t));
		if (!response)
			return 1;
		response->event_type = EventTypeMemoryResponse;
		/* No more requests to process. */
		if (memory_requests.pop(&request) < 0)
		{
			event_ring.ringbuf_discard(response, 0);
			return 0;
		}
		size = request.size;
		if (size >= MEMORY_REQUEST_MAXSIZE)
			size = MEMORY_REQUEST_MAXSIZE;
		/*
		 * request.path_size can't be greater than MEMORY_PATH_SIZE,
		 * but the eBPF verifier doesn't know this.
		 */
		memory_location = 0;
		j = 0;
		while(j < request.path_size && j < MEMORY_PATH_SIZE)
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
