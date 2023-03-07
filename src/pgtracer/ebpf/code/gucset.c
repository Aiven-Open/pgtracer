#include "ebpf_maps.h"

struct guc_request_t {
	u64 guc_location;
	int guc_size;
	char payload[GUC_MAX_LENGTH];
};

struct guc_response_t {
	short event_type;
	u64 guc_location;
	bool status;
};

BPF_QUEUE(gucs_to_set, struct guc_request_t, 128);

/* This will be attached at various points in the program flow,
 * to override GUCs as seen fit.
 * */
int process_guc_uprobe(struct pt_regs *ctx)
{
	struct guc_request_t guc_request;
	struct guc_response_t *guc_response;
	int i = 0;
	int size = 0;
	int ret;
	while (i < 20)
	{
		guc_response = event_ring.ringbuf_reserve(sizeof(struct guc_response_t));
		if (!guc_response)
			return 1;
		guc_response->event_type = EventTypeGUCResponse;

		/* If no resquest to process, bail out */
		if (gucs_to_set.pop(&guc_request) < 0)
		{
			event_ring.ringbuf_discard(guc_response, 0);
			return 1;
		}
		guc_response->guc_location = guc_request.guc_location;
		size = 1;
		if (guc_request.guc_size > 0)
			size = guc_request.guc_size;
		if (size <= 0 || size >= GUC_MAX_LENGTH || guc_request.guc_size <= 0)
		{
			guc_response->status = false;
			event_ring.ringbuf_submit(guc_response, 0);
			i++;
			continue;
		}
		int * payload = (int *) &(guc_request.payload);
		/*
		 * This code is unreachable, but it makes the ebpf verifier happy
		 */
		if ( size >= GUC_MAX_LENGTH)
		{
			size = GUC_MAX_LENGTH;
		}
		ret = bpf_probe_write_user((void *) guc_request.guc_location, &(guc_request.payload), size);
		guc_response->status = (ret >= 0);
		event_ring.ringbuf_submit(guc_response, 0);
		i++;
	}
	return 0;
}
