#include <linux/blkdev.h>
#include "data.h"

struct io_req_data_t {
	short	event_type;
	char	rwbs[8];
	u64		bytes;
};


TRACEPOINT_PROBE(block, block_rq_issue)
{
	struct io_req_data_t *event;
	if (bpf_get_current_pid_tgid() >> 32 != PID)
		return 1;
	event = event_ring.ringbuf_reserve(sizeof(struct io_req_data_t));
	if (!event)
		return 1;
	event->event_type = EventTypeKBlockRqIssue;
	event->bytes = args->nr_sector << 9;
    if (event->bytes == 0) {
        event->bytes = args->bytes;
    }
	bpf_probe_read(&event->rwbs, sizeof(event->rwbs), args->rwbs);
	event_ring.ringbuf_submit(event, 0);
    return 0;
}
