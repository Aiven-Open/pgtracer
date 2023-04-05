#ifndef EBPF_MAPS_H
#define EBPF_MAPS_H
/* Main ringbuf for communicating events to user space. */
BPF_RINGBUF_OUTPUT(event_ring, EVENTRING_PAGE_SIZE);

#endif
