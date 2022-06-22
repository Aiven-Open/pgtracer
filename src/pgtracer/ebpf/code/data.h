#ifndef DATA_H
#define DATA_H

struct portal_key_t {
	u64 pid;
	u64 creation_time;
};

struct stack_data_t {
    short event_type;
    u64 rax;
    u64 rdx;
    u64 rcx;
    u64 rbx;
    u64 rsi;
    u64 rdi;
    u64 rbp;
    u64 rsp;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 rip;
    u64 size;
    u64 start_addr;
    u32 nodetag;
    u32 planstate_nodetag;
    u64 planstatenode;
    u64 instrumentaddr;
    double plan_rows;
    struct portal_key_t portal_key;
    char stack[MAX_STACK_READ]; // Dynamically injected using defines
    char instrument[STRUCT_SIZE_Instrumentation]; // Dynamically injected using defines
};

struct portal_data_t {
    short event_type;
    struct portal_key_t portal_key;
    char query[MAX_QUERY_LENGTH]; // Dynamically injected using defines
	char instrument[STRUCT_SIZE_Instrumentation]; // Dynamically injected using defines
	char search_path[MAX_SEARCHPATH_LENGTH];
};

BPF_RINGBUF_OUTPUT(event_ring, EVENTRING_PAGE_SIZE);


#endif
