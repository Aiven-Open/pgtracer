#ifndef DATA_H
#define DATA_H

struct portal_key_t {
	u64 pid;
	u64 creation_time;
};

struct portal_data_t {
	short event_type;
	struct portal_key_t portal_key;
	u64  queryAddr;
	u64 query_id;
	double startup_cost;
	double total_cost;
	double plan_rows;
	char query[MAX_QUERY_LENGTH]; // Dynamically injected using defines
	char instrument[STRUCT_SIZE_Instrumentation]; // Dynamically injected using defines
	char search_path[MAX_SEARCHPATH_LENGTH];
};

#endif
