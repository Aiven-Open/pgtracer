#ifndef DATA_H
#define DATA_H
#include "stack.h"


typedef struct Id128 {
	u64 u1;
	u64 u2;
} Id128;

struct portal_data_t {
	short event_type;
	Id128 portal_key;
	u64 queryAddr;
	u64 query_id;
	double startup_cost;
	double total_cost;
	double plan_rows;
	char query[MAX_QUERY_LENGTH]; // Dynamically injected using defines
	char instrument[STRUCT_SIZE_Instrumentation]; // Dynamically injected using defines
	char search_path[MAX_SEARCHPATH_LENGTH];
};

struct plan_data_t {
	u64 plan_addr;
	int plan_tag;
	double startup_cost;
	double total_cost;
	double plan_rows;
	int plan_width;
	bool parallel_aware;
};

struct planstate_data_t {
	short event_type;
	Id128 portal_key;
	u64 planstate_addr;
	int planstate_tag;
	u64 lefttree;
	u64 righttree;
	struct plan_data_t plan_data;
	char instrument[STRUCT_SIZE_Instrumentation]; // Dynamically injected using defines
	struct stack_data_t stack_capture;
};

#endif
