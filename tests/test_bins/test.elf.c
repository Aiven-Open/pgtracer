typedef struct StructA {
	int a_int;
	float a_float;
	char* a_charp;
} StructA;

typedef struct StructB {
	StructA b_structa;
	StructA* b_structap;
	struct StructB* b_structbp;
} StructB;

StructA GLOBAL_STRUCT_A = {1, 1.0, "TEST"};

StructB GLOBAL_STRUCT_B = {0};
