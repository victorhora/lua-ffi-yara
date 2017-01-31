#include <stdio.h>
#include <stdlib.h>

#include "yara.h"

#define MATCH_LIMIT 10

typedef struct yawrap_match_s {
	char *msg;
	struct yawrap_match_s* next;
} yawrap_match_t;

typedef struct yarawrap_user_data_s {
	unsigned int count:7;
	unsigned int multi_cap:1;
	yawrap_match_t* head;
} yawrap_user_data_t;

int scan_mem_wrapper(const char* compiled_rules_path, uint8_t* buffer,
	size_t length, yawrap_user_data_t* user_data);
int scan_file_wrapper(const char* compiled_rules_path,
	const char* scan_file_path, yawrap_user_data_t* user_data);
