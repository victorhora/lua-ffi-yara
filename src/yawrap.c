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

int callback(int message, void* message_data, void* user_data) {
	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_RULE* rule = (YR_RULE *) message_data;
		yawrap_user_data_t* data = (yawrap_user_data_t *) user_data;

		// increment the count
		data->count++;

		// get our new match node
		yawrap_match_t* match = malloc(sizeof(yawrap_match_t));
		match->msg = strdup(rule->identifier);
		match->next = data->head;

		// add it to the list
		data->head = match;

		return data->multi_cap != 0 && data->count + 1 <= MATCH_LIMIT ?
			CALLBACK_CONTINUE :
			CALLBACK_ABORT;
	}

	return CALLBACK_CONTINUE;
}

int scan_mem_wrapper(const char* compiled_rules_path, uint8_t* buffer,
	size_t length, yawrap_user_data_t* data) {
	YR_RULES* rules;
	int result;

	result = yr_initialize();

	if (result != ERROR_SUCCESS) {
		return result;
	}

	result = yr_rules_load(compiled_rules_path, &rules);

	if (result != ERROR_SUCCESS) {
		yr_finalize();
		return result;
	}

	// compiled, do the thing!
	result = yr_rules_scan_mem(
		rules,
		buffer,
		length,
		0, // flags
		callback,
		(void *)data,
		1000000 //timeout
	);

	yr_rules_destroy(rules);
	yr_finalize();

	return result;
}

int scan_file_wrapper(const char* compiled_rules_path,
	const char* scan_file_path, yawrap_user_data_t* data) {
	YR_RULES* rules;
	int result;

	result = yr_initialize();

	if (result != ERROR_SUCCESS) {
		return -1;
	}

	result = yr_rules_load(compiled_rules_path, &rules);

	if (result != ERROR_SUCCESS) {
		yr_finalize();
		return -1;
	}

	// compiled, do the thing!
	result = yr_rules_scan_file(
		rules,
		scan_file_path,
		0, // flags
		callback,
		(void *)data,
		1000000 // timeout
	);

	yr_rules_destroy(rules);
	yr_finalize();

	return result;
}

