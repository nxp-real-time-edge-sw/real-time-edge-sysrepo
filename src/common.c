/**
 * @file common.c
 * @author Xiaolin He
 * @brief common functions for the project.
 *
 * Copyright 2019-2020, 2025 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define PLG_NAME    "common"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <errno.h>

#include "common.h"

static pthread_mutex_t tsn_mutex;

void init_tsn_mutex(void)
{
	pthread_mutex_init(&tsn_mutex, NULL);
}

void destroy_tsn_mutex(void)
{
	pthread_mutex_destroy(&tsn_mutex);
}

void init_tsn_socket(void)
{
	pthread_mutex_lock(&tsn_mutex);
	genl_tsn_init();
}

void close_tsn_socket(void)
{
	genl_tsn_close();
	pthread_mutex_unlock(&tsn_mutex);
}

inline uint64_t cal_base_time(struct base_time_s *basetime)
{
	return ((basetime->seconds * 1000000000) + basetime->nanoseconds);
}

inline uint64_t cal_cycle_time(struct cycle_time_s *cycletime)
{
	return ((cycletime->numerator * 1000000000) / cycletime->denominator);
}

int errno2sp(int errtsn)
{
	int errsp = 0;

	switch (errtsn) {
	case SR_ERR_OK:
		break;
	case EINVAL:
		errsp = SR_ERR_INVAL_ARG;
		break;
	case ENOMEM:
		errsp = SR_ERR_NO_MEMORY;
		break;
	default:
		errsp = SR_ERR_INVAL_ARG;
		break;
	}

	return errsp;
}

void pri2num(char *pri_str, int8_t *pri_num)
{
	if (!pri_str || !pri_num)
		return;

	if (!strcmp(pri_str, "zero"))
		*pri_num = 0;
	else if (!strcmp(pri_str, "one"))
		*pri_num = 1;
	else if (!strcmp(pri_str, "two"))
		*pri_num = 2;
	else if (!strcmp(pri_str, "three"))
		*pri_num = 3;
	else if (!strcmp(pri_str, "four"))
		*pri_num = 4;
	else if (!strcmp(pri_str, "five"))
		*pri_num = 5;
	else if (!strcmp(pri_str, "six"))
		*pri_num = 6;
	else if (!strcmp(pri_str, "seven"))
		*pri_num = 7;
	else if (!strcmp(pri_str, "null"))
		*pri_num = -1;
	else
		*pri_num = -1;
}

bool is_del_oper(sr_session_ctx_t *session, char *path)
{
	int rc = SR_ERR_OK;
	bool ret = false;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_change_iter_t *it;

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		printf("ERROR: Get changes from %s failed\n", path);
		return false;
	}

	rc = sr_get_change_next(session, it, &oper, &old_value, &new_value);
	if (rc == SR_ERR_NOT_FOUND)
		ret = false;
	else if (oper == SR_OP_DELETED)
		ret = true;

	sr_free_val(old_value);
	sr_free_val(new_value);

    sr_free_change_iter(it);
	return ret;
}

static char shost_name[64];
char *get_host_name(void)
{
	int ret = 0;

	if (strlen(shost_name) == 0) {
		ret = gethostname(shost_name, sizeof(shost_name));
		if (ret)
			return NULL;
	}

	return shost_name;
}

void print_node_tree_xml(const struct lyd_node *node)
{
    char *str;

    lyd_print_mem(&str, node, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    LOG_INF("node name: %s\r\n%s", LYD_NAME(node), str);
    free(str);
}

/* get interface name */
const char *get_ifname(const struct lyd_node *node)
{
    while (node && strcmp(LYD_NAME(node), "interface")) {
        node = lyd_parent(node);
    }

    if (node) {
        return lyd_get_value(lyd_child(node));
    }

    return NULL;
}
