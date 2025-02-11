/**
 * @file common.c
 * @author Xiaolin He
 * @brief common functions for the project.
 *
 * Copyright 2019-2020 NXP
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <errno.h>
#include <stdarg.h>

#include "common.h"

static pthread_mutex_t tsn_mutex;
static int output_log_level = LOG_LEVEL_WRN;

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
void print_change(sr_change_oper_t oper, sr_val_t *val_old,
		sr_val_t *val_new)
{
	switch (oper) {
	case SR_OP_CREATED:
		if (val_new) {
			printf("\n created new value: ");
			sr_print_val(val_new);
		}
		break;
	case SR_OP_DELETED:
		if (val_old) {
			printf("\n deleted old value: ");
			sr_print_val(val_old);
		}
		break;
	case SR_OP_MODIFIED:
		if (val_old && val_new) {
			printf("\n modified:\nold value ");
			sr_print_val(val_old);
			printf("new value ");
			sr_print_val(val_new);
		}
		break;
	case SR_OP_MOVED:
		if (val_new) {
			printf("\n moved: %s after %s", val_new->xpath,
			       val_old ? val_old->xpath : NULL);
		}
		break;
	}
}

void print_subtree_changes(sr_session_ctx_t *session, const char *xpath)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it = NULL;
	sr_change_oper_t oper;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;

	rc = sr_get_changes_iter(session, xpath, &it);
	if (rc != SR_ERR_OK) {
		printf("Get changes iter failed for xpath %s", xpath);
		return;
	}

	printf("\n ========== START OF CHANGES ==================\n");
	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		print_change(oper, old_value, new_value);
		sr_free_val(old_value);
		sr_free_val(new_value);
	}
	printf("\n ========== END OF CHANGES ==================\n");
}

void print_config_iter(sr_session_ctx_t *session, const char *path)
{
	sr_val_t *values = NULL;
	size_t count = 0;
	int rc = SR_ERR_OK;

	if (!path || !session)
		return;

	rc = sr_get_items(session, path, 0, 0, &values, &count);
	if (rc != SR_ERR_OK) {
		printf("Error by sr_get_items: %s", sr_strerror(rc));
		return;
	}
	for (size_t i = 0; i < count; i++)
		sr_print_val(&values[i]);

	sr_free_values(values, count);
}

int str_to_num(int type, char *str, uint64_t *num)
{
	char *char_ptr;
	char ch;
	int len;
	int base = 0;
	int i;

	char_ptr = str;
	len = strlen(str);
	if ((strncmp(str, "0x", 2) == 0) || (strncmp(str, "0X", 2) == 0)) {
		char_ptr += 2;
		for (i = 2; i < len; i++) {
			ch = *char_ptr;
			if ((ch < '0') || ((ch > '9') && (ch < 'A')) ||
			    ((ch > 'F') && (ch < 'a')) || (ch > 'f'))
				goto err;

			char_ptr++;
		}
		base = 16;
		goto convert;
	}

	char_ptr = str;
	char_ptr += len - 1;
	ch = *char_ptr;
	if ((ch == 'b') || (ch == 'B')) {
		char_ptr = str;
		for (i = 0; i < len - 1; i++) {
			ch = *char_ptr;
			if ((ch < '0') || (ch > '1'))
				goto err;

			char_ptr++;
		}
		base = 2;
		goto convert;
	}

	char_ptr = str;
	if (*char_ptr == '0') {
		char_ptr++;
		for (i = 1; i < len; i++) {
			ch = *char_ptr;
			if ((ch < '0') || (ch > '7'))
				goto err;

			char_ptr++;
		}
		base = 8;
		goto convert;
	}

	char_ptr = str;
	for (i = 0; i < len; i++) {
		ch = *char_ptr;
		if ((ch < '0') || (ch > '9'))
			goto err;

		char_ptr++;
	}
	base = 10;

convert:
	errno = 0;
	*num = strtoul(str, NULL, base);
	if (errno == ERANGE)
		goto err;
	// check type limit
	switch (type) {
	case NUM_TYPE_S8:
		if ((*num < -127) || (*num > 127))
			goto err;
		break;
	case NUM_TYPE_U8:
		if (*num > 255)
			goto err;
		break;
	case NUM_TYPE_S16:
		if ((*num < -32767) || (*num > 32767))
			goto err;
		break;
	case NUM_TYPE_U16:
		if (*num > 65535)
			goto err;
		break;
	case NUM_TYPE_S32:
		if ((*num < -2147483647) || (*num > 2147483647))
			goto err;
		break;
	case NUM_TYPE_U32:
		if (*num > 4294967295)
			goto err;
		break;
	case NUM_TYPE_S64:
		if ((*num < -9223372036854775807) ||
		    (*num > 9223372036854775807))
			goto err;
		break;
	case NUM_TYPE_U64:
		if (*num > 0xFFFFFFFFFFFFFFFF)
			goto err;
		break;
	default:
		goto err;
	}
	return SR_ERR_OK;
err:
	return SR_ERR_INVAL_ARG;
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

void log_set_output_level(log_level_t level)
{
    output_log_level = level;
}

void log_output(log_level_t level, const char *format, ...)
{
    va_list ap;
    char *msg = NULL;
    size_t size = 0;
    int len = 0;
    char *flag[] = {"ERR", "WRN", "INF", "DBG"};

    /* Determine the required buffer size */
    va_start(ap, format);
    len = vsnprintf(msg, size, format, ap);
    va_end(ap);

    if (len < 0) {
        return;
    }

    size = (size_t)len + 1;
    msg = malloc(size);
    if (msg == NULL) {
        return;
    }

    va_start(ap, format);
    len = vsnprintf(msg, size, format, ap);
    va_end(ap);
    
    if (len < 0) {
        free(msg);
        return;
    }

    if (level <= output_log_level) {
        fprintf(stderr, "[%s] %s\r\n", flag[(int)level], msg);
    }

    free(msg);
    return;
}

void print_node_tree_xml(const struct lyd_node *node)
{
    char *str;

    lyd_print_mem(&str, node, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    LOG_DBG("node name: %s\r\n%s", LYD_NAME(node), str);
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
