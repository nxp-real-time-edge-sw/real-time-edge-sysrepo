/**
 * @file qbv.c
 * @author Xiaolin He
 * @brief Application to configure TSN-QBV function based on sysrepo datastore.
 *
 * Copyright 2019-2020, 2022-2023 NXP
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
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "main.h"
#include "qbv.h"

#define TC_QDISC_DEFAULT_HANDLE		(100U)
#define MAX_SUBCMD_LEN				(64U)

struct tsn_qbv_conf *malloc_qbv_memory(void)
{
	struct tsn_qbv_conf *qbvconf_ptr;
	struct tsn_qbv_entry *qbv_entry;

	/* applying memory for qbv configuration data */
	qbvconf_ptr = malloc(sizeof(struct tsn_qbv_conf));
	if (!qbvconf_ptr)
		return NULL;

	qbv_entry = malloc(MAX_ENTRY_SIZE);
	if (!qbv_entry) {
		free(qbvconf_ptr);
		return NULL;
	}
	qbvconf_ptr->admin.control_list = qbv_entry;
	return qbvconf_ptr;
}

void init_qbv_memory(struct sr_qbv_conf *qbvconf)
{
	struct tsn_qbv_entry *qbv_entry = NULL;

	qbv_entry = qbvconf->qbvconf_ptr->admin.control_list;
	memset(qbv_entry, 0, MAX_ENTRY_SIZE);
	memset(qbvconf->qbvconf_ptr, 0, sizeof(struct tsn_qbv_conf));
	qbvconf->qbvconf_ptr->admin.control_list = qbv_entry;
	qbvconf->cycletime_f = false;
	qbvconf->basetime_f = false;
}

void free_qbv_memory(struct tsn_qbv_conf *qbvconf_ptr)
{
	free(qbvconf_ptr->admin.control_list);
	free(qbvconf_ptr);
}

static int tsn_config_del_qbv_by_tc(struct sr_qbv_conf *qbvconf, char *ifname)
{
	const char *cmd = "tc qdisc del dev %s parent root handle %d";
	char cmd_buff[MAX_CMD_LEN];
	int sysret = 0;

	if (!ifname || !qbvconf)
		return SR_ERR_INVAL_ARG;

	snprintf(cmd_buff, MAX_CMD_LEN, cmd, ifname, TC_QDISC_DEFAULT_HANDLE);

	printf("cmd: %s\n", cmd_buff);

	sysret = system(cmd_buff);
	if (!SYSCALL_OK(sysret)) {
		return SR_ERR_INVAL_ARG;
	}

	return SR_ERR_OK;
}

static int tsn_config_qbv_by_tc(sr_session_ctx_t *session, char *ifname,
		struct sr_qbv_conf *qbvconf)
{
	int i = 0;
	int count = 1;
	int offset = 0;
	pid_t sysret = 0;
	int rc = SR_ERR_OK;
	uint32_t gate_mask = 0;
	char *host_name = NULL;
	uint32_t interval = 0;
	uint64_t base_time = 0;
	uint64_t cycle_time = 0;
	int num_tc = QBV_TC_NUM;
	uint64_t cycle_time_extension = 0;
	struct tsn_qbv_entry *entry = NULL;
	struct tsn_qbv_conf *pqbv = qbvconf->qbvconf_ptr;
	char stc_cmd[MAX_CMD_LEN];
	char stc_subcmd[MAX_SUBCMD_LEN];

	if (pqbv->admin.control_list_length == 0)
		return SR_ERR_INVAL_ARG;

	host_name = get_host_name();
	if (host_name && (strcasestr(host_name, "IMX8MP") ||
	    strcasestr(host_name, "IMX8DXL") ||
	    strcasestr(host_name, "IMX93")) && !strcasestr(ifname, "swp"))
		num_tc = 5;

	base_time = pqbv->admin.base_time;
	cycle_time = pqbv->admin.cycle_time;
	cycle_time_extension = pqbv->admin.cycle_time_extension;

	snprintf(stc_cmd, MAX_CMD_LEN, "tc qdisc replace ");

	snprintf(stc_subcmd, MAX_SUBCMD_LEN, "dev %s ", ifname);
	strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));

	snprintf(stc_subcmd, MAX_SUBCMD_LEN, "parent root handle %d taprio ",
			 TC_QDISC_DEFAULT_HANDLE);
	strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));

	snprintf(stc_subcmd, MAX_SUBCMD_LEN, "num_tc %d map ", num_tc);
	strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));

	for (i = 0; i < num_tc; i++) {
		snprintf(stc_subcmd, MAX_SUBCMD_LEN, "%d ", i);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}

	snprintf(stc_subcmd, MAX_SUBCMD_LEN, "queues ");
	strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));

	for (i = 0; i < num_tc; i++) {
		offset = i;
		snprintf(stc_subcmd, MAX_SUBCMD_LEN, "%d@%d ", count, offset);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}

	if (base_time > 0) {
		snprintf(stc_subcmd, MAX_SUBCMD_LEN, "base-time %" PRIu64 " ", base_time);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}

	if (cycle_time > 0) {
		snprintf(stc_subcmd, MAX_SUBCMD_LEN, "cycle-time %" PRIu64 " ", cycle_time);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}

	if (cycle_time_extension > 0) {
		snprintf(stc_subcmd, MAX_SUBCMD_LEN, "cycle-time-extension %" PRIu64 " ", cycle_time_extension);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}

	for (i = 0; i < pqbv->admin.control_list_length; i++) {
		entry = pqbv->admin.control_list;

		gate_mask = entry[i].gate_state;
		interval = entry[i].time_interval;

		snprintf(stc_subcmd, MAX_SUBCMD_LEN, "sched-entry S %X %d ",
				gate_mask, interval);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}

	snprintf(stc_subcmd, MAX_SUBCMD_LEN, "flags 2");
	strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));

	sysret = system(stc_cmd);
	if (SYSCALL_OK(sysret)) {
		printf("ok. cmd:%s\n", stc_cmd);
	} else {
		printf("failed! ret:0x%X cmd:%s\n", sysret, stc_cmd);
		rc = SR_ERR_INVAL_ARG;
	}

	return rc;
}

int tsn_config_qbv(sr_session_ctx_t *session, char *ifname,
		struct sr_qbv_conf *qbvconf)
{
	int rc = SR_ERR_OK;
	uint64_t time;

	if (qbvconf->basetime_f) {
		time = cal_base_time(&qbvconf->basetime);
		qbvconf->qbvconf_ptr->admin.base_time = time;
	}
	if (qbvconf->cycletime_f) {
		time = cal_cycle_time(&qbvconf->cycletime);
		qbvconf->qbvconf_ptr->admin.cycle_time = time;
	}

#ifdef SYSREPO_TSN_TC
	if (qbvconf->qbv_en) {
		rc = tsn_config_qbv_by_tc(session, ifname, qbvconf);
	} else {
		rc = tsn_config_del_qbv_by_tc(qbvconf, ifname);
	}
#else
	init_tsn_socket();
	rc = tsn_qos_port_qbv_set(ifname, qbvconf->qbvconf_ptr, qbvconf->qbv_en);
	close_tsn_socket();
#endif

	if (rc != 0) {
		sr_session_set_error_message(session, "Set Qbv error: %s",
				strerror(-rc));
		printf("ERROR: set qbv error, %s!\n", strerror(-rc));
		rc = errno2sp(-rc);
		goto out;
	}
out:
	return rc;
}

void clr_qbv(sr_val_t *value, struct sr_qbv_conf *qbvconf)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *index;
	char *key_value = NULL;
	char *nodename;
	struct tsn_qbv_entry *entry;
	uint64_t u64_val = 0;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "gate-enabled")) {
		qbvconf->qbv_en = false;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		qbvconf->qbvconf_ptr->admin.gate_states = 0;
	} else if (!strcmp(nodename, "gate-states-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}
		entry = qbvconf->qbvconf_ptr->admin.control_list;
		(entry + u64_val)->gate_state = 0;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}
		entry = qbvconf->qbvconf_ptr->admin.control_list;
		(entry + u64_val)->time_interval = 0;
	} else if (!strcmp(nodename, "numerator")) {
		qbvconf->cycletime.numerator = 0;
	} else if (!strcmp(nodename, "denominator")) {
		qbvconf->cycletime.denominator = 1;
		qbvconf->cycletime_f = true;
	} else if (!strcmp(nodename,
			   "admin-cycle-time-extension")) {
		qbvconf->qbvconf_ptr->admin.cycle_time_extension = 0;
	} else if (!strcmp(nodename, "seconds")) {
		qbvconf->basetime.seconds = 0;
	} else if (!strcmp(nodename, "nanoseconds")) {
		qbvconf->basetime.nanoseconds = 0;
		qbvconf->basetime_f = true;
	} else if (!strcmp(nodename, "config-change")) {
		qbvconf->qbvconf_ptr->config_change = 0;
	} else if (!strcmp(nodename, "queue-max-sdu")) {
		sr_xpath_recover(&xp_ctx);
		key_value = sr_xpath_key_value(value->xpath,
					       "queue-max-sdu-table",
					       "traffic-class",
					       &xp_ctx);
		if (key_value != NULL && strcmp("0", key_value))
			qbvconf->qbvconf_ptr->maxsdu = 0;
	}
}

int parse_qbv(sr_session_ctx_t *session, sr_val_t *value,
		struct sr_qbv_conf *qbvconf)
{
	int valid = 0;
	sr_xpath_ctx_t xp_ctx = {0};
	char *index = NULL;
	char *key_value = NULL;
	uint8_t u8_val = 0;
	uint32_t u32_val = 0;
	uint64_t u64_val = 0;
	char *nodename = NULL;
	struct tsn_qbv_entry *entry = NULL;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	if (!strcmp(nodename, "gate-enabled")) {
		qbvconf->qbv_en = value->data.bool_val;
		if (!qbvconf->qbv_en)
			valid = 1;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		u8_val = value->data.uint8_val;
		qbvconf->qbvconf_ptr->admin.gate_states = u8_val;
	} else if (!strcmp(nodename, "gate-states-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		entry = qbvconf->qbvconf_ptr->admin.control_list;
		u8_val = value->data.uint8_val;
		(entry + u64_val)->gate_state = u8_val;
		valid = 1;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		entry = qbvconf->qbvconf_ptr->admin.control_list;
		u32_val = value->data.uint32_val;
		if (!u32_val)
			qbvconf->qbvconf_ptr->admin.control_list_length = u64_val;
		else
			qbvconf->qbvconf_ptr->admin.control_list_length = u64_val + 1;
		(entry + u64_val)->time_interval = u32_val;
		valid = 1;
	} else if (!strcmp(nodename, "numerator")) {
		qbvconf->cycletime.numerator = value->data.uint32_val;
	} else if (!strcmp(nodename, "denominator")) {
		qbvconf->cycletime.denominator = value->data.uint32_val;
		if (!qbvconf->cycletime.denominator) {
			sr_session_set_error_message(session, "The value of %s is zero",
					value->xpath);
			printf("ERROR: denominator is zero!\n");
			valid = -1;
			goto out;
		}
		qbvconf->cycletime_f = true;
	} else if (!strcmp(nodename,
			  "admin-cycle-time-extension")) {
		u32_val = value->data.uint32_val;
		qbvconf->qbvconf_ptr->admin.cycle_time_extension = u32_val;
	} else if (!strcmp(nodename, "seconds")) {
		qbvconf->basetime.seconds = value->data.uint64_val;
		qbvconf->basetime_f = true;
	} else if (!strcmp(nodename, "nanoseconds")) {
		qbvconf->basetime.nanoseconds = value->data.uint64_val;
		qbvconf->basetime_f = true;
	} else if (!strcmp(nodename, "config-change")) {
		qbvconf->qbvconf_ptr->config_change = value->data.bool_val;
	} else if (!strcmp(nodename, "queue-max-sdu")) {
		sr_xpath_recover(&xp_ctx);
		key_value = sr_xpath_key_value(value->xpath,
                                              "queue-max-sdu-table",
                                              "traffic-class",
                                              &xp_ctx);
		if (key_value != NULL && strcmp("0", key_value))
			qbvconf->qbvconf_ptr->maxsdu = value->data.uint32_val;
	}

out:
	return valid;
}

int abort_qbv_config(sr_session_ctx_t *session, char *path,
		struct sr_qbv_conf *qbvconf)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_change_iter_t *it;

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		printf("ERROR: Get changes from %s failed\n", path);
		goto out;
	}
	while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper,
						     &old_value,
						     &new_value))) {
		if (oper == SR_OP_DELETED) {
			if (old_value) {
				clr_qbv(old_value, qbvconf);
				continue;
			} else {
				init_qbv_memory(qbvconf);
			}
		}
		parse_qbv(session, new_value, qbvconf);

		sr_free_val(old_value);
		sr_free_val(new_value);
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
out:
    sr_free_change_iter(it);
	return rc;
}

int config_qbv_per_port(sr_session_ctx_t *session, char *path, bool abort,
		char *ifname)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	struct sr_qbv_conf qbvconf;
	int valid = 0, ret;

	qbvconf.qbvconf_ptr = malloc_qbv_memory();
	if (!qbvconf.qbvconf_ptr)
		return errno2sp(ENOMEM);

	init_qbv_memory(&qbvconf);

	rc = sr_get_items(session, path, 0, 0, &values, &count);
	if (rc == SR_ERR_NOT_FOUND) {
		/*
		 * If can't find any item, we should check whether this
		 * container was deleted.
		 */
		if (is_del_oper(session, path)) {
			printf("WARN: %s was deleted, disable %s",
			       path, "this Instance.\n");
			qbvconf.qbv_en = false;
			goto config_qbv;
		} else {
			printf("WARN: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));
			free_qbv_memory(qbvconf.qbvconf_ptr);
			return SR_ERR_OK;
		}
	} else if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get items from %s failed", path);
		printf("ERROR: %s sr_get_items: %s\n", __func__, sr_strerror(rc));
		free_qbv_memory(qbvconf.qbvconf_ptr);
		return rc;
	}

	for (i = 0; i < count; i++) {
		if (values[i].type == SR_LIST_T
		    || values[i].type == SR_CONTAINER_PRESENCE_T)
			continue;

		ret = parse_qbv(session, &values[i], &qbvconf);
		if (ret < 0)
			goto cleanup;
		valid += ret;
	}
	if (!valid)
		goto cleanup;

	if (abort) {
		rc = abort_qbv_config(session, path, &qbvconf);
		if (rc != SR_ERR_OK)
			goto cleanup;
	}

config_qbv:
	rc = tsn_config_qbv(session, ifname, &qbvconf);

cleanup:
	free_qbv_memory(qbvconf.qbvconf_ptr);
	sr_free_values(values, count);

	return rc;
}

int qbv_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	sr_change_oper_t oper;
	char *ifname;
	char ifname_bak[IF_NAME_MAX_LEN] = {0,};
	char xpath[XPATH_MAX_LEN] = {0,};

	/* snprintf(xpath, XPATH_MAX_LEN, "%s%s/%s:*//*", IF_XPATH, BR_PORT, QBV_MODULE); */

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		printf("ERROR: %s sr_get_changes_iter: %s\n", __func__, sr_strerror(rc));
		goto cleanup;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		ifname = sr_xpath_key_value(value->xpath, "interface",
					"name", &xp_ctx);
		if (!ifname)
			continue;

		if (strcmp(ifname, ifname_bak)) {
			snprintf(ifname_bak, IF_NAME_MAX_LEN, "%s", ifname);
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']%s/%s:*//*", IF_XPATH,
				 ifname, BR_PORT, QBV_MODULE);
			rc = config_qbv_per_port(session, xpath, abort, ifname);
			if (rc != SR_ERR_OK)
				break;
		}

		sr_free_val(old_value);
		sr_free_val(new_value);
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
cleanup:
    sr_free_change_iter(it);
	return rc;
}

int qbv_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                          const char *module_name, const char *path,
                          sr_event_t event, uint32_t request_id,
                          void *private_ctx)
{
	int rc = SR_ERR_OK;

	/* configure Qbv only when receiving the event SR_EV_DONE */
	if (event != SR_EV_DONE)
		return rc;

	printf("Qbv callback: %s\n", path);

	rc = qbv_config(session, path, false);

	return rc;
}

