/**
 * @file qci_sg.c
 * @author Xiaolin He
 * @brief Implementation of Stream Gate function based on sysrepo
 * datastore.
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

#define PLG_NAME    "qci_sg"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "qci.h"

#define CFG_CHANGE          "config-change"
#define ADMIN_CT_EXT        "admin-cycle-time-extension"
#define GC_DUE_OCT_RX_EN    "gate-closed-due-to-invalid-rx-enable"
#define GC_DUE_OCT_RX       "gate-closed-due-to-invalid-rx"
#define GC_DUE_OCT_EX_EN    "gate-closed-due-octets-exceeded-enable"
#define GC_DUE_OCT_EX       "gate-closed-due-octets-exceeded"

struct std_qci_list *sg_list_head;

static bool stc_cfg_flag;
static struct tc_qci_gates_para sqci_gates_para;

void clr_qci_sg(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sg *sgi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;
	char *index;
	uint64_t u64_val = 0;
	struct tsn_qci_psfp_gcl *entry = sgi->sgconf.admin.gcl;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "gate-enable")) {
		sgi->enable = false;
	} else if (!strcmp(nodename, "stream-gate-instance-id")) {
		sgi->sg_handle = 0;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		sgi->sgconf.admin.gate_states = false;
	} else if (!strcmp(nodename, "admin-ipv")) {
		sgi->sgconf.admin.init_ipv = -1;
	} else if (!strcmp(nodename, "gate-state-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		(entry + u64_val)->gate_state = false;
	} else if (!strcmp(nodename, "ipv-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		(entry + u64_val)->ipv = -1;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		(entry + u64_val)->time_interval = 0;
	} else if (!strcmp(nodename, "interval-octet-max")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		(entry + u64_val)->octet_max = 0;
	} else if (!strcmp(nodename, "numerator")) {
		sgi->cycletime.numerator = 0;
	} else if (!strcmp(nodename, "denominator")) {
		sgi->cycletime.denominator = 0;
		sgi->cycletime_f = false;
	} else if (!strcmp(nodename, "seconds")) {
		sgi->basetime.seconds = 0;
	} else if (!strcmp(nodename, "nanoseconds")) {
		sgi->basetime.nanoseconds = 0;
		sgi->basetime_f = false;
	} else if (!strcmp(nodename, ADMIN_CT_EXT)) {
		sgi->sgconf.admin.cycle_time_extension = 0;
	} else if (!strcmp(nodename, CFG_CHANGE)) {
		sgi->sgconf.config_change = false;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX_EN)) {
		sgi->sgconf.block_invalid_rx_enable = false;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX)) {
		sgi->sgconf.block_invalid_rx = false;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX_EN)) {
		sgi->sgconf.block_octets_exceeded_enable = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX)) {
		sgi->sgconf.block_octets_exceeded = false;
	}
}

static struct tc_qci_gate_entry *qci_gate_find_entry(uint32_t id)
{
	struct tc_qci_gates_para *para = &sqci_gates_para;
	struct tc_qci_gate_entry *gate = NULL;
	int i = 0;

	for (i = 0; i < para->entry_cnt; i++) {
		gate = para->entry + i;
		if (gate->id == id)
			return gate;
	}

	return NULL;
}

int parse_qci_sg(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sg *sgi)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	uint64_t u64_val = 0;
	char *nodename;
	char *num_str;
	char *index;
	struct tsn_qci_psfp_gcl *entry = sgi->sgconf.admin.gcl;
	struct tc_qci_gates_para *para = &sqci_gates_para;
	struct tc_qci_gate_entry *gate = NULL;
	struct tc_qci_gate_entry gate_tmp;
	struct tc_qci_gate_acl *acl = NULL;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	gate = qci_gate_find_entry(sgi->sg_id);
	if (stc_cfg_flag && !gate)
		goto out;
	else if (!gate)
		gate = &gate_tmp;

	acl = gate->acl;

	if (!strcmp(nodename, "gate-enable")) {
		sgi->enable = value->data.bool_val;
	} else if (!strcmp(nodename, "stream-gate-instance-id")) {
		sgi->sg_handle = value->data.uint32_val;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "open")) {
			sgi->sgconf.admin.gate_states = true;
		} else if (!strcmp(num_str, "closed")) {
			sgi->sgconf.admin.gate_states = false;
		} else {
			sr_session_set_error_message(session, "Invalid '%s'", num_str);
			LOG_ERR("Invalid '%s' in %s!", num_str, value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		gate->gate_state = sgi->sgconf.admin.gate_states;
	} else if (!strcmp(nodename, "admin-ipv")) {
		pri2num(value->data.enum_val, &sgi->sgconf.admin.init_ipv);
	} else if (!strcmp(nodename, "gate-state-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		num_str = value->data.enum_val;
		if (!strcmp(num_str, "open")) {
			(entry + u64_val)->gate_state = true;
		} else if (!strcmp(num_str, "closed")) {
			(entry + u64_val)->gate_state = false;
		} else {
			sr_session_set_error_message(session, "Invalid '%s'", num_str);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}

		if (u64_val < SUB_PARA_LEN)
			acl[u64_val].state = (entry + u64_val)->gate_state;
	} else if (!strcmp(nodename, "ipv-spec")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		pri2num(value->data.enum_val, &(entry + u64_val)->ipv);
		if (u64_val < SUB_PARA_LEN)
			acl[u64_val].ipv = (entry + u64_val)->ipv;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		(entry + u64_val)->time_interval = value->data.uint32_val;
		if ((entry + u64_val)->time_interval == 0)
			sgi->sgconf.admin.control_list_length = u64_val;
		else
			sgi->sgconf.admin.control_list_length = u64_val + 1;
		gate->acl_len = MIN(sgi->sgconf.admin.control_list_length, SUB_PARA_LEN);

		if (u64_val < SUB_PARA_LEN)
			acl[u64_val].interval = value->data.uint32_val;
	} else if (!strcmp(nodename, "interval-octet-max")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath, "gate-control-entry",
					   "index", &xp_ctx);
		if (index != NULL) {
			u64_val = strtoul(index, NULL, 0);
		}

		(entry + u64_val)->octet_max = value->data.uint32_val;
	} else if (!strcmp(nodename, "numerator")) {
		sgi->cycletime.numerator = value->data.uint32_val;
	} else if (!strcmp(nodename, "denominator")) {
		sgi->cycletime.denominator = value->data.uint32_val;
		if (!sgi->cycletime.denominator) {
			sr_session_set_error_message(session, "The value of %s is zero",
					value->xpath);
			LOG_ERR("denominator is zero!");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		sgi->cycletime_f = true;
	} else if (!strcmp(nodename, "seconds")) {
		sgi->basetime.seconds = value->data.uint64_val;
		sgi->basetime_f = true;
	} else if (!strcmp(nodename, "nanoseconds")) {
		sgi->basetime.nanoseconds = (uint64_t)value->data.uint32_val;
		sgi->basetime_f = true;
	} else if (!strcmp(nodename, ADMIN_CT_EXT)) {
		sgi->sgconf.admin.cycle_time_extension = value->data.int32_val;
	} else if (!strcmp(nodename, CFG_CHANGE)) {
		sgi->sgconf.config_change = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX_EN)) {
		sgi->sgconf.block_invalid_rx_enable = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX)) {
		sgi->sgconf.block_invalid_rx = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX_EN)) {
		sgi->sgconf.block_octets_exceeded_enable = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX)) {
		sgi->sgconf.block_octets_exceeded = value->data.bool_val;
	}

	para->set_flag = true;

out:
	return rc;
}

int get_sg_per_port_per_id(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it;
	sr_xpath_ctx_t xp_ctx_cp = {0};
	sr_xpath_ctx_t xp_ctx_id = {0};
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	char *cpname;
	char *sg_id;
	uint32_t sgid = 0;
	struct std_qci_list *cur_node = NULL;
	char sgid_bak[IF_NAME_MAX_LEN] = "unknown";
	struct tc_qci_gates_para *para = &sqci_gates_para;
	int cnt = 0;

	rc = sr_get_changes_iter(session, path, &it);

	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		LOG_ERR("%s sr_get_changes_iter: %s", __func__, sr_strerror(rc));
		goto out;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		if (!value)
			continue;

        LOG_INF("node name: %s, opt: %d", sr_xpath_node_name(value->xpath), (int)oper);

        /* skip the new created node with the default value */
        if (new_value && (oper == SR_OP_CREATED) && new_value->dflt) {
            continue;
        }

		sg_id = sr_xpath_key_value(value->xpath,
					    "stream-gate-instance-table",
					    "stream-gate-instance-id",
					    &xp_ctx_id);

		if ((!sg_id) || !strncmp(sg_id, sgid_bak, IF_NAME_MAX_LEN))
			continue;

		snprintf(sgid_bak, IF_NAME_MAX_LEN, "%s", sg_id);

		sgid = strtoul(sg_id, NULL, 0);
		cpname = sr_xpath_key_value(value->xpath, "component", "name",
                                    &xp_ctx_cp);
		if (!cpname)
			continue;

		if (cnt < SUB_PARA_LEN)
			para->entry[cnt++].id = sgid;

		if (!sg_list_head) {
			sg_list_head = new_list_node(QCI_T_SG, cpname, sgid);
			if (!sg_list_head) {
				sr_session_set_error_message(session, "%s in %s",
						"Create new node failed", value->xpath);
				rc = SR_ERR_NO_MEMORY;
				goto out;
			}
			continue;
		}
		cur_node = is_node_in_list(sg_list_head, cpname, sgid,
					   QCI_T_SG);
		if (!cur_node) {
			cur_node = new_list_node(QCI_T_SG, cpname, sgid);
			if (!cur_node) {
				sr_session_set_error_message(session, "%s in %s",
						"Create new node failed", value->xpath);
				rc = SR_ERR_NO_MEMORY;
				goto out;
			}

			add_node2list(sg_list_head, cur_node);
		}

		sr_free_val(old_value);
		sr_free_val(new_value);
	}
	para->entry_cnt = cnt;

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
    sr_free_change_iter(it);
	return rc;
}

int abort_sg_config(sr_session_ctx_t *session, char *path,
		struct std_qci_list *node)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_change_iter_t *it;

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		LOG_ERR("Get changes from %s failed", path);
		goto out;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper,
						     &old_value,
						     &new_value))) {
		if (oper == SR_OP_DELETED) {
			if (!old_value)
				continue;

			clr_qci_sg(session, old_value, node->sg_ptr);
			continue;
		}
		parse_qci_sg(session, new_value, node->sg_ptr);

		sr_free_val(old_value);
		sr_free_val(new_value);
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
    sr_free_change_iter(it);
	return rc;
}

int parse_sg_per_port_per_id(sr_session_ctx_t *session, bool abort)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	struct std_qci_list *cur_node = sg_list_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	while (cur_node) {
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[stream-gate-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cur_node->sg_ptr->port,
			 SGI_XPATH, cur_node->sg_ptr->sg_id);
		if (abort) {
			rc = abort_sg_config(session, xpath, cur_node);
			if (rc != SR_ERR_OK)
				goto out;

			cur_node = cur_node->next;
			continue;
		}

		rc = sr_get_items(session, xpath, 0, 0, &values, &count);
		if (rc == SR_ERR_NOT_FOUND) {
			rc = SR_ERR_OK;
			/*
			 * If can't find any item, we should check whether this
			 * container was deleted.
			 */
			if (is_del_oper(session, xpath)) {
			    LOG_WRN("%s was deleted, disable this Instance.", xpath);
				cur_node->sg_ptr->enable = false;
			} else {
			    LOG_WRN("%s sr_get_items: %s", __func__, sr_strerror(rc));
				del_list_node(cur_node->pre, QCI_T_SG);
			}
			cur_node = cur_node->next;
		} else if (rc != SR_ERR_OK) {
			sr_session_set_error_message(session, "Get items from %s failed", xpath);
		    LOG_ERR("%s sr_get_items: %s", __func__, sr_strerror(rc));
			goto out;
		} else {
			for (i = 0; i < count; i++) {
				if (values[i].type == SR_LIST_T ||
				    values[i].type == SR_CONTAINER_PRESENCE_T)
					continue;

				rc = parse_qci_sg(session, &values[i],
						  cur_node->sg_ptr);
				if (rc != SR_ERR_OK) {
					cur_node->apply_st = APPLY_PARSE_ERR;
					sr_free_values(values, count);
					del_list_node(cur_node, QCI_T_SG);
					goto out;
				}
			}
			sr_free_values(values, count);
			cur_node->apply_st = APPLY_PARSE_SUC;

			cur_node = cur_node->next;
		}
	}

out:
	return rc;
}

void print_sg_config(struct tsn_qci_psfp_sgi_conf *sgi)
{
    LOG_INF("tsn_qci_psfp_sgi_conf: gate_enabled=%d, config_change=%d, \
            admin.gate_states=%d, admin.control_list_length=%d, \
            admin.cycle_time=%d, admin.cycle_time_extension=%d, \
            admin.base_time=%d, admin.init_ipv=%d, \
            admin.gcl->gate_state=%d, admin.gcl->ipv=%d, \
            admin.gcl->time_interval=%d, admin.gcl->octet_max=%d, \
            block_invalid_rx_enable=%d, block_invalid_rx=%d, \
            block_octets_exceeded_enable=%d, block_octets_exceeded=%d",
            sgi->gate_enabled, sgi->config_change,
            sgi->admin.gate_states, sgi->admin.control_list_length,
            sgi->admin.cycle_time, sgi->admin.cycle_time_extension,
            sgi->admin.base_time, sgi->admin.init_ipv,
            sgi->admin.gcl->gate_state, sgi->admin.gcl->ipv,
            sgi->admin.gcl->time_interval, sgi->admin.gcl->octet_max,
            sgi->block_invalid_rx_enable, sgi->block_invalid_rx,
            sgi->block_octets_exceeded_enable, sgi->block_octets_exceeded);
}

int config_sg(sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	struct std_qci_list *cur_node = sg_list_head;
	uint64_t time;
	struct tsn_qci_psfp_sgi_conf *sgi;

	if (!stc_cfg_flag)
		init_tsn_socket();
	while (cur_node) {
		sgi = &cur_node->sg_ptr->sgconf;
		if (cur_node->sg_ptr->basetime_f) {
			time = cal_base_time(&cur_node->sg_ptr->basetime);
			sgi->admin.base_time = time;
		}
		if (cur_node->sg_ptr->cycletime_f) {
			time = cal_cycle_time(&cur_node->sg_ptr->cycletime);
			sgi->admin.cycle_time = time;
		}

        LOG_INF("config_sg: port-name=%s, stream-gate-handle=%d, enable=%d",
                cur_node->sg_ptr->port, cur_node->sg_ptr->sg_handle,
                (int)cur_node->sg_ptr->enable);
        print_sg_config(sgi);

		/* set new stream gates configuration */
		rc = tsn_qci_psfp_sgi_set(cur_node->sg_ptr->port,
					  cur_node->sg_ptr->sg_handle,
					  cur_node->sg_ptr->enable, sgi);
		if (rc < 0) {
			sr_session_set_error_message(session, "failed to set stream gate, %s!",
					strerror(-rc));
			cur_node->apply_st = APPLY_SET_ERR;
			goto cleanup;
		} else {
			cur_node->apply_st = APPLY_SET_SUC;
		}
		if (cur_node->next == NULL)
			break;
		cur_node = cur_node->next;
	}

cleanup:
	if (!stc_cfg_flag)
		close_tsn_socket();

	return rc;
}

static int qci_sg_update_time(void)
{
	struct std_qci_list *cur_node = sg_list_head;
	struct tc_qci_gate_entry *gate = NULL;
	struct std_sg *sg_ptr;
	uint64_t time;

	while (cur_node) {
		sg_ptr = cur_node->sg_ptr;

		gate = qci_gate_find_entry(sg_ptr->sg_id);
		if (!gate)
			break;

		if (sg_ptr->basetime_f) {
			time = cal_base_time(&sg_ptr->basetime);
			gate->base_time = time;
		}

		if (sg_ptr->cycletime_f) {
			time = cal_cycle_time(&sg_ptr->cycletime);
			gate->cycle_time = time;
		}

		cur_node = cur_node->next;
	}

	return SR_ERR_OK;
}

int qci_sg_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;

	if (!abort) {
		rc = get_sg_per_port_per_id(session, path);
		if (rc != SR_ERR_OK)
			goto out;
	}
	if (!sg_list_head)
		goto out;

	rc = parse_sg_per_port_per_id(session, abort);
	if (rc != SR_ERR_OK)
		goto out;

	if (stc_cfg_flag) {
		qci_sg_update_time();
		rc = qci_check_parameter();
	} else {
		rc = config_sg(session);
	}
out:
	return rc;
}

int qci_sg_get_para(char *buf, int len)
{
	struct tc_qci_gates_para *para = &sqci_gates_para;
	struct tc_qci_gate_entry *gate = NULL;
	struct tc_qci_gate_acl *acl = NULL;
	char sub_buf[SUB_CMD_LEN];
	bool trap_flag = false;
	char *host_name = NULL;
	char *ifn = NULL;
	int i = 0;
	int j = 0;

	if (!para->set_flag || !buf || !len)
		return 0;

	for (i = 0; i < para->entry_cnt; i++) {
		gate = para->entry + i;

		snprintf(sub_buf, SUB_CMD_LEN, "action gate index %d ", gate->id);
		strncat(buf, sub_buf, len - 1 - strlen(buf));

		snprintf(sub_buf, SUB_CMD_LEN, "base-time %" PRIu64 " ", gate->base_time);
		strncat(buf, sub_buf, len - 1 - strlen(buf));

		if (gate->cycle_time) {
			snprintf(sub_buf, SUB_CMD_LEN, "cycle-time %" PRIu64 " ", gate->cycle_time);
			strncat(buf, sub_buf, len - 1 - strlen(buf));
		}

		for (j = 0; j < gate->acl_len; j++) {
			acl = gate->acl + j;

			if (acl->state)
				snprintf(sub_buf, SUB_CMD_LEN, "sched-entry OPEN ");
			else
				snprintf(sub_buf, SUB_CMD_LEN, "sched-entry CLOSE ");
			strncat(buf, sub_buf, len - 1 - strlen(buf));

			snprintf(sub_buf, SUB_CMD_LEN, "%d %d -1 ", acl->interval, acl->ipv);
			strncat(buf, sub_buf, len - 1 - strlen(buf));
		}
	}

	host_name = get_host_name();
	if (!host_name)
		goto ret_tag;

	ifn = get_interface_name();
	if (strcasestr(host_name, "LS1028ATSN") && (strlen(ifn) >= 5)
				&& (ifn[0] == 's') && (ifn[1] == 'w'))
		trap_flag = true;

	if (strcasestr(host_name, "LS1021ATSN"))
		trap_flag = true;

	if (trap_flag) {
		snprintf(sub_buf, SUB_CMD_LEN, "action trap ");
		strncat(buf, sub_buf, len - 1 - strlen(buf));
	}

ret_tag:
	return (int)strlen(buf);
}

int qci_sg_clear_para(void)
{
	memset(&sqci_gates_para, 0, sizeof(sqci_gates_para));
	return 0;
}

int qci_sg_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                             const char *module_name, const char *path,
                             sr_event_t event, uint32_t request_id,
                             void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

    LOG_INF("stream-gates: start callback(%d): %s", (int)event, path);

    snprintf(xpath, XPATH_MAX_LEN, "%s//*", path);

#ifdef SYSREPO_TSN_TC
	stc_cfg_flag = true;
	qci_set_xpath(xpath);
	qci_set_session(session);
#else
	stc_cfg_flag = false;
#endif

	rc = qci_sg_config(session, xpath, false);

	if (sg_list_head) {
		free_list(sg_list_head, QCI_T_SG);
		sg_list_head = NULL;
	}

    if (rc) {
        return SR_ERR_CALLBACK_FAILED;
    } else {
        return SR_ERR_OK;
    }
}
