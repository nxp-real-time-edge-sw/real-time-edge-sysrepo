/**
 * @file qci_fm.c
 * @author Xiaolin He
 * @brief Implementation of Flow meter function based on sysrepo
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

#define PLG_NAME    "qci_fm"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "qci.h"

struct std_qci_list *fm_list_head;

static bool stc_cfg_flag;
static struct tc_qci_policer_para sqci_policer_para;

void clr_qci_fm(sr_session_ctx_t *session, sr_val_t *value,
		struct std_fm *fmi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "ieee802-dot1q-qci-augment:flow-meter-enabled"))
		fmi->enable = false;
	else if (!strcmp(nodename, "committed-information-rate"))
		fmi->fmconf.cir = 0;
	else if (!strcmp(nodename, "committed-burst-size"))
		fmi->fmconf.cbs = 0;
	else if (!strcmp(nodename, "excess-information-rate"))
		fmi->fmconf.eir = 0;
	else if (!strcmp(nodename, "excess-burst-size"))
		fmi->fmconf.ebs = 0;
	else if (!strcmp(nodename, "coupling-flag"))
		fmi->fmconf.cf = false;
	else if (!strcmp(nodename, "color-mode"))
		fmi->fmconf.cm = false;
	else if (!strcmp(nodename, "drop-on-yellow"))
		fmi->fmconf.drop_on_yellow  = false;
	else if (!strcmp(nodename, "mark-all-frames-red-enable"))
		fmi->fmconf.mark_red_enable = false;
}

static struct tc_qci_policer_entry *qci_fm_find_entry(uint32_t id)
{
	struct tc_qci_policer_para *para = &sqci_policer_para;
	struct tc_qci_policer_entry *entry = NULL;
	int i = 0;

	for (i = 0; i < para->entry_cnt; i++) {
		entry = para->entry + i;
		if (entry->id == id)
			return entry;
	}

	return NULL;
}

int parse_qci_fm(sr_session_ctx_t *session, sr_val_t *value,
		struct std_fm *fmi)
{
	struct tc_qci_policer_para *para = &sqci_policer_para;
	struct tc_qci_policer_entry *entry = NULL;
	struct tc_qci_policer_entry entry_tmp;
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;
	char *num_str;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	entry = qci_fm_find_entry(fmi->fm_id);
	if (stc_cfg_flag && !entry)
		goto out;
	else if (!entry)
		entry = &entry_tmp;

	if (!strcmp(nodename, "ieee802-dot1q-qci-augment:flow-meter-enabled")) {
		fmi->enable = value->data.bool_val;
	} else if (!strcmp(nodename, "committed-information-rate")) {
		fmi->fmconf.cir = value->data.uint64_val / 1000;
		entry->cir = value->data.uint64_val;
	} else if (!strcmp(nodename, "committed-burst-size")) {
		fmi->fmconf.cbs = value->data.uint32_val;
		entry->cbs = value->data.uint32_val;
	} else if (!strcmp(nodename, "excess-information-rate")) {
		fmi->fmconf.eir = value->data.uint64_val / 1000;
		entry->eir = value->data.uint64_val;
	} else if (!strcmp(nodename, "excess-burst-size")) {
		fmi->fmconf.ebs = value->data.uint32_val;
		entry->ebs = value->data.uint32_val;
	} else if (!strcmp(nodename, "coupling-flag")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "zero")) {
			fmi->fmconf.cf = false;
		} else if (!strcmp(num_str, "one")) {
			fmi->fmconf.cf = true;
		} else {
			sr_session_set_error_message(session, "Invalid '%s'", num_str);
			LOG_ERR("Invalid '%s' in %s!", num_str, value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "color-mode")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "color-blind")) {
			fmi->fmconf.cm = false;
		} else if (!strcmp(num_str, "color-aware")) {
			fmi->fmconf.cm = true;
		} else {
			sr_session_set_error_message(session, "Invalid '%s'", num_str);
			LOG_ERR("Invalid '%s' in %s!", num_str, value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "drop-on-yellow")) {
		fmi->fmconf.drop_on_yellow  = value->data.bool_val;
	} else if (!strcmp(nodename, "mark-all-frames-red-enable")) {
		fmi->fmconf.mark_red_enable = value->data.bool_val;
	}

	para->set_flag = true;

out:
	return rc;
}

int get_fm_per_port_per_id(sr_session_ctx_t *session, const char *path)
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
	char *fm_id;
	uint32_t fmid = 0;
	struct std_qci_list *cur_node = NULL;
	char fmid_bak[IF_NAME_MAX_LEN] = "unknown";
	struct tc_qci_policer_para *para = &sqci_policer_para;
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

		fm_id = sr_xpath_key_value(value->xpath,
					    "flow-meter-instance-table",
					    "flow-meter-instance-id",
					    &xp_ctx_id);

		if ((!fm_id) || !strncmp(fm_id, fmid_bak, IF_NAME_MAX_LEN))
			continue;

		snprintf(fmid_bak, IF_NAME_MAX_LEN, "%s", fm_id);

		fmid = strtoul(fm_id, NULL, 0);
		cpname = sr_xpath_key_value(value->xpath, "component",
					    "name", &xp_ctx_cp);
		if (!cpname)
			continue;

		if (cnt < SUB_PARA_LEN)
			para->entry[cnt++].id = fmid;

		if (!fm_list_head) {
			fm_list_head = new_list_node(QCI_T_FM, cpname, fmid);
			if (!fm_list_head) {
				sr_session_set_error_message(session, "Create new node failed");
				rc = SR_ERR_NO_MEMORY;
				goto out;
			}
			continue;
		}
		cur_node = is_node_in_list(fm_list_head, cpname, fmid,
					   QCI_T_FM);
		if (!cur_node) {
			cur_node = new_list_node(QCI_T_FM, cpname, fmid);
			if (!cur_node) {
				sr_session_set_error_message(session, "Create new node failed");
				rc = SR_ERR_NO_MEMORY;
				goto out;
			}

			add_node2list(fm_list_head, cur_node);
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

int abort_fm_config(sr_session_ctx_t *session, char *path,
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

			clr_qci_fm(session, old_value, node->fm_ptr);
			continue;
		}
		parse_qci_fm(session, new_value, node->fm_ptr);

		sr_free_val(old_value);
		sr_free_val(new_value);
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
out:
    sr_free_change_iter(it);
	return rc;
}

int parse_fm_per_port_per_id(sr_session_ctx_t *session, bool abort)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	struct std_qci_list *cur_node = fm_list_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	while (cur_node) {
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[flow-meter-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cur_node->fm_ptr->port,
			 FMI_XPATH, cur_node->fm_ptr->fm_id);

		if (abort) {
			rc = abort_fm_config(session, xpath, cur_node);
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
				cur_node->fm_ptr->enable = false;
			} else {
			    LOG_WRN("%s sr_get_items: %s", __func__, sr_strerror(rc));
				del_list_node(cur_node->pre, QCI_T_FM);
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

				rc = parse_qci_fm(session, &values[i],
						  cur_node->fm_ptr);
				if (rc != SR_ERR_OK) {
					cur_node->apply_st = APPLY_PARSE_ERR;
					sr_free_values(values, count);
					del_list_node(cur_node, QCI_T_FM);
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

void print_fm_config(struct tsn_qci_psfp_fmi *fmiconf)
{
    LOG_INF("tsn_qci_psfp_fmi: cir=%d, cbs=%d, eir=%d, ebs=%d, cf=%d, cm=%d, \
            drop_on_yellow=%d, mark_red_enable=%d, mark_red=%d",
            fmiconf->cir, fmiconf->cbs, fmiconf->eir,
            fmiconf->ebs, fmiconf->cf, fmiconf->cm,
            fmiconf->drop_on_yellow, fmiconf->mark_red_enable, fmiconf->mark_red);
}

int config_fm(sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	struct std_qci_list *cur_node = fm_list_head;

	if (!stc_cfg_flag)
		init_tsn_socket();
	while (cur_node) {

        LOG_INF("config_fm: port-name=%s, flow-meters-handle=%d, enable=%d",
                cur_node->fm_ptr->port, cur_node->fm_ptr->fm_id,
                cur_node->fm_ptr->enable);
        print_fm_config(&(cur_node->fm_ptr->fmconf));

		/* set new flow meter configuration */
		rc = tsn_qci_psfp_fmi_set(cur_node->fm_ptr->port,
					  cur_node->fm_ptr->fm_id,
					  cur_node->fm_ptr->enable,
					  &(cur_node->fm_ptr->fmconf));
		if (rc < 0) {
			sr_session_set_error_message(session, "failed to set flow meter, %s!",
					strerror(-rc));
			cur_node->apply_st = APPLY_SET_ERR;
			goto cleanup;
		} else {
			cur_node->apply_st = APPLY_SET_SUC;
		}
		cur_node = cur_node->next;
	}

cleanup:
	if (!stc_cfg_flag)
		close_tsn_socket();

	return rc;
}

int qci_fm_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;

	if (!abort) {
		rc = get_fm_per_port_per_id(session, path);
		if (rc != SR_ERR_OK)
			goto out;
	}
	if (!fm_list_head)
		goto out;

	rc = parse_fm_per_port_per_id(session, abort);
	if (rc != SR_ERR_OK)
		goto out;

	if (stc_cfg_flag)
		rc = qci_check_parameter();
	else
		rc = config_fm(session);
out:
	return rc;
}

int qci_fm_get_para(char *buf, int len)
{
	struct tc_qci_policer_para *para = &sqci_policer_para;
	struct tc_qci_policer_entry *entry = NULL;
	char sub_buf[SUB_CMD_LEN];
	uint32_t cir = 0;
	int i = 0;

	if (!para->set_flag || !buf || !len)
		return 0;

	for (i = 0; i < para->entry_cnt; i++) {
		entry = para->entry + i;

		snprintf(sub_buf, SUB_CMD_LEN, "action police index %d ", entry->id);
		strncat(buf, sub_buf, len - 1 - strlen(buf));

		if (entry->cir > MBPS) {
			cir = entry->cir / MBPS;
			snprintf(sub_buf, SUB_CMD_LEN, "rate %dmbit ", cir);
		} else if (entry->cir > KBPS) {
			cir = entry->cir / KBPS;
			snprintf(sub_buf, SUB_CMD_LEN, "rate %dkbit ", cir);
		} else {
			cir = entry->cir;
			snprintf(sub_buf, SUB_CMD_LEN, "rate %dbit ", cir);
		}
		strncat(buf, sub_buf, len - 1 - strlen(buf));

		snprintf(sub_buf, SUB_CMD_LEN, "burst %d ", entry->cbs);
		strncat(buf, sub_buf, len - 1 - strlen(buf));
	}

	return (int)strlen(buf);
}

int qci_fm_clear_para(void)
{
	memset(&sqci_policer_para, 0, sizeof(sqci_policer_para));
	return 0;
}

int qci_fm_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                             const char *module_name, const char *path,
                             sr_event_t event, uint32_t request_id,
                             void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

    LOG_INF("flow-meters: start callback(%d): %s", (int)event, path);

    snprintf(xpath, XPATH_MAX_LEN, "%s//*", path);

#ifdef SYSREPO_TSN_TC
	stc_cfg_flag = true;
	qci_set_xpath(xpath);
	qci_set_session(session);
#else
	stc_cfg_flag = false;
#endif

	rc = qci_fm_config(session, xpath, false);

	if (fm_list_head) {
		free_list(fm_list_head, QCI_T_FM);
		fm_list_head = NULL;
	}
    if (rc) {
        return SR_ERR_CALLBACK_FAILED;
    } else {
        return SR_ERR_OK;
    }
}
