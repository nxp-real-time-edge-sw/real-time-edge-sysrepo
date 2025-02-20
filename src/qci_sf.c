/**
 * @file qci_sf.c
 * @author Xiaolin He
 * @brief Implementation of Stream Filter function based on sysrepo
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "main.h"
#include "qci.h"

struct std_qci_list *sf_list_head;
static bool stc_cfg_flag;

void clr_qci_sf(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sf *sfi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "ieee802-dot1q-qci-augment:stream-filter-enabled")) {
		sfi->enable = false;
	} else if (!strcmp(nodename, "stream-filter-instance-id")) {
		sfi->sf_id = 0;
	} else if (!strcmp(nodename, "wildcard")) {
		sfi->sfconf.stream_handle_spec = -1;
	} else if (!strcmp(nodename, "stream-handle")) {
		sfi->sfconf.stream_handle_spec = -1;
	} else if (!strcmp(nodename, "priority-spec")) {
		sfi->sfconf.priority_spec = -1;
	} else if (!strcmp(nodename, "max-sdu-size")) {
		sfi->sfconf.stream_filter.maximum_sdu_size = 0;
	} else if (!strcmp(nodename, "stream-gate-ref")) {
		sfi->sfconf.stream_gate_instance_id = 0;
	} else if (!strcmp(nodename, "stream-blocked-due-to-oversize-frame-enabled")) {
		sfi->sfconf.block_oversize_enable = 0;
	} else if (!strcmp(nodename, "flow-meter-ref")) {
		sfi->sfconf.stream_filter.flow_meter_instance_id = -1;
	}
}

int parse_qci_sf(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sf *sfi)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	uint32_t u32_val = 0;
	char *nodename;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	if (!strcmp(nodename, "ieee802-dot1q-qci-augment:stream-filter-enabled")) {
		sfi->enable = value->data.bool_val;
	} else if (!strcmp(nodename, "stream-filter-instance-id")) {
		sfi->sf_id = value->data.uint32_val;
	} else if (!strcmp(nodename, "wildcard")) {
		sfi->sfconf.stream_handle_spec = -1;
	} else if (!strcmp(nodename, "stream-handle")) {
		sfi->sfconf.stream_handle_spec = value->data.int32_val;
	} else if (!strcmp(nodename, "priority-spec")) {
		pri2num(value->data.enum_val, &sfi->sfconf.priority_spec);
	} else if (!strcmp(nodename, "max-sdu-size")) {
		/* Only use parameters in the first list */
		u32_val = value->data.uint32_val;
		sfi->sfconf.stream_filter.maximum_sdu_size = u32_val;
	} else if (!strcmp(nodename, "stream-blocked-due-to-oversize-frame-enabled")) {
		/* Only use parameters in the first list */
		sfi->sfconf.block_oversize_enable = value->data.bool_val;
	} else if (!strcmp(nodename, "stream-gate-ref")) {
		sfi->sfconf.stream_gate_instance_id = value->data.uint32_val;
	} else if (!strcmp(nodename, "flow-meter-ref")) {
		u32_val = value->data.uint32_val;
		sfi->sfconf.stream_filter.flow_meter_instance_id = u32_val;
	}

out:
	return rc;
}

int get_sf_per_port_per_id(sr_session_ctx_t *session, const char *path)
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
	char *sf_id;
	uint32_t sfid = 0;
	struct std_qci_list *cur_node = NULL;
	char sfid_bak[IF_NAME_MAX_LEN] = "unknown";

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		LOG_ERR("%s sr_get_changes_iter: %s\n", __func__, sr_strerror(rc));
		goto out;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		if (!value)
			continue;

        LOG_DBG("node name: %s, opt: %d", sr_xpath_node_name(value->xpath), (int)oper);

        /* skip the new created node with the default value */
        if (new_value && (oper == SR_OP_CREATED) && new_value->dflt) {
            continue;
        }

		sf_id = sr_xpath_key_value(value->xpath,
					    "stream-filter-instance-table",
					    "stream-filter-instance-id",
					    &xp_ctx_id);

		if ((!sf_id) || !strncmp(sf_id, sfid_bak, IF_NAME_MAX_LEN))
			continue;

		snprintf(sfid_bak, IF_NAME_MAX_LEN, "%s", sf_id);

		sfid = strtoul(sf_id, NULL, 0);
		cpname = sr_xpath_key_value(value->xpath, "component", "name", &xp_ctx_cp);
		if (!cpname)
			continue;

		if (!sf_list_head) {
			sf_list_head = new_list_node(QCI_T_SF, cpname, sfid);
			if (!sf_list_head) {
				sr_session_set_error_message(session, "%s in %s\n",
						"Create new node failed", value->xpath);
				rc = SR_ERR_NO_MEMORY;
				goto out;
			}
			continue;
		}
		cur_node = is_node_in_list(sf_list_head, cpname, sfid,
					   QCI_T_SF);
		if (!cur_node) {
			cur_node = new_list_node(QCI_T_SF, cpname, sfid);
			if (!cur_node) {
				sr_session_set_error_message(session, "%s in %s\n",
						"Create new node failed", value->xpath);
				rc = SR_ERR_NO_MEMORY;
				goto out;
			}

			add_node2list(sf_list_head, cur_node);
		}

		sr_free_val(old_value);
		sr_free_val(new_value);
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
    sr_free_change_iter(it);
	return rc;
}

int abort_sf_config(sr_session_ctx_t *session, char *path,
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
		LOG_ERR("Get changes from %s failed\n", path);
		goto out;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper,
						     &old_value,
						     &new_value))) {
		if (oper == SR_OP_DELETED) {
			if (!old_value)
				continue;

			clr_qci_sf(session, old_value, node->sf_ptr);
			continue;
		}
		parse_qci_sf(session, new_value, node->sf_ptr);

		sr_free_val(old_value);
		sr_free_val(new_value);
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
    sr_free_change_iter(it);
	return rc;
}

int parse_sf_per_port_per_id(sr_session_ctx_t *session, bool abort)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	struct std_qci_list *cur_node = sf_list_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	while (cur_node) {
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[stream-filter-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cur_node->sf_ptr->port,
			 SFI_XPATH, cur_node->sf_ptr->sf_id);
		if (abort) {
			rc = abort_sf_config(session, xpath, cur_node);
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
				cur_node->sf_ptr->enable = false;
				rc = SR_ERR_OK;
			} else {
			    LOG_WRN("%s sr_get_items: %s", __func__, sr_strerror(rc));
				del_list_node(cur_node->pre, QCI_T_SF);
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

				rc = parse_qci_sf(session, &values[i],
						       cur_node->sf_ptr);
				if (rc != SR_ERR_OK) {
					cur_node->apply_st = APPLY_PARSE_ERR;
					sr_free_values(values, count);
					del_list_node(cur_node, QCI_T_SF);
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

static void print_sf_config(struct tsn_qci_psfp_sfi_conf *sfi)
{
    LOG_DBG("tsn_qci_psfp_sfi_conf: stream_handle_spec=%d, \
            priority_spec=%d, stream_gate_instance_id=%d, \
            stream_filter.maximum_sdu_size=%d, \
            stream_filter.flow_meter_instance_id=%d, \
            block_oversize_enable=%d, block_oversize=%d",
            sfi->stream_handle_spec, sfi->priority_spec,
            sfi->stream_gate_instance_id,
            sfi->stream_filter.maximum_sdu_size,
            sfi->stream_filter.flow_meter_instance_id,
            sfi->block_oversize_enable,
            sfi->block_oversize);
}

int config_sf(sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	struct std_qci_list *cur_node = sf_list_head;

	if (!stc_cfg_flag)
		init_tsn_socket();
	while (cur_node) {
        LOG_DBG("config_sf: port-name=%s, stream-filter-handle=%d, enable=%d",
                cur_node->sf_ptr->port, cur_node->sf_ptr->sf_id,
			    (int)cur_node->sf_ptr->enable);
        print_sf_config(&(cur_node->sf_ptr->sfconf));

		/* set new stream filters configuration */
		rc = tsn_qci_psfp_sfi_set(cur_node->sf_ptr->port,
					  cur_node->sf_ptr->sf_id,
					  cur_node->sf_ptr->enable,
					  &(cur_node->sf_ptr->sfconf));
		if (rc < 0) {
			cur_node->apply_st = APPLY_SET_ERR;
			sr_session_set_error_message(session, "failed to set stream filter, %s!",
					strerror(-rc));
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

int qci_sf_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;

	if (!abort) {
		rc = get_sf_per_port_per_id(session, path);
		if (rc != SR_ERR_OK)
			goto out;
	}

	if (!sf_list_head)
		goto out;

	rc = parse_sf_per_port_per_id(session, abort);
	if (rc != SR_ERR_OK)
		goto out;

	if (!stc_cfg_flag)
		rc = config_sf(session);
out:
	return rc;
}

int qci_sf_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                             const char *module_name, const char *path,
                             sr_event_t event, uint32_t request_id,
                             void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

    LOG_DBG("stream-filters: start callback(%d): %s", (int)event, path);

#ifdef SYSREPO_TSN_TC
	stc_cfg_flag = true;
#else
	stc_cfg_flag = false;
#endif

    snprintf(xpath, XPATH_MAX_LEN, "%s//*", path);

	rc = qci_sf_config(session, xpath, false);

	if (sf_list_head) {
		free_list(sf_list_head, QCI_T_SF);
		sf_list_head = NULL;
	}

    if (rc) {
        return SR_ERR_CALLBACK_FAILED;
    } else {
        return SR_ERR_OK;
    }
}
