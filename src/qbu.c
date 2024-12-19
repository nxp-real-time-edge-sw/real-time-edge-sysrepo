/**
 * @file qbu.c
 * @author Xiaolin He
 * @brief Application to configure TSN-QBU function based on sysrepo datastore.
 *
 * Copyright 2019-2024 NXP
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
#include <inttypes.h>
#include <libyang/libyang.h>
#include <sysrepo.h>
#include <assert.h>

#include "common.h"
#include "qbu.h"

#define NODE_SET_SIZE	(20U)

static uint32_t get_preemptible_queues_mask(const struct lyd_node *node)
{
	const char *key = "priority";
    struct lyd_node *iter;
	uint32_t mask = 0;
	uint32_t prio = 0;

	LY_LIST_FOR(lyd_child(node), iter) {
		const char *nodename = LYD_NAME(iter);

		if (!strncmp(nodename, key, strlen(key))) {

			/* get the priority number from the last character of the nodename */
			prio = nodename[strlen(key)] - '0';
			if (!strcmp(lyd_get_value(iter), "preemptable")) {
				mask |= (1 << prio);
			}
		}
	}
	return mask;
}

static int config_frame_preemption(const char *ifname,
								   const struct lyd_node *node,
								   const uint32_t value)
{
#ifdef SYSREPO_TSN_TC
	const char *cmd_enable = "ethtool --set-frame-preemption %s fp on preemptible-queues-mask 0x%02X min-frag-size %d";
	const char *cmd_disable = "ethtool --set-frame-preemption %s disabled";
	char cmd_buff[MAX_CMD_LEN];
	int sysret = 0;

	if (value != 0) {
		snprintf(cmd_buff, sizeof(cmd_buff), cmd_enable, ifname, value, QBU_MIN_FRAG_SIZE);
	} else {
		snprintf(cmd_buff, sizeof(cmd_buff), cmd_disable, ifname);
	}

	sysret = system(cmd_buff);
	if (!SYSCALL_OK(sysret)) {
		return SR_ERR_INVAL_ARG;
	}

	return SR_ERR_OK;
#else
	int rc = SR_ERR_OK;

	init_tsn_socket();
	/* Disable the cut-through mode before configure the Qbu. */
	tsn_ct_set(ifname, 0);
	rc = tsn_qbu_set(ifname, value);
	close_tsn_socket();

	if (rc < 0) {
		return SR_ERR_INVAL_ARG;
	}
	return SR_ERR_OK;
#endif
}

static const struct lyd_node *is_path_include(const struct lyd_node *node,
											  const char *node_name)
{
    const struct lyd_node *iter = NULL;

	for (iter = node; iter; iter = lyd_parent(iter)) {
		if (!strcmp(LYD_NAME(iter), node_name)) {
			return iter;
		}
	}

	return NULL;
}

static const char *get_ifname(const struct lyd_node *node)
{
    const struct lyd_node *target = NULL;
    struct lyd_node *output = NULL;

	target = is_path_include(node, "interface");

	if (target && !lyd_find_path(target, "name", 0, &output) && output) {
		return lyd_get_value(output);
	} else {
		return NULL;
	}
}

static int check_and_add(const struct lyd_node **set, const struct lyd_node *node)
{
	const struct lyd_node **iter = set;

	while (*iter) {
		assert(((iter - set) / sizeof(*iter)) < NODE_SET_SIZE);
		if (*iter == node) {
			return -1;
		}
		iter++;
	}
	*iter = node;

	return 0;
}

int qbu_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                          const char *module_name, const char *path,
                          sr_event_t event, uint32_t request_id,
                          void *private_ctx)
{
	char xpath[XPATH_MAX_LEN] = {0};
	sr_change_iter_t *iter = NULL;
    const struct lyd_node *node = NULL;
    sr_change_oper_t op;
	int rc = SR_ERR_OK;

	/* configure Qbu only when receiving the event SR_EV_DONE */
	if (event != SR_EV_DONE)
		return rc;

	snprintf(xpath, XPATH_MAX_LEN, "%s//.", QBU_PARA_XPATH);

	rc = sr_get_changes_iter(session, xpath, &iter);
	if (rc != SR_ERR_OK) {
		return rc;
	}

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node,
					NULL, NULL, NULL)) == SR_ERR_OK) {

		const struct lyd_node *set[NODE_SET_SIZE] = { 0 };
		const struct lyd_node *target = NULL;
		char *ifname = NULL;
		uint32_t value = 0;

		target = is_path_include(node, "frame-preemption-status-table");
		if (target != NULL) {

			ifname = strdup(get_ifname(node));
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {

				if (check_and_add(&set[0], target)) {
					continue;
				}
				value = get_preemptible_queues_mask(node);
				rc = config_frame_preemption(ifname, target, value);

			} else if (op == SR_OP_DELETED) {
				value = 0;
				rc = config_frame_preemption(ifname, target, value);
			}
			free(ifname);

			if (rc) {
				char *__path = lyd_path(target, LYD_PATH_STD, NULL, 0);
				sr_session_set_error_message(session,
						"Failed to config frame preemption (Qbu): %s", __path);
				free(__path);

				rc = SR_ERR_UNSUPPORTED;
				break;
			}
		}
	}
    sr_free_change_iter(iter);

	return rc;
}
