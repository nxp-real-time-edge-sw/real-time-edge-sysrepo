/**
 * @file qbu.c
 * @author Xiaolin He
 * @brief Application to configure TSN-QBU function based on sysrepo datastore.
 *
 * Copyright 2019-2025 NXP
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

#define PLG_NAME    "qbu"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "qbu.h"

static int get_preemptible_queues_mask(sr_session_ctx_t *session, char *ifname,
                                        uint32_t *mask)
{
	const char *key = "priority";
    const struct lyd_node *node;
    const struct lyd_node *iter;
	const char *nodename = NULL; 
	uint32_t prio = 0;
    sr_data_t *subtree = NULL;
    char *xpath = NULL;
    int rc = SR_ERR_OK;

    if ((mask == NULL) || (strlen(ifname) == 0)) {
        rc = SR_ERR_INVAL_ARG;
        goto err;
    }

    rc = asprintf(&xpath,
         "/ietf-interfaces:interfaces/interface[name='%s']/ieee802-dot1q-bridge:bridge-port/ieee802-dot1q-preemption-bridge:frame-preemption-parameters/frame-preemption-status-table",
         ifname);
    if (rc < 0) {
        rc = SR_ERR_NO_MEMORY;
        goto err;
    }

    rc = sr_get_subtree(session, xpath, 0, &subtree);
    free(xpath);
    if (rc) {
        goto err;
    }
    node = subtree->tree;

	LY_LIST_FOR(lyd_child(node), iter) {

		nodename = LYD_NAME(iter);
		if (!strncmp(nodename, key, strlen(key))) {

			/* get the priority number from the last character of the nodename */
			prio = nodename[strlen(key)] - '0';
			if (!strcmp(lyd_get_value(iter), "preemptable")) {
				*mask |= (1 << prio);
			}
		}
	}
    sr_release_data(subtree);
    return SR_ERR_OK;

err:
    return rc;
}

static int config_frame_preemption(const char *ifname, const uint32_t value)
{
#ifdef SYSREPO_TSN_TC
	const char *cmd_enable = "ethtool --set-mm %s tx-enabled on pmac-enabled on verify-enabled off tx-min-frag-size %d";
	const char *cmd_disable = "ethtool  --set-mm %s tx-enabled off pmac-enabled off";
	char *host_name = NULL;
	int num_tc = 8;
	char cmd_buff[MAX_CMD_LEN];
	char stc_subcmd[SUB_CMD_LEN];
	int sysret = 0;

	if (strlen(ifname) == 0) {
		return SR_ERR_INVAL_ARG;
	}

	if (value != 0) {
		snprintf(cmd_buff, sizeof(cmd_buff), cmd_enable, ifname, QBU_MIN_FRAG_SIZE);
	} else {
		snprintf(cmd_buff, sizeof(cmd_buff), cmd_disable, ifname);
	}

	LOG_INF("Command: %s", cmd_buff);
	sysret = system(cmd_buff);
	if (!SYSCALL_OK(sysret)) {
		return SR_ERR_INVAL_ARG;
	}

	host_name = get_host_name();
	if (host_name && (strcasestr(host_name, "IMX8MP") ||
	    strcasestr(host_name, "IMX8DXL") ||
	    strcasestr(host_name, "IMX93")) && !strcasestr(ifname, "swp"))
		num_tc = 5;

	snprintf(cmd_buff, MAX_CMD_LEN, "tc qdisc del dev %s root handle 1:", ifname);
	system(cmd_buff);

	snprintf(cmd_buff, MAX_CMD_LEN, "tc qdisc add dev %s root handle 1: mqprio num_tc %d map ", ifname, num_tc);
	for (int i = 0; i < num_tc; i++) {
		snprintf(stc_subcmd, SUB_CMD_LEN, "%d ", i);
		strncat(cmd_buff, stc_subcmd, strlen(stc_subcmd) + 1);
	}
	snprintf(stc_subcmd, SUB_CMD_LEN, "queues ");
	strncat(cmd_buff, stc_subcmd, strlen(stc_subcmd) + 1);
	for (int i = 0; i < num_tc; i++) {
		snprintf(stc_subcmd, SUB_CMD_LEN, "1@%d ", i);
		strncat(cmd_buff, stc_subcmd, strlen(stc_subcmd) + 1);
	}
	snprintf(stc_subcmd, SUB_CMD_LEN, "fp ");
	strncat(cmd_buff, stc_subcmd, strlen(stc_subcmd) + 1);
	for (int i = 0; i < num_tc; i++) {
		if (value & (1 << i))
			snprintf(stc_subcmd, SUB_CMD_LEN, "P ");
		else
			snprintf(stc_subcmd, SUB_CMD_LEN, "E ");
		strncat(cmd_buff, stc_subcmd, strlen(stc_subcmd) + 1);
	}
	snprintf(stc_subcmd, SUB_CMD_LEN, "hw 1");
	strncat(cmd_buff, stc_subcmd, strlen(stc_subcmd) + 1);

	LOG_INF("Command: %s", cmd_buff);
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

/*
module: ietf-interfaces
  +--rw interfaces
     +--rw interface* [name]
        +--rw dot1q:bridge-port
           +--rw preempt-bridge:frame-preemption-parameters {frame-preemption}?
              +--rw preempt-bridge:frame-preemption-status-table
              |  +--rw preempt-bridge:priority0?   frame-preemption-status-enum
              |  +--rw preempt-bridge:priority1?   frame-preemption-status-enum
              |  +--rw preempt-bridge:priority2?   frame-preemption-status-enum
              |  +--rw preempt-bridge:priority3?   frame-preemption-status-enum
              |  +--rw preempt-bridge:priority4?   frame-preemption-status-enum
              |  +--rw preempt-bridge:priority5?   frame-preemption-status-enum
              |  +--rw preempt-bridge:priority6?   frame-preemption-status-enum
              |  +--rw preempt-bridge:priority7?   frame-preemption-status-enum
              +--ro preempt-bridge:hold-advance?                    uint32
              +--ro preempt-bridge:release-advance?                 uint32
              +--ro preempt-bridge:preemption-active?               boolean
              +--ro preempt-bridge:hold-request?                    enumeration
*/

int qbu_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                          const char *module_name, const char *path,
                          sr_event_t event, uint32_t request_id,
                          void *private_ctx)
{
	sr_change_iter_t *iter = NULL;
    const struct lyd_node *node = NULL;
    sr_change_oper_t op;
	int rc = SR_ERR_OK;
    char *xpath;
	char ifname[IF_NAME_MAX_LEN];
	uint32_t mask = 0;

    LOG_INF("Qbu: start callback(%d): %s", (int)event, path);

    rc = asprintf(&xpath, "%s//*", path);
    if (rc < 0) {
        return SR_ERR_CALLBACK_FAILED;
    }

	rc = sr_get_changes_iter(session, xpath, &iter);
    free(xpath);
	if (rc != SR_ERR_OK) {
        sr_session_set_error_message(session, "Getting changes iter failed(%s).",
                sr_strerror(rc));
		return rc;
	}

    do {
        rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        if (rc != SR_ERR_OK) {
            break;
        }
        LOG_INF("node name: %s, opt: %d", LYD_NAME(node), (int)op);

        /* skip the new created node with the default value */
        if ((op == SR_OP_CREATED) && (node->flags & LYD_DEFAULT)) {
            continue;
        }

        if (op == SR_OP_CREATED || op == SR_OP_MODIFIED) {

            ifname[0] = 0;
            strncpy(&ifname[0], get_ifname(node), sizeof(ifname) - 1);

			rc = get_preemptible_queues_mask(session, ifname, &mask);
            if (!rc) {
			    rc = config_frame_preemption(ifname, mask);
            }
            break;
        }
    } while(1);

    sr_free_change_iter(iter);

    if (rc != SR_ERR_OK && rc != SR_ERR_NOT_FOUND) {
        sr_session_set_error_message(session, "Setting frame preemption parameters failed(%s).",
                sr_strerror(rc));
        LOG_ERR("Setting frame preemption parameters failed(%s).", sr_strerror(rc));
		return SR_ERR_CALLBACK_FAILED;
    }

    LOG_INF("Qbu: end callback(%d): %s", (int)event, path);

    return SR_ERR_OK;
}
