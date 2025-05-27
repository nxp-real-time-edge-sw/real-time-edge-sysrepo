/**
 * Copyright 2025 NXP
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

#define PLG_NAME    "TSN"

#include "common.h"
#include "mac_cfg.h"
#include "vlan_cfg.h"
#include "ip_cfg.h"
#include "brtc_cfg.h"
#include "qbu.h"
#include "qbv.h"
#include "qci.h"
#include "cb_streamid.h"
#include "cb.h"

static sr_subscription_ctx_t *subscription = NULL;

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
    char *mod_name = NULL;
    char *xpath = NULL;
    int rc;

	/* Init tsn mutex */
	init_tsn_mutex();

#ifdef SYSREPO_TSN_TC
	qci_init_para();
#endif

    /* Subscribe to the ipv4 subtree */
    mod_name = "ietf-interfaces";
    xpath = "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4";
    SR_CONFIG_SUBSCR(mod_name, xpath, ip_subtree_change_cb, 0);

    /* Subscribe to QBU subtree */
	xpath = BRIDGE_PORT_XPATH "/ieee802-dot1q-preemption-bridge:frame-preemption-parameters";
    SR_CONFIG_SUBSCR(mod_name, xpath, qbu_subtree_change_cb, 0);

	/* Subscribe to QBV subtree */
	xpath = BRIDGE_PORT_XPATH "/ieee802-dot1q-sched-bridge:gate-parameter-table";
    SR_CONFIG_SUBSCR(mod_name, xpath, qbv_subtree_change_cb, 0);

    mod_name = "ieee802-dot1q-bridge";
    /* Subscribe to VLAN_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/bridge-vlan";
    SR_CONFIG_SUBSCR(mod_name, xpath, vlan_subtree_change_cb, 1);

    /* Subscribe to MAC_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/address";
    SR_CONFIG_SUBSCR(mod_name, xpath, mac_subtree_change_cb, 2);

    /* Subscribe to QCI-Stream-Filter subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/ieee802-dot1q-psfp-bridge:stream-filters";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_sf_subtree_change_cb, 0);

    /* Subscribe to QCI-Stream-Gate subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/ieee802-dot1q-psfp-bridge:stream-gates";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_sg_subtree_change_cb, 0);

    /* Subscribe to QCI-Flow-Meter subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/ieee802-dot1q-psfp-bridge:flow-meters";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_fm_subtree_change_cb, 0);

    /* Subscribe to BR_TC_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/nxp-bridge-vlan-tc-flower:traffic-control";
    SR_CONFIG_SUBSCR(mod_name, xpath, brtc_subtree_change_cb, 0);

    mod_name = "ieee802-dot1cb-stream-identification";
    /* Subscribe to CB-StreamID subtree */
    xpath = "/ieee802-dot1cb-stream-identification:stream-identity";
    SR_CONFIG_SUBSCR(mod_name, xpath, cb_streamid_subtree_change_cb, 0);

    mod_name = "ieee802-dot1cb-frer";
    /* Subscribe to CB */
    xpath = "/ieee802-dot1cb-frer:frer";
    SR_CONFIG_SUBSCR(mod_name, xpath, cb_subtree_change_cb, 0);

    LOG_INF("TSN plugin initialization finished.");
    return SR_ERR_OK;

error:
	destroy_tsn_mutex();
    sr_unsubscribe(subscription);
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *running_session, void *private_data)
{
	destroy_tsn_mutex();
	sr_unsubscribe(subscription);

    LOG_INF("TSN plugin cleanup finished.");
}
