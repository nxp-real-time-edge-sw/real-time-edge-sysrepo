/**
 * @file vlan_cfg.c
 * @author hongbo wang
 * @brief Application to configure VLAN based on sysrepo datastore.
 *
 * Copyright 2020, 2025 NXP
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

#include "vlan_cfg.h"

struct item_cfg {
	bool valid;
	bool delflag;
	bool vidflag;
	uint32_t vid;
	char ifname[IF_NAME_MAX_LEN];
	char bridge_name[IF_NAME_MAX_LEN];
};

static struct item_cfg sitem_conf;

static int set_inet_br_vlan(char *ifname, char *bridge_name, int vid, bool addflag)
{
	char cmdstr[MAX_CMD_LEN];
	int ret;

	if (addflag)
		snprintf(cmdstr, MAX_CMD_LEN, "ip link set dev %s master %s; bridge vlan add dev %s vid %d",
			 ifname, bridge_name, ifname, vid);
	else
		snprintf(cmdstr, MAX_CMD_LEN, "bridge vlan del dev %s vid %d",
			 ifname, vid);

    LOG_DBG("Command: %s", cmdstr);
	ret = system(cmdstr);
	if (SYSCALL_OK(ret))
		return 0;
	else
		return -1;
}

#if 0
static int set_inet_vlan(char *ifname, int vid, bool addflag)
{
	int ret = 0;
	int sockfd = 0;
	struct vlan_ioctl_args ifr;
	size_t max_len = sizeof(ifr.device1);

	if (!ifname)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		PRINT("create socket failed! ret:%d", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.u.VID = vid;

	if (addflag) {
		ifr.cmd = ADD_VLAN_CMD;
		snprintf(ifr.device1, max_len, "%s", ifname);
	} else {
		ifr.cmd = DEL_VLAN_CMD;
		snprintf(ifr.device1, max_len, "%s.%d", ifname, vid);
	}

	ret = ioctl(sockfd, SIOCSIFVLAN, &ifr);
	close(sockfd);
	if (ret < 0) {
		PRINT("%s ioctl error! ret:%d", __func__, ret);
		return -3;
	}

	return 0;
}
#endif

static int parse_node(sr_session_ctx_t *session, sr_val_t *value,
			struct item_cfg *conf)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename = NULL;

	if (!session || !value || !conf)
		return rc;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto ret_tag;

	if (!strcmp(nodename, "vid")) {
		if (value->data.uint32_val > 0) {
			conf->vid = value->data.uint32_val;
			conf->vidflag = true;
		}
	} else if (!strcmp(nodename, "name")) {
		if (conf->vidflag) {
			snprintf(conf->ifname, IF_NAME_MAX_LEN, "%s",
						value->data.string_val);
			conf->valid = true;
			conf->delflag = false;
		}
	}

ret_tag:
	return rc;
}

static int parse_item(sr_session_ctx_t *session, char *path,
			struct item_cfg *conf)
{
	size_t i;
	size_t count;
	int rc = SR_ERR_OK;
	sr_val_t *values = NULL;

	rc = sr_get_items(session, path, 0, 0, &values, &count);
	if (rc == SR_ERR_NOT_FOUND) {
		/*
		 * If can't find any item, we should check whether this
		 * container was deleted.
		 */
		if (is_del_oper(session, path)) {
			LOG_WRN("%s was deleted, disable this Instance.", path);
			conf->delflag = true;
			goto cleanup;
		} else {
			LOG_WRN("%s sr_get_items: %s", __func__, sr_strerror(rc));
			return SR_ERR_OK;
		}
	} else if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get items from %s failed", path);
		LOG_ERR("%s sr_get_items: %s", __func__, sr_strerror(rc));
		return rc;
	}

	for (i = 0; i < count; i++) {
		if (values[i].type == SR_LIST_T
		    || values[i].type == SR_CONTAINER_PRESENCE_T)
			continue;

		rc = parse_node(session, &values[i], conf);
	}

cleanup:
	sr_free_values(values, count);

	return rc;
}

static int parse_config(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	char *vid = NULL;
    char *bridge_name = NULL;
	sr_val_t *value = NULL;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	sr_change_iter_t *it = NULL;
	sr_xpath_ctx_t xp_ctx = {0};
	char xpath[XPATH_MAX_LEN] = {0};
	char vid_bak[MAX_VLAN_LEN] = {0};
	struct item_cfg *conf = &sitem_conf;

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", path);

	rc = sr_get_changes_iter(session, xpath, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", xpath);
		LOG_ERR("%s sr_get_changes_iter: %s", __func__, sr_strerror(rc));
		goto cleanup;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {

		value = new_value ? new_value : old_value;
		if (!value)
			continue;

		vid = sr_xpath_key_value(value->xpath, "vlan", "vid", &xp_ctx);

		bridge_name = sr_xpath_key_value(value->xpath, "bridge", "name", &xp_ctx);
        if (bridge_name) {
            strncpy((char *)sitem_conf.bridge_name, bridge_name, IF_NAME_MAX_LEN - 1);
        }

		sr_free_val(old_value);
		sr_free_val(new_value);

		if (!vid)
			continue;

		if (!strcmp(vid, vid_bak))
			continue;
		snprintf(vid_bak, MAX_VLAN_LEN, "%s", vid);

		rc = parse_item(session, xpath, conf);
		if (rc != SR_ERR_OK)
			break;
	}

cleanup:
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

    sr_free_change_iter(it);
	return rc;
}

static int set_config(sr_session_ctx_t *session, bool abort)
{
	int ret = 0;
	int rc = SR_ERR_OK;
	struct item_cfg *conf = &sitem_conf;

	if (abort) {
		memset(conf, 0, sizeof(struct item_cfg));
		return rc;
	}

	if (!conf->valid)
		return rc;

	if (conf->delflag) {
		conf->delflag = false;
		ret = set_inet_br_vlan(conf->ifname, conf->bridge_name, conf->vid, false);
		LOG_DBG("del vlan ifname:%s vid:%d", conf->ifname, conf->vid);
	} else {
		ret = set_inet_br_vlan(conf->ifname, conf->bridge_name, conf->vid, true);
		LOG_DBG("add vlan ifname:%s vid:%d", conf->ifname, conf->vid);
	}

	if (ret != 0)
		return SR_ERR_INVAL_ARG;

	return rc;
}

/*
module: ieee802-dot1q-bridge
  +--rw bridges
     +--rw bridge* [name]
        +--rw component* [name]
           +--rw bridge-vlan
              +--ro version?                   uint16
              +--ro max-vids?                  uint16
              +--ro override-default-pvid?     boolean
              +--ro protocol-template?         dot1qtypes:protocol-frame-format-type {port-and-protocol-based-vlan}?
              +--ro max-msti?                  uint16
              +--rw vlan* [vid]
              |  +--rw vid               dot1qtypes:vlan-index-type
              |  +--rw name?             dot1qtypes:name-type
              |  +--ro untagged-ports*   if:interface-ref
              |  +--ro egress-ports*     if:interface-ref
              +--rw protocol-group-database* [db-index] {port-and-protocol-based-vlan}?
              |  +--rw db-index                 uint16
              |  +--rw frame-format-type?       dot1qtypes:protocol-frame-format-type
              |  +--rw (frame-format)?
              |  |  +--:(ethernet-rfc1042-snap8021H)
              |  |  |  +--rw ethertype?         dot1qtypes:ethertype-type
              |  |  +--:(snap-other)
              |  |  |  +--rw protocol-id?       string
              |  |  +--:(llc-other)
              |  |     +--rw dsap-ssap-pairs
              |  |        +--rw llc-address?   string
              |  +--rw group-id?                uint32
              +--rw vid-to-fid-allocation* [vids]
              |  +--rw vids               dot1qtypes:vid-range-type
              |  +--ro fid?               uint32
              |  +--ro allocation-type?   enumeration
              +--rw fid-to-vid-allocation* [fid]
              |  +--rw fid                uint32
              |  +--ro allocation-type?   enumeration
              |  +--ro vid*               dot1qtypes:vlan-index-type
              +--rw vid-to-fid* [vid]
                 +--rw vid    dot1qtypes:vlan-index-type
                 +--rw fid?   uint32

*/

int vlan_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                           const char *module_name, const char *path,
                           sr_event_t event, uint32_t request_id,
                           void *private_ctx)
{
	int rc = SR_ERR_OK;

    LOG_DBG("bridge-vlan: start callback(%d): %s", (int)event, path);

	memset(&sitem_conf, 0, sizeof(struct item_cfg));
	rc = parse_config(session, path);
	if (rc == SR_ERR_OK) {
		rc = set_config(session, false);
	}

    if (rc) {
        return SR_ERR_CALLBACK_FAILED;
    } else {
        LOG_DBG("bridge-vlan: end callback(%d): %s", (int)event, path);
        return SR_ERR_OK;
    }
}
