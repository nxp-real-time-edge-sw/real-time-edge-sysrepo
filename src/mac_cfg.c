/**
 * @file mac_cfg.c
 * @author hongbo wang
 * @brief Application to configure mac address based on sysrepo datastore.
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

#include "mac_cfg.h"

struct item_cfg {
	bool valid;
	char ifname[IF_NAME_MAX_LEN];
	char mac_addr[MAC_ADDR_LEN];
};
static struct item_cfg sitem_conf;

static int set_inet_mac(const char *ifname, const char *mac_addr)
{
    char *command = NULL;
    int rc;
    const char *cmd_fmt = "ifname=%s; "
                          "ip link add name ${ifname} type bridge; "
                          "ip link set dev ${ifname} address %s; "
                          "ip link set dev ${ifname} up";

    rc = asprintf(&command, cmd_fmt, ifname, mac_addr);
    if (rc < 0) {
		return SR_ERR_SYS;
    }

    rc = system(command);
	if (!SYSCALL_OK(rc)) {
        LOG_DBG("Command failed: %s", command);
        free(command);
		return SR_ERR_INVAL_ARG;
	}

    LOG_DBG("Command: %s", command);
    free(command);
    return SR_ERR_OK;
}

static int set_config(struct item_cfg *conf)
{
	if (!conf->valid)
		return SR_ERR_INVAL_ARG;

    /* replace "-" with ":" in the MAC address */
    for (int i = 0; i < strlen(conf->mac_addr); i++) {
        if (conf->mac_addr[i] == '-') {
            conf->mac_addr[i] = ':';
        }
    }

	return set_inet_mac((char *)conf->ifname, (char *)conf->mac_addr);
}

static int parse_node(sr_session_ctx_t *session, sr_val_t *value,
			struct item_cfg *conf)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *strval = NULL;
	char *nodename = NULL;

	if (!session || !value || !conf)
		return rc;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto ret_tag;

	strval = value->data.string_val;

	if (!strcmp(nodename, "address")) {
		if (!conf->valid) {
			snprintf(conf->mac_addr, MAC_ADDR_LEN, "%s", strval);
			conf->valid = true;
		}
	} else if (!strcmp(nodename, "name")) {
		if (!conf->valid)
			snprintf(conf->ifname, IF_NAME_MAX_LEN, "%s", strval);
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
	char *ifname = NULL;
	sr_val_t *value = NULL;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	sr_change_iter_t *it = NULL;
	sr_xpath_ctx_t xp_ctx = {0};
	char xpath[XPATH_MAX_LEN] = {0};
	char ifname_bak[IF_NAME_MAX_LEN] = {0};
	struct item_cfg *conf = &sitem_conf;

	memset(conf, 0, sizeof(struct item_cfg));

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", BRIDGE_XPATH);

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

		ifname = sr_xpath_key_value(value->xpath, "bridge", "name", &xp_ctx);

		sr_free_val(old_value);
		sr_free_val(new_value);

		if (!ifname)
			continue;

		if (!strcmp(ifname, ifname_bak))
			continue;
		snprintf(ifname_bak, IF_NAME_MAX_LEN, "%s", ifname);
		snprintf(conf->ifname, IF_NAME_MAX_LEN, "%s", ifname);

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

int mac_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                          const char *module_name, const char *path,
                          sr_event_t event, uint32_t request_id,
                          void *private_ctx)
{
	int rc = SR_ERR_OK;

    LOG_DBG("bridge/address: start callback(%d): %s", (int)event, path);

	rc = parse_config(session, path);
	if (rc == SR_ERR_OK) {
		rc = set_config(&sitem_conf);
	}

    if (rc) {
        return SR_ERR_CALLBACK_FAILED;
    } else {
        return SR_ERR_OK;
    }
}
