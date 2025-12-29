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

#define PLG_NAME    "lldp"

#include <sysrepo.h>
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <time.h>

#include "common.h"

#define MODULE_NAME_LLDP    "ieee802-dot1ab-lldp"
#define LLDP_ROOT_PATH      "/ieee802-dot1ab-lldp:lldp"
#define LLDP_PORT_PATH      LLDP_ROOT_PATH "/port"

#define LLDP_BUFFER_SIZE    (32 * 1024U)

#define SECONDS_PER_MINUTE      (60U)
#define SECONDS_PER_HOUR        (60 * SECONDS_PER_MINUTE)
#define SECONDS_PER_DAY         (24 * SECONDS_PER_HOUR)

static sr_subscription_ctx_t *subscription = NULL;

static const char *lldp_convert_admin_status(const char *status)
{
    if (!strcmp(status, "RX and TX")) {
        return "tx-and-rx";
    } else if (!strcmp(status, "TX only")) {
        return "tx-only";
    } else if (!strcmp(status, "RX only")) {
        return "rx-only";
    } else {
        return "disabled";
    }
}

static const char *lldp_get_id_subtype(const char *type)
{
    if (type == NULL)
        return NULL;

    if (!strcmp(type, "mac")) {
        return "mac-address";
    } else if (!strcmp(type, "ifname")) {
        return "interface-name";
    } else if (!strcmp(type, "ifalias")) {
        return "interface-alias";
    } else if (!strcmp(type, "local")) {
        return "local";
    } else if (!strcmp(type, "ip")) {
        return "network-address";
    } else {
        return NULL;
    }
}

static void lldp_get_ieee_mac_address(char *id)
{
    size_t len;

    len = strlen(id);
    for (int i = 0; i < len; i++) {
        if (id[i] == ':') {
            id[i] = '-';
        } else {
            id[i] = toupper(id[i]);
        }
    }
}

static int lldp_get_management_address(struct lyd_node *parent, const cJSON *chassis, const char *node_name)
{
    struct lyd_node *mgmt_node = NULL;
    uint32_t ipv4;
    char ipv4_val[32];
    int ret = 0;
    cJSON *item;

    cJSON *mgmt_ip = cJSON_GetObjectItem(chassis, "mgmt-ip");
    if (mgmt_ip == NULL)
        return SR_ERR_NOT_FOUND;

    cJSON_ArrayForEach(item, mgmt_ip) {
        char *val = cJSON_GetStringValue(cJSON_GetObjectItem(item, "value"));
        ret = inet_pton(AF_INET, val, &ipv4);
        if (ret > 0)
            break;
    }

    if (ret == 0)
        return SR_ERR_NOT_FOUND;

    const char *address_subtype = "ietf-routing:ipv4";
    snprintf(ipv4_val, sizeof(ipv4_val), "%08X", htonl(ipv4));
    lyd_new_list(parent, NULL, node_name, 0, &mgmt_node,
                 address_subtype, ipv4_val);

    return SR_ERR_OK;
}

static void lldp_get_port_id_and_desc(struct lyd_node *parent, const cJSON *port)
{
    cJSON *id = cJSON_GetObjectItem(port, "id");
    if (id != NULL) {
        char *type = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(id, 0), "type"));

        const char *port_id_subtype = lldp_get_id_subtype(type);
        if (port_id_subtype != NULL) {
            lyd_new_path(parent, NULL, "port-id-subtype", port_id_subtype, 0, NULL);

            char *value = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(id, 0), "value"));
            if (value != NULL) {
                if (!strcmp(port_id_subtype, "mac-address"))
                    lldp_get_ieee_mac_address(value);

                lyd_new_path(parent, NULL, "port-id", value, 0, NULL);
            }
        }
    }

    cJSON *descr = cJSON_GetObjectItem(port, "descr");
    char *descr_val = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(descr, 0), "value"));
    if (descr_val != NULL) {
        lyd_new_path(parent, NULL, "port-desc", descr_val, 0, NULL);
    }
}

static void lldp_get_interface_mac_address(const char *ifname, char *ieee_mac, int length)
{
    struct ifreq ifr;
    uint8_t *mac;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_addr.sa_family = AF_INET;
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
    snprintf(ieee_mac, length, "%02X-%02X-%02X-%02X-%02X-%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(fd);
}

static int lldp_sys_json_info(const char *cmd, char *buffer, cJSON **output)
{
    FILE *fptr;

    fptr = popen(cmd, "r");
    if (fptr == NULL) {
        LOG_ERR("Failed to execute \"%s\"", cmd);
        return SR_ERR_SYS;
    }

    fread(buffer, 1, LLDP_BUFFER_SIZE, fptr);
    pclose(fptr);

    *output = cJSON_Parse(buffer);
    if (*output == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            LOG_ERR("cJSON Error: %s", error_ptr);
        }
        return SR_ERR_INVAL_ARG;
    }

    return SR_ERR_OK;
}

static void lldp_age_to_time_mark(const char *age, char *time_mark, int length)
{
    struct timespec now;
    int days;
    int hours;
    int minutes;
    int seconds;
    time_t offset;
    int ret;

    clock_gettime(CLOCK_MONOTONIC, &now);

    ret = sscanf(age, "%d days, %02d:%02d:%02d", &days, &hours, &minutes, &seconds);
    if (ret != 4) {
        ret = sscanf(age, "%d day, %02d:%02d:%02d", &days, &hours, &minutes, &seconds);
    }

    if (ret != 4) {
        days = 0;
        hours = 0;
        minutes = 0;
        seconds = 0;
    }

    offset = days * SECONDS_PER_DAY + hours * SECONDS_PER_HOUR +
                minutes * SECONDS_PER_MINUTE + seconds;

    snprintf(time_mark, length, "%lld", (long long)(now.tv_sec - offset) * 100);
}

static int lldp_get_system_data(struct lyd_node *parent, const cJSON *chassis)
{
    cJSON *id;
    char *type;
    char *value;

    id = cJSON_GetObjectItem(chassis, "id");
    if (id == NULL) {
        return SR_ERR_NOT_FOUND;
    }

    /* chassis-id-subtype and chassis-id */
    type = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(id, 0), "type"));
    const char *chassis_id_subtype = lldp_get_id_subtype(type);
    if (chassis_id_subtype != NULL) {

        lyd_new_path(parent, NULL, "chassis-id-subtype", chassis_id_subtype, 0, NULL);

        value = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(id, 0), "value"));
        if (value != NULL) {
            if (!strcmp(chassis_id_subtype, "mac-address"))
                lldp_get_ieee_mac_address(value);

            lyd_new_path(parent, NULL, "chassis-id", value, 0, NULL);
        }
    }

    /* system-name */
    cJSON *name = cJSON_GetObjectItem(chassis, "name");
    char *system_name = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(name, 0), "value"));
    if (system_name != NULL) {
        lyd_new_path(parent, NULL, "system-name", system_name, 0, NULL);
    }

    /* system-description */
    cJSON *system_descr = cJSON_GetObjectItem(chassis, "descr");
    char *system_description = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(system_descr, 0), "value"));
    if (system_description != NULL) {
        lyd_new_path(parent, NULL, "system-description", system_description, 0, NULL);
    }

    return SR_ERR_OK;
}

static int lldp_get_remote_systems_data(struct lyd_node *parent, const char *if_name)
{
    const char *cmd_fmt = "lldpcli -f json show neighbors ports %s  2>&1";
    struct lyd_node *remote_systems_data_node;
    char *command;
    cJSON *output;
    cJSON *interface;
    char *buffer;
    char time_mark[32];
    int rc = SR_ERR_OK;

    asprintf(&command, cmd_fmt, if_name);

    buffer = (char *)malloc(LLDP_BUFFER_SIZE);
    memset(buffer, 0, LLDP_BUFFER_SIZE);

    rc = lldp_sys_json_info(command, buffer, &output);
    free(command);
    if (rc) {
        goto error;
    }

    cJSON *lldp0 = cJSON_GetArrayItem(cJSON_GetObjectItem(output, "lldp"), 0);
    cJSON *interfaces = cJSON_GetObjectItem(lldp0, "interface");

    cJSON_ArrayForEach(interface, interfaces) {

        char *rid = cJSON_GetStringValue(cJSON_GetObjectItem(interface, "rid"));
        if (rid == NULL)
            goto error;

        char *age = cJSON_GetStringValue(cJSON_GetObjectItem(interface, "age"));
        if (age == NULL)
            goto error;

        lldp_age_to_time_mark(age, time_mark, sizeof(time_mark) - 1);

        lyd_new_list(parent, NULL, "remote-systems-data", 0,
                     &remote_systems_data_node, time_mark, rid);

        cJSON *chassis0 = cJSON_GetArrayItem(cJSON_GetObjectItem(interface, "chassis"), 0);
        if (chassis0 != NULL)
            lldp_get_system_data(remote_systems_data_node, chassis0);

        cJSON *port = cJSON_GetArrayItem(cJSON_GetObjectItem(interface, "port"), 0);
        if (port != NULL)
            lldp_get_port_id_and_desc(remote_systems_data_node, port);

        lldp_get_management_address(remote_systems_data_node, chassis0, "management-address");
    }

error:
    cJSON_Delete(output);
    free(buffer);
    return rc;
}

static int lldp_get_port_info(struct lyd_node *parent, const cJSON *interface)
{
    struct lyd_node *port_node = NULL;
    char *if_name;
    char dst_mac[32];

    if_name = cJSON_GetStringValue(cJSON_GetObjectItem(interface, "name"));
    if (if_name == NULL)
        return SR_ERR_NOT_FOUND;

    memset(dst_mac, 0, sizeof(dst_mac));
    lldp_get_interface_mac_address(if_name, dst_mac, sizeof(dst_mac) - 1);

    lyd_new_list(parent, NULL, "port", 0, &port_node, if_name, dst_mac);

    cJSON *status = cJSON_GetArrayItem(cJSON_GetObjectItem(interface, "status"), 0);
    if (status != NULL) {
        char *status_val = cJSON_GetStringValue(cJSON_GetObjectItem(status, "value"));
        if (status_val != NULL) {
            lyd_new_path(port_node, NULL, "admin-status",
                    lldp_convert_admin_status(status_val), 0, NULL);
        }
    }

    cJSON *chassis = cJSON_GetArrayItem(cJSON_GetObjectItem(interface, "chassis"), 0);
    if (chassis != NULL) {
        lldp_get_management_address(port_node, chassis, "management-address-tx-port");
    }

    cJSON *port = cJSON_GetArrayItem(cJSON_GetObjectItem(interface, "port"), 0);
    if (port != NULL)
        lldp_get_port_id_and_desc(port_node, port);

    lldp_get_remote_systems_data(port_node, if_name);

    return SR_ERR_OK;
}

static int lldp_get_interfaces(struct lyd_node *parent)
{
    const char *cmd = "lldpcli -f json show interfaces 2>&1";
    cJSON *output = NULL;
    cJSON *interface = NULL;
    char *buffer;
    int rc = SR_ERR_OK;

    buffer = (char *)malloc(LLDP_BUFFER_SIZE);
    memset(buffer, 0, LLDP_BUFFER_SIZE);

    rc = lldp_sys_json_info(cmd, buffer, &output);
    if (rc) {
        goto error;
    }

    cJSON *lldp = cJSON_GetObjectItem(output, "lldp");
    cJSON *interfaces = cJSON_GetObjectItem(cJSON_GetArrayItem(lldp, 0), "interface");

    cJSON_ArrayForEach(interface, interfaces) {
        lldp_get_port_info(parent, interface);
    }

error:
    cJSON_Delete(output);
    free(buffer);
    return rc;
}

static int lldp_get_local_system_data(struct lyd_node *parent)
{
    struct lyd_node *local_system_data_node;
    const char *cmd = "lldpcli -f json show chassis details 2>&1";
    char *buffer;
    cJSON *sysinf;
    int rc = SR_ERR_OK;

    buffer = (char *)malloc(LLDP_BUFFER_SIZE);
    memset(buffer, 0, LLDP_BUFFER_SIZE);

    rc = lldp_sys_json_info(cmd, buffer, &sysinf);
    if (rc) {
        goto error;
    }

    rc = lyd_new_path(parent, NULL, "local-system-data", NULL, 0, &local_system_data_node);
    if (rc) {
        goto error;
    }

    cJSON *local_chassis0 = cJSON_GetArrayItem(cJSON_GetObjectItem(sysinf, "local-chassis"), 0);
    cJSON *chassis0 = cJSON_GetArrayItem(cJSON_GetObjectItem(local_chassis0, "chassis"), 0);

    rc = lldp_get_system_data(local_system_data_node, chassis0);

error:
    cJSON_Delete(sysinf);
    free(buffer);
    return rc;
}

static int lldp_oper_subscribe_cb(sr_session_ctx_t *session, uint32_t sub_id,
        const char *module_name,const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *root;
    int rc;

    LOG_INF("lldp: start oper callback at %s; request xpath: %s", path, request_xpath);

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));
    sr_release_context(sr_session_get_connection(session));

    rc = lyd_new_path(NULL, ly_ctx, LLDP_ROOT_PATH, NULL, 0, &root);
    if (rc != SR_ERR_OK)
        return SR_ERR_CALLBACK_FAILED;

    rc = lldp_get_local_system_data(root);
    if (rc != SR_ERR_OK)
        return SR_ERR_CALLBACK_FAILED;

    rc = lldp_get_interfaces(root);
    if (rc != SR_ERR_OK)
        return SR_ERR_CALLBACK_FAILED;

    *parent = root;
    return SR_ERR_OK;
}

static bool lldp_node_updated(const struct lyd_node *node)
{
    struct lyd_meta *m;

    while (node != NULL) {

        if ((m = lyd_find_meta(node->meta, NULL, "yang:operation"))) {

            if (!strcmp(lyd_get_meta_value(m), "create") ||
                    !strcmp(lyd_get_meta_value(m), "replace")) {
                return true;
            }
        }
        node = lyd_parent(node); 
    }
    return false;
}

static const char *lldp_get_updated_value(const struct lyd_node *diff,
                                          const char *path)
{
    struct lyd_node *node = NULL;
    int lyret;

    lyret = lyd_find_path(diff, path, 0, &node);
    if (!lyret && !(node->flags & LYD_DEFAULT)) {
        if (lldp_node_updated(node)) {
            return lyd_get_value(node);
        }
    }

    return NULL;
}

static int lldp_parse_port(const int fd, const struct lyd_node *tree)
{
    const char *port_name;
    const char *str_value;

    port_name = lyd_get_value(lyd_child(tree));
    str_value = lldp_get_updated_value(tree, LLDP_PORT_PATH "/admin-status");
    if (str_value != NULL) {
        dprintf(fd, "configure port %s lldp status %s\n", port_name, str_value);
    }

    return SR_ERR_OK;
}

static int lldp_do_update(char *fname)
{
    const char cmd_fmt[] = "FNAME=%s; cat $FNAME; lldpcli -c $FNAME  2>&1";
    char cmd_buf[64];
	int sysret = 0;

    sprintf(cmd_buf, cmd_fmt, fname);
    LOG_INF("%s", cmd_buf);

    sysret = system(cmd_buf);
	if (!SYSCALL_OK(sysret)) {
        return SR_ERR_CALLBACK_FAILED;
	}

    return SR_ERR_OK;
}

static int lldp_change_subscribe_cb(sr_session_ctx_t *session, uint32_t sub_id,
        const char *module_name, const char *path, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    const struct lyd_node *node = NULL;
    struct lyd_node *match = NULL;
	sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    int rc = SR_ERR_CALLBACK_FAILED;
    char name_buff[] = "/tmp/lldp-XXXXXX";
    const char *str_value;
    char *xpath;
    int lyret = 0;
    int fd = 0;

    LOG_INF("start callback(%d): %s", (int)event, path);

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

    fd = mkstemp(name_buff);
    if (fd < 0) {
        LOG_ERR("Failed to create a temporary file (%s).", strerror(errno));
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

        str_value = lldp_get_updated_value(node, LLDP_ROOT_PATH "/message-tx-hold-multiplier");
        if (str_value != NULL) {
            dprintf(fd, "configure lldp tx-hold %s\n", str_value);
        }

        str_value = lldp_get_updated_value(node, LLDP_ROOT_PATH "/message-tx-interval");
        if (str_value != NULL) {
            dprintf(fd, "configure lldp tx-interval %s\n", str_value);
        }

        lyret = lyd_find_path(node, LLDP_ROOT_PATH "/port", 0, &match);
        if (!lyret) {
            rc = lldp_parse_port(fd, match);
            if (rc) {
                LOG_ERR("Failed to parse the port configuration (%s).", sr_strerror(rc));
                goto error;
            }
        }

    } while(1);

    rc = lldp_do_update(name_buff);

error:
    unlink(name_buff);
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
    char *xpath = LLDP_ROOT_PATH;
    int rc;

    rc = sr_module_change_subscribe(session, MODULE_NAME_LLDP, xpath,
                                    lldp_change_subscribe_cb, NULL, 0,
                                    SR_SUBSCR_DONE_ONLY, &subscription);
    if (rc != SR_ERR_OK) {
        LOG_ERR("Failed to subscribe for \"%s\" (%s).",
                xpath, sr_strerror(rc));
        goto error;
    }
    LOG_INF("Subscribed changes for %s", xpath);

    sr_session_switch_ds(session, SR_DS_OPERATIONAL);

    rc = sr_oper_get_subscribe(session, MODULE_NAME_LLDP, xpath,
                               lldp_oper_subscribe_cb, NULL, 0, &subscription);
    if (rc != SR_ERR_OK) {
        LOG_ERR("Failed to subscribe operational data for \"%s\" (%s).",
                xpath, sr_strerror(rc));
        goto error;
    }
    LOG_INF("Subscribed operational data for %s", xpath);

    sr_session_switch_ds(session, SR_DS_RUNNING);

    return SR_ERR_OK;

error:
    sr_unsubscribe(subscription);
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *running_session, void *private_data)
{
	sr_unsubscribe(subscription);

    LOG_INF("LLDP plugin cleanup finished.");
}
