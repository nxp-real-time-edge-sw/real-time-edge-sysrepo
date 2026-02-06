/**
 * Copyright 2026 NXP
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

#define PLG_NAME    "hardware"

#include <sysrepo.h>
#include <cjson/cJSON.h>

#include "common.h"

#define MODULE_NAME_PTP    "ietf-hardware"
#define HW_ROOT_PATH       "/ietf-hardware:hardware"

#define HW_BUFFER_SIZE     (32 * 1024U)

static sr_subscription_ctx_t *subscription = NULL;

static int lshw_json_info(const char *cmd, char *buffer, cJSON **output)
{
    FILE *fptr;

    fptr = popen(cmd, "r");
    if (fptr == NULL) {
        LOG_ERR("Failed to execute \"%s\"", cmd);
        return SR_ERR_SYS;
    }

    fread(buffer, 1, HW_BUFFER_SIZE, fptr);
    pclose(fptr);

    *output = cJSON_Parse(buffer);
    if (*output == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
            LOG_ERR("cJSON Error: %s", error_ptr);

        return SR_ERR_INVAL_ARG;
    }

    return SR_ERR_OK;
}

static void hw_get_component_info(struct lyd_node *parent, cJSON *component, char *port_name)
{
    struct lyd_node *component_node = NULL;
    char *firmware;

    lyd_new_list(parent, NULL, "component", 0, &component_node, port_name);
    lyd_new_path(component_node, NULL, "class", "iana-hardware:port", 0, NULL);

    char *description = cJSON_GetStringValue(cJSON_GetObjectItem(component, "description"));
    if (description != NULL)
        lyd_new_path(component_node, NULL, "description", description, 0, NULL);

    char *vendor = cJSON_GetStringValue(cJSON_GetObjectItem(component, "vendor"));
    if (vendor != NULL)
        lyd_new_path(component_node, NULL, "mfg-name", vendor, 0, NULL);

    char *version = cJSON_GetStringValue(cJSON_GetObjectItem(component, "version"));
    if (version != NULL)
        lyd_new_path(component_node, NULL, "hardware-rev", version, 0, NULL);

    char *serial = cJSON_GetStringValue(cJSON_GetObjectItem(component, "serial"));
    if (serial != NULL)
        lyd_new_path(component_node, NULL, "serial-num", serial, 0, NULL);

    cJSON *cfg = cJSON_GetObjectItem(component, "configuration");
    char *driver = cJSON_GetStringValue(cJSON_GetObjectItem(cfg, "driver"));
    char *driverversion = cJSON_GetStringValue(cJSON_GetObjectItem(cfg, "driverversion"));
    if ((driver != NULL) && (driverversion != NULL)) {
        if (asprintf(&firmware, "%s:%s", driver, driverversion) < 0)
            return;

        lyd_new_path(component_node, NULL, "firmware-rev", firmware, 0, NULL);
        free(firmware);
    }
}

static void hw_get_component_port(struct lyd_node *parent, char *name)
{
    char *buffer;
    cJSON *output;
    cJSON *component = NULL;
    const char *cmd = "lshw -json -c network 2>&1";
    char *port_name = NULL;

    buffer = (char *)malloc(HW_BUFFER_SIZE);
    memset(buffer, 0, HW_BUFFER_SIZE);

    if (lshw_json_info(cmd, buffer, &output))
        goto error;

    cJSON_ArrayForEach(component, output) {
        cJSON *logicalname = cJSON_GetObjectItem(component, "logicalname");
        if (cJSON_IsArray(logicalname)) {
            cJSON *lname = NULL;
            cJSON_ArrayForEach(lname, logicalname) {
                port_name = cJSON_GetStringValue(lname);
                if ((port_name == NULL) || ((name != NULL) && strcmp(port_name, name)))
                    continue;

                hw_get_component_info(parent, component, port_name);
            }
        } else {
            port_name = cJSON_GetStringValue(logicalname);
            if ((port_name == NULL) || ((name != NULL) && strcmp(port_name, name)))
                continue;

            hw_get_component_info(parent, component, port_name);
        }
    }

error:
    cJSON_Delete(output);
    free(buffer);
}

static int hw_oper_subscribe_cb(sr_session_ctx_t *session, uint32_t sub_id,
        const char *module_name,const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *root;
    int rc;
    char port_name[16] = {0};

    LOG_INF("start oper callback at %s; request xpath: %s", path, request_xpath);

    ly_ctx = sr_acquire_context(sr_session_get_connection(session));
    sr_release_context(sr_session_get_connection(session));

    rc = lyd_new_path(NULL, ly_ctx, HW_ROOT_PATH, NULL, 0, &root);
    if (rc)
        goto error;

    if (strstr(request_xpath, "component") != NULL) {
        rc = sscanf(request_xpath, "%*[^']'%[^']']", port_name);
        if (rc == 1)
            hw_get_component_port(root, port_name);
        else
            hw_get_component_port(root, NULL);
    }

    *parent = root;
    return SR_ERR_OK;

error:
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
    char *xpath = HW_ROOT_PATH;
    int rc = 0;

    sr_session_switch_ds(session, SR_DS_OPERATIONAL);

    rc = sr_oper_get_subscribe(session, MODULE_NAME_PTP, xpath,
                               hw_oper_subscribe_cb, NULL, 0, &subscription);
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

    LOG_INF("Hardware plugin cleanup finished.");
}
