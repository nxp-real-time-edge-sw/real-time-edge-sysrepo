/**
 * @file speed.c
 * @author Jianchao Wang
 * @brief Application to get the port speed based on sysrepo datastore.
 *
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

#define PLG_NAME    "speed"

#include <libyang/libyang.h>
#include "speed.h"

#define SPEED_BUFFER_SIZE (64U)
#define SPEED_PATH        "/ietf-interfaces:interfaces/interface[name='%s']/speed"

static int speed_string_info(const char *cmd, char *buffer)
{
    FILE *fp;
    char *key_pos;

    if (!cmd || !buffer)
        return SR_ERR_INVAL_ARG;

    fp = popen(cmd, "r");
    if (!fp) {
        LOG_ERR("Failed to execute command: %s", cmd);
        return SR_ERR_SYS;
    }

    fread(buffer, 1, SPEED_BUFFER_SIZE, fp);
    pclose(fp);

    key_pos = strstr(buffer, "Mb/s");
    if (key_pos != NULL) {
        memset(key_pos, '0', 6);
        return SR_ERR_OK;
    }

    return SR_ERR_NOT_FOUND;
}

static void get_port_speed(struct lyd_node *parent, const struct ly_ctx *ly_ctx, char *port_name)
{
    int rc;
    char *cmd;
    char *speed_path;
    char speed[SPEED_BUFFER_SIZE] = {0};

    rc = asprintf(&cmd, "ethtool %s | grep -i speed | awk '{print $2}' 2>&1", port_name);
    if (rc < 0)
        return;

    rc = speed_string_info(cmd, speed);
    if (rc != SR_ERR_OK)
        goto error;

    rc = asprintf(&speed_path, SPEED_PATH, port_name);
    if (rc < 0)
        goto error;

    lyd_new_path(parent, ly_ctx, speed_path, speed, 0, NULL);
    free(speed_path);

error:
    free(cmd);
}

static void get_all_ports_speed(struct lyd_node *parent, const struct ly_ctx *ly_ctx)
{
    FILE *fp;
    char *port = NULL;
    size_t len = 0;
    ssize_t read;
    const char *cmd = "ls /sys/class/net 2>&1";

    fp = popen(cmd, "r");
    if (fp == NULL) {
        LOG_ERR("Failed to execute command: %s", cmd);
        return;
    }

    while ((read = getline(&port, &len, fp)) > 0) {
        if (port[read - 1] == '\n')
            port[read - 1] = '\0';

        get_port_speed(parent, ly_ctx, port);
    }

    free(port);
    pclose(fp);
}

int speed_oper_subscribe_cb(sr_session_ctx_t *session, uint32_t sub_id,
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

    rc = lyd_new_path(NULL, ly_ctx, SPEED_ROOT_PATH, NULL, 0, &root);
    if (rc)
        goto error;

    if (strstr(request_xpath, "speed") != NULL) {
        rc = sscanf(request_xpath, "%*[^']'%[^']']/speed", port_name);
        if (rc == 1)
            get_port_speed(root, ly_ctx, port_name);
        else
            get_all_ports_speed(root, ly_ctx);
    }

    *parent = root;
    return SR_ERR_OK;

error:
    return rc;
}