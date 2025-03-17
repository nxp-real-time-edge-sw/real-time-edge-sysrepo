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

#include <sysrepo.h>

#include "common.h"

#define MODULE_NAME_PTP     "ieee1588-ptp-tt"
#define PTP_ROOT_PATH       "/ieee1588-ptp-tt:ptp"
#define PTP_INSTANCES_PATH  "/ieee1588-ptp-tt:ptp/instances"

#define PTP_CONFIG_FILE     "/etc/ptp4l_cfg/instance%d.cfg"

#define PTP_BUFFER_SIZE     (16 * 1024U)


/* Add extra parameters undefined in YANG model */
static void ptp_add_extra_config(FILE *fptr)
{
    fprintf(fptr, "min_neighbor_prop_delay    -20000000\n");
    fprintf(fptr, "assume_two_step            1\n");
    fprintf(fptr, "follow_up_info             1\n");
    fprintf(fptr, "transportSpecific          1\n");
    fprintf(fptr, "tx_timestamp_timeout       20\n");
}

static int ptp_change_subscribe_cb(sr_session_ctx_t *session, uint32_t sub_id,
        const char *module_name, const char *path, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    sr_data_t *data = NULL;
    struct lyd_node *instance= NULL;
    struct lyd_node *ports= NULL;
    struct lyd_node *port= NULL;
    struct lyd_node *match = NULL;
    int lyret = 0;
    int rc = SR_ERR_CALLBACK_FAILED;
    int instance_index;
    char fname[128];
    char *xpath;
    FILE *fptr;

    LOG_DBG("ptp: start callback(%d): %s", (int)event, path);

    rc = asprintf(&xpath, PTP_INSTANCES_PATH "/*");
    if (rc < 0) {
        return SR_ERR_CALLBACK_FAILED;
    }

    rc = sr_get_subtree(session, xpath, 0, &data);
    free(xpath);
    if (rc || data == NULL) {
        return SR_ERR_CALLBACK_FAILED;
    }

    instance = data->tree;
    instance_index = atoi(lyd_get_value(lyd_child(instance)));

    sprintf(fname, PTP_CONFIG_FILE, instance_index);
    fptr = fopen(fname, "w+");
    if (fptr == NULL) {
        LOG_ERR("Failed to create the config file (%s).", strerror(errno));
        sr_release_data(data);
        return SR_ERR_CALLBACK_FAILED;
    }

    fprintf(fptr, "[global]\n");

    lyret = lyd_find_path(instance, "path-trace-ds", 0, &match);
    if (!lyret) {
        if (!strcmp(lyd_get_value(lyd_child(match)), "true")) {
            fprintf(fptr, "path_trace_enabled %8d\n", 1);
        }
    }

    lyret = lyd_find_path(instance, "default-ds/priority1", 0, &match);
    if (!lyret) {
        fprintf(fptr, "priority1 %8s\n", lyd_get_value(match));
    }

    lyret = lyd_find_path(instance, "default-ds/priority2", 0, &match);
    if (!lyret) {
        fprintf(fptr, "priority2 %8s\n", lyd_get_value(match));
    }

    lyret = lyd_find_path(instance, "default-ds/domain-number", 0, &match);
    if (!lyret) {
        fprintf(fptr, "domainNumber %8s\n", lyd_get_value(match));
    }

    lyret = lyd_find_path(instance, "default-ds/time-receiver-only", 0, &match);
    if (!lyret && !strcmp(lyd_get_value(match), "true")) {
        fprintf(fptr, "domainNumber %8d\n", 1);
    }

    lyret = lyd_find_path(instance, "parent-ds/protocol-address/network-protocol", 0, &match);
    if (!lyret) {
        if (!strcmp(lyd_get_value(match), "ieee802-3")) {
            fprintf(fptr, "network_transport %8s\n", "L2");
        }

        lyret = lyd_find_path(instance, "parent-ds/protocol-address/address-field", 0, &match);
        if (!lyret) {
            char *mac = strdup(lyd_get_value(match));
            char *ptr = mac;

            while (*ptr != 0) {
                if (*ptr == '-') {
                    *ptr = ':';
                }
                ptr++;
            }
            fprintf(fptr, "ptp_dst_mac    %s\n", mac);
            free(mac);
        }
    }

    lyret = lyd_find_path(instance, "ports", 0, &ports);
    if (lyret) {
        rc = SR_ERR_CALLBACK_FAILED;
        goto error;
    }
    port = lyd_child(ports);

    lyret = lyd_find_path(port, "port-ds/log-announce-interval", 0, &match);
    if (!lyret) {
        fprintf(fptr, "logAnnounceInterval %8s\n", lyd_get_value(match));
    }

    lyret = lyd_find_path(port, "port-ds/log-sync-interval", 0, &match);
    if (!lyret) {
        fprintf(fptr, "logSyncInterval %8s\n", lyd_get_value(match));
    }

    lyret = lyd_find_path(port, "port-ds/ieee802-dot1as-gptp:sync-receipt-timeout", 0, &match);
    if (!lyret) {
        fprintf(fptr, "syncReceiptTimeout %8s\n", lyd_get_value(match));
    }

    lyret = lyd_find_path(port, "port-ds/ieee802-dot1as-gptp:mean-link-delay-thresh", 0, &match);
    if (!lyret) {
        fprintf(fptr, "neighborPropDelayThresh %8s\n", lyd_get_value(match));
    }

    lyret = lyd_find_path(port, "port-ds/delay-mechanism", 0, &match);
    if (!lyret) {
        if (!strcmp(lyd_get_value(match), "p2p")) {
            fprintf(fptr, "delay_mechanism %8s\n", "P2P");
        }
    }

    ptp_add_extra_config(fptr);
    rc = SR_ERR_OK;

error:
    sr_release_data(data);
    fclose(fptr);
    return rc;
}

int ptp_module_init(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription)
{
    char *xpath = PTP_ROOT_PATH;
    int rc = 0;

    rc = sr_module_change_subscribe(session, MODULE_NAME_PTP, xpath,
                                    ptp_change_subscribe_cb, NULL, 0,
                                    SR_SUBSCR_DONE_ONLY, subscription);
    if (rc != SR_ERR_OK) {
        LOG_ERR("Failed to subscribe for \"%s\" (%s).", xpath, sr_strerror(rc));
        goto error;
    }
    LOG_INF("Subscribed changes for %s", xpath);

    return SR_ERR_OK;
error:
    return SR_ERR_UNSUPPORTED;
}
