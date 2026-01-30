/**
 * @file speed.c
 * @author Jianchao Wang
 * @brief header file for speed.c.
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

#ifndef __SPEED_H_
#define __SPEED_H_

#include "common.h"

#define MODULE_NAME_SPEED    "ietf-interfaces"
#define SPEED_ROOT_PATH      "/ietf-interfaces:interfaces"

#define SR_OPER_GET_SUBSCR(mod_name, xpath, cb)                                 \
    rc = sr_oper_get_subscribe(session, mod_name, xpath, cb, NULL, 0, &subscription);  \
    if (rc != SR_ERR_OK) {                                                      \
        LOG_ERR("Failed to subscribe operational data for \"%s\" (%s).",        \
                xpath, sr_strerror(rc));                                        \
        goto error;                                                             \
    } else {                                                                    \
        LOG_INF("Subscribed operational data for %s", xpath);                   \
    }

int speed_oper_subscribe_cb(sr_session_ctx_t *session, uint32_t sub_id,
                            const char *module_name,const char *path,
                            const char *request_xpath, uint32_t request_id,
                            struct lyd_node **parent, void *private_data);

#endif