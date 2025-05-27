/**
 * @file qbv.h
 * @author Xiaolin He
 * @brief header file for qbv.c.
 *
 * Copyright 2019-2020, 2025 NXP
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

#ifndef __QBV_H_
#define __QBV_H_

#include <tsn/genl_tsn.h>
#include "common.h"

#define QBV_TC_NUM (8)

#define QBV_MODULE		"ieee802-dot1q-sched-bridge"
#define QBV_FEATURE		"scheduled-traffic"

#define QBV_GATE_PARA_XPATH 	IF_XPATH BR_PORT "/" QBV_MODULE ":gate-parameter-table"

struct sr_qbv_conf {
	bool qbv_en;
	struct tsn_qbv_conf *qbvconf_ptr;
	bool cycletime_f;
	bool basetime_f;
	struct cycle_time_s cycletime;
	struct base_time_s basetime;
};

int qbv_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                          const char *module_name, const char *path,
                          sr_event_t event, uint32_t request_id,
                          void *private_ctx);

#endif
