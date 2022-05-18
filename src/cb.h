/**
 * @file cb.h
 * @author shang gao
 * @brief header file for cb.c.
 *
 * Copyright 2021 NXP
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

#ifndef __CB_H__
#define __CB_H__

#include "common.h"

#define CB_XPATH  ("/ieee802-dot1cb-frer:frer")
#define PPATH  ("/ieee802-dot1cb-frer:frer/sequence-identification")
int cb_subtree_change_cb(sr_session_ctx_t *session, const char *path,
	sr_notif_event_t event, void *private_ctx);

#endif
