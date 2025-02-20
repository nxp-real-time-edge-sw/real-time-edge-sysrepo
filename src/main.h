/**
 * @file main.h
 * @author Xiaolin He
 * @brief header file for main.c.
 *
 * Copyright 2019, 2025 NXP
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

#ifndef __MAIN_H_
#define __MAIN_H_

#include <stdlib.h>

#include "common.h"

#define IF_XPATH 				"/ietf-interfaces:interfaces/interface"
#define BRIDGE_XPATH 			"/ieee802-dot1q-bridge:bridges/bridge"
#define BRIDGE_COMPONENT_XPATH 	BRIDGE_XPATH "/component"

#define BR_PORT 				"/ieee802-dot1q-bridge:bridge-port"

extern struct sr_tsn_callback file_clbks;

#endif
