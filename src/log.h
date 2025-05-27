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

#ifndef __LOG_H_
#define __LOG_H_

#include <sysrepo.h>

#define LOG_ERR(...)    SRPLG_LOG_ERR(PLG_NAME, __VA_ARGS__)
#define LOG_WRN(...)    SRPLG_LOG_WRN(PLG_NAME, __VA_ARGS__)
#define LOG_INF(...)    SRPLG_LOG_INF(PLG_NAME, __VA_ARGS__)
#define LOG_DBG(...)    SRPLG_LOG_DBG(PLG_NAME, __VA_ARGS__)

#endif
