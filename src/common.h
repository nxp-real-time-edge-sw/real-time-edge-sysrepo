/**
 * @file common.h
 * @author Xiaolin He
 * @brief header file for common.c.
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

#ifndef __COMMON_H_
#define __COMMON_H_

#define XPATH_MAX_LEN		(200U)
#define IF_NAME_MAX_LEN		(20U)
#define NODE_NAME_MAX_LEN	(80U)
#define MSG_MAX_LEN			(400U)

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/xpath.h>
#include <tsn/genl_tsn.h>
#include <linux/tsn.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <assert.h>

#include "log.h"

#define MAX_CMD_LEN		(512)
#define SUB_CMD_LEN		(64)
#define SUB_PARA_LEN		(64)
#define MAX_VLAN_ID		(4096)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define SYSCALL_OK(r) (((r) != -1) && WIFEXITED(r) && (WEXITSTATUS(r) == 0))

#define SR_CONFIG_SUBSCR(mod_name, xpath, cb, prio)							\
    rc = sr_module_change_subscribe(session, mod_name, xpath, cb, NULL, prio, 	\
           	SR_SUBSCR_DONE_ONLY, &subscription);		                    \
    if (rc != SR_ERR_OK) {													\
        LOG_ERR("Failed to subscribe for \"%s\" (%s).",	                    \
                xpath, sr_strerror(rc));									\
        goto error;                                                         \
    } else {                                                                \
        LOG_INF("Subscribed changes for %s", xpath);                        \
    }

#define IF_XPATH 				"/ietf-interfaces:interfaces/interface"
#define BRIDGE_XPATH 			"/ieee802-dot1q-bridge:bridges/bridge"
#define BRIDGE_COMPONENT_XPATH 	BRIDGE_XPATH "/component"

#define BR_PORT 				"/ieee802-dot1q-bridge:bridge-port"
#define BRIDGE_PORT_XPATH       "/ietf-interfaces:interfaces/interface/ieee802-dot1q-bridge:bridge-port"

enum apply_status {
	APPLY_NONE = 0,
	APPLY_PARSE_SUC,
	APPLY_PARSE_ERR,
	APPLY_SET_SUC,
	APPLY_SET_ERR,
};

enum num_type {
	NUM_TYPE_S8 =  0x1,
	NUM_TYPE_U8 =  0x2,
	NUM_TYPE_S16 =  0x3,
	NUM_TYPE_U16 =  0x4,
	NUM_TYPE_S32 =  0x5,
	NUM_TYPE_U32 =  0x6,
	NUM_TYPE_S64 =  0x7,
	NUM_TYPE_U64 =  0x8,
};

struct cycle_time_s {
	uint64_t numerator;
	uint64_t denominator;
};

struct base_time_s {
	uint64_t seconds;
	uint64_t nanoseconds;
};

void init_tsn_mutex(void);
void destroy_tsn_mutex(void);

void init_tsn_socket(void);
void close_tsn_socket(void);

uint64_t cal_base_time(struct base_time_s *basetime);
uint64_t cal_cycle_time(struct cycle_time_s *cycletime);

int errno2sp(int errtsn);
void pri2num(char *pri_str, int8_t *pri_num);
bool is_del_oper(sr_session_ctx_t *session, char *path);
char *get_host_name(void);

void print_node_tree_xml(const struct lyd_node *node);
const char *get_ifname(const struct lyd_node *node);

#endif
