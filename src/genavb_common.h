/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SYSREPO_GENAVB_COMMON_H_
#define _SYSREPO_GENAVB_COMMON_H_

#define DEFAULT_SR_EVENT1 SR_EV_CHANGE
#define DEFAULT_SR_EVENT2 SR_EV_DONE
#define RETURN_IF_NOT_DEFAULT_EV(ev)											\
	do {																		\
		if (((ev) != (DEFAULT_SR_EVENT1)) && ((ev) != (DEFAULT_SR_EVENT2))) {	\
			return SR_ERR_OK;													\
		}																		\
	} while (0)

#define LY_NEW_PATH(root, ly_ctx, xpath, str, opt, parent)											\
	{																								\
		if (lyd_new_path(root, ly_ctx, xpath, str, opt, parent) != LY_SUCCESS) {					\
			LOG_ERR(" %s:%d, lyd_new_path failed for xpath %s\n", __FUNCTION__, __LINE__, xpath);	\
			rc = SR_ERR_INTERNAL;																	\
			goto cleanup;																			\
		}																							\
	}

#ifdef __linux__

#include "common.h"

#else

#define XPATH_MAX_LEN	  (256U)
#define IF_NAME_MAX_LEN	  (20U)
#define NODE_NAME_MAX_LEN (80U)
#define MSG_MAX_LEN	  (400U)
#define MACADDR_LEN	  (6)

#define LOG_ERR(fmt, args...) PRINTF("[ERR]" fmt "\n", ##args)
#define LOG_WRN(fmt, args...) PRINTF("[WRN]" fmt "\n", ##args)
#define LOG_INF(fmt, args...) PRINTF("[INF]" fmt "\n", ##args)
#define LOG_DBG(fmt, args...) PRINTF("[DBG]" fmt "\n", ##args)

#define XPATH_IFACE   "/ietf-interfaces:interfaces/interface"
#define XPATH_BR_PORT "/ieee802-dot1q-bridge:bridge-port"

struct cycle_time_s {
	uint64_t numerator;
	uint64_t denominator;
};

struct base_time_s {
	uint64_t seconds;
	uint64_t nanoseconds;
};

/*list to store keys*/
struct key_list {
	uint64_t key;
	uint64_t *key2; //second key is optional

	struct key_list *next;
};

int parse_mac_address(char *mac_str, uint8_t *mac);
void pri2num(char *pri_str, uint8_t *pri_num);
bool is_del_oper(sr_session_ctx_t *session, char *path);
uint64_t cal_base_time(struct base_time_s *basetime);
uint64_t cal_cycle_time(struct cycle_time_s *cycletime);
int errno2sp(int errtsn);
int add_key_if_unique(struct key_list **head, uint64_t *key, uint64_t *key2);
void free_key_list(struct key_list **head);
int get_port_id_from_interface(const char *interface_name);
int xpath_node_is_present(char *xpath, const char *node_name);
char *dup_node_name(const char *node);

#endif

#endif /* _SYSREPO_GENAVB_COMMON_H_ */
