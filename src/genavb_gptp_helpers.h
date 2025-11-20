/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SYSREPO_GENAVB_GPTP_HELPERS_H_
#define _SYSREPO_GENAVB_GPTP_HELPERS_H_

int gptp_genavb_init(void *avb_h);

void gptp_genavb_exit(void *avb_h);

size_t gptp_get_max_instances(void);

uint16_t gptp_get_max_ports_per_instances(void);

void *gptp_get_genavb_ctrl(void);

uint8_t *get_response_header(uint8_t *buf, uint16_t *id, uint16_t *length, uint16_t *status);
uint8_t *get_node_next(uint8_t *buf, uint16_t length);
uint8_t *get_node_header(uint8_t *buf, uint16_t *id, uint16_t *length, uint16_t *status);

int managed_get(struct genavb_control_handle *ctrl_h, void *cmd, unsigned int cmd_len, void *response, unsigned int response_len);
int managed_set(struct genavb_control_handle *ctrl_h, void *cmd, unsigned int cmd_len, void *response, unsigned int response_len);

#endif /* _SYSREPO_GENAVB_GPTP_HELPERS_H_ */
