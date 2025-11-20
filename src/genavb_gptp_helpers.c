/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "genavb_private.h"

//#define DEBUG

struct genavb_control_handle *ctrl_h = NULL;

#define BUF_LEN 100

uint8_t *get_response_header(uint8_t *buf, uint16_t *id, uint16_t *length, uint16_t *status)
{
        *id = ((uint16_t *)buf)[0];
        *length = ((uint16_t *)buf)[1];
        *status = ((uint16_t *)buf)[2];

        buf += 6;

        return buf;
}

uint8_t *get_node_next(uint8_t *buf, uint16_t length)
{
        buf += length - 2;

        return buf;
}

uint8_t *get_node_header(uint8_t *buf, uint16_t *id, uint16_t *length, uint16_t *status)
{
        buf = get_response_header(buf, id, length, status);

        return buf;
}

void *gptp_get_genavb_ctrl(void)
{
	return ctrl_h;
}

int gptp_genavb_init(void *avb_h)
{
	int rc;

	rc = genavb_init((struct genavb_handle **)&avb_h, 0);
	if (rc != GENAVB_SUCCESS) {
		LOG_ERR("genavb_init() failed: %s\n", genavb_strerror(rc));
		rc = SR_ERR_INTERNAL;
		goto error_genavb_init;
	}

	rc = genavb_control_open((struct genavb_handle *)avb_h, &ctrl_h, GENAVB_CTRL_GPTP);
	if (rc != GENAVB_SUCCESS) {
		LOG_ERR("genavb_control_open() failed: %s\n", genavb_strerror(rc));
		rc = SR_ERR_INTERNAL;
		goto error_genavb_open;
	}

	return 0;

error_genavb_open:
	if (avb_h)
		genavb_exit((struct genavb_handle *)avb_h);

error_genavb_init:
	return -1;
}

void gptp_genavb_exit(void *avb_h)
{
	if (ctrl_h)
		genavb_control_close(ctrl_h);

	if (avb_h)
		genavb_exit((struct genavb_handle *)avb_h);
}

//TODO: get genavb API to get the max gptp instance
size_t gptp_get_max_instances(void)
{
	return 1;
}

//TODO: get genavb API to get the max ports per gptp instance
uint16_t gptp_get_max_ports_per_instances(void)
{
	return 1;
}

int managed_set(struct genavb_control_handle *ctrl_h, void *cmd, unsigned int cmd_len, void *response, unsigned int response_len)
{
	genavb_msg_type_t msg_type;

#ifdef DEBUG
	int i;
#endif
	int rc;

	if (!ctrl_h)
		goto err;

	msg_type = GENAVB_MSG_MANAGED_SET;
	rc = genavb_control_send_sync(ctrl_h, &msg_type, cmd, cmd_len, response, &response_len, 100);
	if (rc != GENAVB_SUCCESS) {
		printf("genavb_control_send_sync() failed: %s\n", genavb_strerror(rc));
		goto err;
	}

	if (msg_type != GENAVB_MSG_MANAGED_SET_RESPONSE) {
		printf("genavb_control_send_sync() wrong response message type: %d\n", msg_type);
		goto err;
	}

#ifdef DEBUG
	printf("%d", response_len);

	for (i = 0; i < response_len; i++)
		printf(" %1x", ((uint8_t *)response)[i]);

	printf("\n");
#endif

	return 0;

err:
	return -1;
}

int managed_get(struct genavb_control_handle *ctrl_h, void *cmd, unsigned int cmd_len, void *response, unsigned int response_len)
{
	genavb_msg_type_t msg_type;

#ifdef DEBUG
	int i;
#endif
	int rc;

	if (!ctrl_h)
		goto err;

	msg_type = GENAVB_MSG_MANAGED_GET;
	rc = genavb_control_send_sync(ctrl_h, &msg_type, cmd, cmd_len, response, &response_len, 100);
	if (rc != GENAVB_SUCCESS) {
		printf("genavb_control_send_sync() failed: %s\n", genavb_strerror(rc));
		goto err;
	}

	if (msg_type != GENAVB_MSG_MANAGED_GET_RESPONSE) {
		printf("genavb_control_send_sync() wrong response message type: %d\n", msg_type);
		goto err;
	}

#ifdef DEBUG
	printf("%d", response_len);

	for (i = 0; i < response_len; i++)
		printf(" %1x", ((uint8_t *)response)[i]);

	printf("\n");
#endif

	return 0;

err:
	return -1;
}


