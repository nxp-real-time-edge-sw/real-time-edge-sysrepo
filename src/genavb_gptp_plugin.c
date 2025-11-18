/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define PLG_NAME    "genavb-ptp"

#include <sysrepo.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "common.h"

#include <genavb/genavb.h>

static sr_subscription_ctx_t *subscription = NULL;

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	char *xpath = PTP_ROOT_PATH;
	struct genavb_handle *avb_h = NULL;
	struct genavb_control_handle *ctrl_h;
	int rc;

	rc = genavb_init(&avb_h, 0);
	if (rc != GENAVB_SUCCESS) {
		LOG_ERR("genavb_init() failed: %s\n", genavb_strerror(rc));
		rc = SR_ERR_INTERNAL;
		goto error_genavb_init;
	}

	*private_data = avb_h;

	rc = genavb_control_open(avb_h, &ctrl_h, GENAVB_CTRL_GPTP);
	if (rc != GENAVB_SUCCESS) {
		LOG_ERR("genavb_control_open() failed: %s\n", genavb_strerror(rc));
		rc = SR_ERR_INTERNAL;
		goto error_genavb_open;
	}

	LOG_INF("GenAVB/TSN PTP plugin subscribed changes for %s", xpath);

	return SR_ERR_OK;

error_subscribe:
	if (ctrl_h)
		genavb_control_close(ctrl_h);

error_genavb_open:
	if (avb_h)
		genavb_exit(avb_h);

error_genavb_init:
	return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *running_session, void *private_data)
{
	struct genavb_handle *avb_h = (struct genavb_handle *)private_data;

	sr_unsubscribe(subscription);

	if (avb_h)
		genavb_exit(avb_h);

	LOG_INF("GenAVB/TSN PTP plugin cleanup finished.");
}
