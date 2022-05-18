/**
 * @file cb.c
 * @author shang gao
 * @brief Application to configure CB generation and CB recovery related parameters based on sysrepo datastore.
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

#include "cb.h"
#include "cb_streamid.h"
#define NULL_CB (0)
#define CBREC (1)
#define CBGEN (2)

struct cb_para {
	int index;
	int streamhandle;
	bool gen;
	union {
		struct tsn_seq_gen_conf *cbgen;
		struct tsn_seq_rec_conf *cbrec;
	};
};

static struct cb_para cb_node;

static int parse_node(sr_session_ctx_t *session, sr_val_t *value)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename = NULL;
	char port_path[100];
	int handle;
	struct std_cb_stream_list *cb_stream;

	if (!session || !value)
		return rc;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto ret_tag;

	sr_xpath_recover(&xp_ctx);
	if (sr_xpath_node(value->xpath, "sequence-generation", &xp_ctx)) {
		cb_node.gen = 1;
		if (!cb_node.cbgen)
			cb_node.cbgen = calloc(1, sizeof(struct tsn_seq_gen_conf));
		if (!cb_node.cbgen)
			return -1;

		if (!strcmp(nodename, "index")) {
			cb_node.index = value->data.uint8_val;
		} else if (!strcmp(nodename, "stream")) {
			cb_node.streamhandle = value->data.uint8_val;
		}
	} else if (sr_xpath_node(value->xpath, "stream-split", &xp_ctx)) {
		if (!strcmp(nodename, "port")) {
			if (!strstr(value->data.string_val, "swp"))
				return -1;
			cb_node.cbgen->iport_mask =
				1 << (value->data.string_val[3] - '0');
		} else if (!strcmp(nodename, "output-id")) {
			handle = value->data.uint8_val;
			cb_stream = find_stream_handle(handle);
			if (!cb_stream)
				return -1;
			cb_node.cbgen->split_mask |=
				1 << cb_stream->stream_ptr->cbconf.ofac_oport;
		}
	} else if (sr_xpath_node(value->xpath, "sequence-recovery", &xp_ctx)) {
		cb_node.gen = 0;
		if (!cb_node.cbrec)
			cb_node.cbrec = calloc(1, sizeof(struct tsn_seq_rec_conf));
		if (!cb_node.cbrec)
			return -1;
		if (!strcmp(nodename, "history-length")) {
			cb_node.cbrec->his_len = value->data.uint8_val;
		}
	}

ret_tag:
	return rc;
}

static int parse_item(sr_session_ctx_t *session, char *path)
{
	size_t i;
	size_t count;
	int rc = SR_ERR_OK;
	sr_val_t *values = NULL;
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_items(session, path, &values, &count);
	if (rc == SR_ERR_NOT_FOUND) {
		/*
		 * If can't find any item, we should check whether this
		 * container was deleted.
		 */
		if (is_del_oper(session, path)) {
			printf("WARN: %s was deleted, disable %s",
			       path, "this Instance.\n");
			goto cleanup;
		} else {
			printf("WARN: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));
			return SR_ERR_OK;
		}
	} else if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get items from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_items: %s\n", __func__,
		       sr_strerror(rc));
		return rc;
	}

	for (i = 0; i < count; i++) {
		if (values[i].type == SR_LIST_T
		    || values[i].type == SR_CONTAINER_PRESENCE_T)
			continue;
		rc = parse_node(session, &values[i]);
	}

cleanup:
	sr_free_values(values, count);

	return rc;
}

static int parse_config(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *value = NULL;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	sr_change_iter_t *it = NULL;
	char xpath[XPATH_MAX_LEN] = {0};
	char err_msg[MSG_MAX_LEN] = {0};

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", path);
	rc = sr_get_changes_iter(session, xpath, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", xpath);
		sr_set_error(session, err_msg, xpath);
		printf("ERROR: %s sr_get_changes_iter: %s\n", __func__,
		       sr_strerror(rc));
		goto cleanup;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		if (!value)
			continue;

		rc = parse_item(session, xpath);
		if (rc != SR_ERR_OK)
			break;
	}

cleanup:
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

	return rc;
}

void cbrec_execute(void)
{
	struct tsn_seq_rec_conf *cbrec = cb_node.cbrec;
	char *port = "swp0";

	cbrec->seq_len = 16;
	cbrec->rtag_pop_en = 1;

	init_tsn_socket();
	tsn_cbrec_set(port, cb_node.index, cbrec);
	close_tsn_socket();
}

void cbgen_execute(void)
{
	struct tsn_seq_gen_conf *cbgen = cb_node.cbgen;
	char *port = "swp0";

	cbgen->seq_len = 16;
	cbgen->seq_num = 2048;

	init_tsn_socket();
	tsn_cbgen_set(port, cb_node.index, cbgen);
	close_tsn_socket();
}

int cb_subtree_change_cb(sr_session_ctx_t *session, const char *path,
	sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0};

	snprintf(xpath, XPATH_MAX_LEN, "%s", path);

	switch (event) {
	case SR_EV_VERIFY:
		rc = parse_config(session, xpath);
		break;
	case SR_EV_ENABLED:
		rc = parse_config(session, xpath);
		break;
	case SR_EV_APPLY:
		if (cb_node.gen)
			cbgen_execute();
		else
			cbrec_execute();
		break;
	case SR_EV_ABORT:
		break;
	default:
		break;
	}

	return rc;
}
