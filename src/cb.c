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
#define NULL_CB (0)
#define CBREC (1)
#define CBGEN (2)

struct item_cfg {
	int his_len;
	int ind;
	char port[20];
	char genport[20];
	unsigned int input_id_list[10];
	unsigned int output_id_list[10];
	int cb_flag;
};
static struct item_cfg sitem_conf;

static int parse_node(sr_session_ctx_t *session, sr_val_t *value,
			struct item_cfg *conf)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename = NULL;
	char port_path[100];

	if (!session || !value || !conf)
		return rc;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto ret_tag;

	if (!strcmp(nodename, "history-length")) {
		conf->his_len = value->data.uint8_val;
	} else if (!strcmp(nodename, "index")) {
		conf->ind = value->data.uint8_val;
	} else if (!strcmp(nodename, "port-list")) {
		strcpy(conf->port, value->data.string_val);
	} else if (!strcmp(nodename, "output-id-list")) {
		if (value->data.uint8_val < 10)
			conf->output_id_list[value->data.uint8_val] = value->data.uint8_val + 1;
	} else if (!strcmp(nodename, "port")) {
		strncpy(port_path, value->xpath, strlen(PPATH));
		strcpy(conf->genport, value->data.string_val);
	} else if (!strcmp(nodename, "input-id-list")) {
		if (value->data.uint8_val < 10)
			conf->input_id_list[value->data.uint8_val] = value->data.uint8_val + 1;
	}

ret_tag:
	return rc;
}

static int parse_item(sr_session_ctx_t *session, char *path,
			struct item_cfg *conf)
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
		rc = parse_node(session, &values[i], conf);
	}

	if (conf->ind && conf->his_len && strlen(conf->port) > 0) {
		conf->cb_flag = CBREC;
	} else if (conf->ind && !conf->his_len && strlen(conf->genport) > 0) {
		conf->cb_flag = CBGEN;
	} else {
		conf->cb_flag = NULL_CB;
		printf("ERROR : invalid file\n");
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
	struct item_cfg *conf = &sitem_conf;

	memset(conf, 0, sizeof(struct item_cfg));

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

		rc = parse_item(session, xpath, conf);
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
	struct tsn_seq_rec_conf cbrecy;
	struct tsn_seq_rec_conf *recy = &cbrecy;
	struct item_cfg *conf = &sitem_conf;

	memset(&cbrecy, 0, sizeof(cbrecy));
	cbrecy.seq_len = 16;
	cbrecy.his_len = conf->his_len;
	cbrecy.rtag_pop_en = 1;

	init_tsn_socket();
	tsn_cbrec_set(conf->port, conf->ind, recy);
	close_tsn_socket();
}

void cbgen_execute(void)
{
	struct tsn_seq_gen_conf cbgenr;
	struct tsn_seq_gen_conf *genr = &cbgenr;
	struct item_cfg *conf = &sitem_conf;
	int iport_mask = 0;
	int split_mask = 0;
	int index = 0;
	int num = 0;
	int index_in = 0;
	int num_in = 0;

	memset(&cbgenr, 0, sizeof(cbgenr));
	for (index = 0; index < 10; index++) {
		if (conf->output_id_list[index] != 0) {
			conf->output_id_list[index] = conf->output_id_list[index] - 1;
			conf->output_id_list[index] = 0x01 << conf->output_id_list[index];
		}
	}

	for (num = 0; num < 10; num++)
		split_mask = split_mask + conf->output_id_list[num];

	for (index_in = 0; index_in < 10; index_in++) {
		if (conf->input_id_list[index_in] != 0) {
			conf->input_id_list[index_in] = conf->input_id_list[index_in] - 1;
			conf->input_id_list[index_in] = 0x01 << conf->input_id_list[index_in];
		}
	}

	for (num_in = 0; num_in < 10; num_in++)
		iport_mask = iport_mask + conf->input_id_list[num_in];

	cbgenr.seq_len = 16;
	cbgenr.seq_num = 2048;
	cbgenr.iport_mask = iport_mask;
	cbgenr.split_mask = split_mask;

	init_tsn_socket();
	tsn_cbgen_set(conf->genport, conf->ind, genr);
	close_tsn_socket();
}

int cb_subtree_change_cb(sr_session_ctx_t *session, const char *path,
	sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0};
	struct item_cfg *conf = &sitem_conf;

	snprintf(xpath, XPATH_MAX_LEN, "%s", path);

	switch (event) {
	case SR_EV_VERIFY:
		rc = parse_config(session, xpath);
		break;
	case SR_EV_ENABLED:
		rc = parse_config(session, xpath);
		break;
	case SR_EV_APPLY:
		if (conf->cb_flag == CBREC)
			cbrec_execute();
		else if (conf->cb_flag == CBGEN)
			cbgen_execute();
		break;
	case SR_EV_ABORT:
		break;
	default:
		break;
	}

	return rc;
}
