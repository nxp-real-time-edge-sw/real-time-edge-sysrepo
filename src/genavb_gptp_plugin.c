/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "genavb_private.h"

static sr_subscription_ctx_t *subscription = NULL;

//#define PLG_NAME    "genavb-ptp"
#define PTP_MODULE     "ieee1588-ptp-tt"
#define PTP_ROOT_XPATH       "/ieee1588-ptp-tt:ptp"
#define PTP_INSTANCES_XPATH  "/ieee1588-ptp-tt:ptp/instances"
#define PTP_INSTANCE_XPATH  "/ieee1588-ptp-tt:ptp/instances/instance"
#define PTP_INSTANCE_INDEX_XPATH "/ieee1588-ptp-tt:ptp/instances/instance/instance-index"
#define PTP_PORT_XPATH  "/ieee1588-ptp-tt:ptp/instances/instance/ports/port"

#define MAX_CLOCK_CLASS_IDENTITY_REFS		10
#define MAX_CLOCK_ACCURACY_IDENTITY_REFS	27
#define MAX_TIME_SOURCE_IDENTITY_REFS		9 
#define BUF_LEN 100
#define MAX_SIZE 64
#define MAX_INDICES		4
#define MAX_PORTS_PER_INSTANCE	4

#define SET_INSTANCE_INFO(id,instance_id,max_instances) { \
	instance_id_g[id] = instance_id; \
	num_instances_g = max_instances; \
}

#define SET_PORT_ID_INFO(id1,instance_index,port,id2,num_ports) { \
	port_info_g[id1].instance_id = instance_index; \
	port_info_g[id1].port_id[id2] = port; \
	port_info_g[id1].max_ports = num_ports; \
}

#define GET_SCHEMA_NODE(snode,set,i) { \
	snode = (const struct lysc_node *)set->snodes[i]; \
	if (!snode) { \
		LOG_ERR(" schema node is NULL"); \
		continue; \
	} \
}

#define GET_RUNNING_DS_SESS_ANG_GET_ITEMS(session,new_sess,xpath,vals,count) { \
	rc = sr_session_start(sr_session_get_connection(session),SR_DS_RUNNING,&new_sess); \
	if (rc != SR_ERR_OK) { \
		LOG_ERR(" sr_session_start failed, rc %d",rc); \
		return -1; \
	} \
	\
	rc = sr_get_items(new_sess,xpath,0,0,&vals,&count); \
	if (rc != SR_ERR_OK) { \
		LOG_ERR(" sr_get_items failed, rc %d",rc); \
		sr_session_stop(new_sess); \
		return -1; \
	}\
}

struct gptp_identity_ref {
	char identity_ref[64];
	uint8_t value;
};

struct gptp_port_instance {
	uint32_t instance_id;
	uint16_t port_id[MAX_PORTS_PER_INSTANCE];
	uint8_t max_ports;
};

uint32_t instance_id_g[MAX_INDICES];
uint8_t num_instances_g = 0;
struct gptp_port_instance port_info_g[MAX_INDICES];

#ifdef __linux__
#define PREPARE_PORT_XPATH(instance_path, instance_index,port_index, ds,nodename) {\
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%d']/ports/port[port-index='%d']/%s/%s",instance_path,instance_index,port_index,ds,nodename); \
}
#else
#define PREPARE_PORT_XPATH(instance_path, instance_index,port_index, ds,nodename) {\
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%ld']/ports/port[port-index='%d']/%s/%s",instance_path,instance_index,port_index,ds,nodename); \
}
#endif

#ifdef __linux__
#define PREPARE_PORT_XPATH_WITH_CNTR(instance_path, instance_index, port_index, ds, cntr_name, nodename) {\
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%d']/ports/port[port-index='%d']/%s/%s/%s", instance_path, instance_index, port_index, ds, cntr_name, nodename); \
}
#else
#define PREPARE_PORT_XPATH_WITH_CNTR(instance_path, instance_index, port_index, ds, cntr_name, nodename) {\
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%ld']/ports/port[port-index='%d']/%s/%s/%s", instance_path, instance_index, port_index, ds, cntr_name, nodename); \
}
#endif

#ifdef __linux__
#define PREPARE_XPATH(instance_path, instance_index,ds,nodename) { \
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%d']/%s/%s",instance_path,instance_index,ds,nodename); \
}
#else
#define PREPARE_XPATH(instance_path, instance_index,ds,nodename) { \
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%ld']/%s/%s",instance_path,instance_index,ds,nodename); \
}
#endif

#ifdef __linux__
#define PREPARE_XPATH_WITH_CNTR(instance_path, instance_index,ds,cntr_name,nodename) { \
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%d']/%s/%s/%s",instance_path,instance_index,ds,cntr_name,nodename); \
}
#else
#define PREPARE_XPATH_WITH_CNTR(instance_path, instance_index,ds,cntr_name,nodename) { \
        snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%ld']/%s/%s/%s",instance_path,instance_index,ds,cntr_name,nodename); \
}
#endif

uint32_t gptp_get_operation_id_g = 0;
struct gptp_identity_ref clock_class_identity_ref_g[MAX_CLOCK_CLASS_IDENTITY_REFS];
struct gptp_identity_ref clock_accuracy_identity_ref_g[MAX_CLOCK_ACCURACY_IDENTITY_REFS];
struct gptp_identity_ref time_source_identity_ref_g[MAX_TIME_SOURCE_IDENTITY_REFS];

char port_state_string[10][32] = {"",
			    "initializing",
			    "faulty",
			    "disabled",
			    "listening",
			    "pre-time-transmitter",
			    "time-transmitter",
			    "passive",
			    "uncalibrated",
			    "time-receiver"};


void gptp_clock_class_identity_ref_init()
{
	/* clock-class identity ref to value mapping entries */
	strcpy(clock_class_identity_ref_g[0].identity_ref,"ieee1588-ptp-tt:cc-primary-sync");
	clock_class_identity_ref_g[0].value = 6;

	strcpy(clock_class_identity_ref_g[1].identity_ref,"ieee1588-ptp-tt:cc-primary-sync-lost");
	clock_class_identity_ref_g[1].value = 7;

	strcpy(clock_class_identity_ref_g[2].identity_ref,"ieee1588-ptp-tt:cc-application-specific-sync");
	clock_class_identity_ref_g[2].value = 13;

	strcpy(clock_class_identity_ref_g[3].identity_ref,"ieee1588-ptp-tt:cc-application-specific-sync-lost");
	clock_class_identity_ref_g[3].value = 14;

	strcpy(clock_class_identity_ref_g[4].identity_ref,"ieee1588-ptp-tt:cc-primary-sync-alternative-a");
	clock_class_identity_ref_g[4].value = 52;

	strcpy(clock_class_identity_ref_g[5].identity_ref,"ieee1588-ptp-tt:cc-application-specific-alternative-a");
	clock_class_identity_ref_g[5].value = 58;

	strcpy(clock_class_identity_ref_g[6].identity_ref,"ieee1588-ptp-tt:cc-primary-sync-alternative-b");
	clock_class_identity_ref_g[6].value = 187;

	strcpy(clock_class_identity_ref_g[7].identity_ref,"ieee1588-ptp-tt:cc-application-specific-alternative-b");
	clock_class_identity_ref_g[7].value = 193;

	strcpy(clock_class_identity_ref_g[8].identity_ref,"ieee1588-ptp-tt:cc-default");
	clock_class_identity_ref_g[8].value = 248;

	strcpy(clock_class_identity_ref_g[9].identity_ref,"ieee1588-ptp-tt:cc-time-receiver-only");
	clock_class_identity_ref_g[9].value = 255;

	return;
}

/*
   Get clock-class identity ref string from value
	input: value - identity ref value
	output: str  - identity ref string
*/
int gptp_clock_class_get_identity_ref_from_value(char *str, uint8_t value)
{
	int i;

	for (i = 0;i < MAX_CLOCK_CLASS_IDENTITY_REFS;i++) {
		if (value == clock_class_identity_ref_g[i].value) {
			strcpy(str,clock_class_identity_ref_g[i].identity_ref);
			return 0;
		}
	}

	return -1;
}

/*
   Get clock-class value from identity ref string
	input: str  - identity ref string
	output: value - identity ref value
*/
int gptp_clock_class_get_value_from_identity_ref(char *str, uint8_t *value)
{
	int i;

	for (i = 0;i < MAX_CLOCK_CLASS_IDENTITY_REFS;i++) {
		if (!strcmp(str,clock_class_identity_ref_g[i].identity_ref)) {
			*value = clock_class_identity_ref_g[i].value;
			return 0;
		}
	}

	return -1;

}

void gptp_clock_accuracy_identity_ref_init()
{
	/* clock-accuracy identity ref to value mapping entries */
	strcpy(clock_accuracy_identity_ref_g[0].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-1000-fs");
	clock_accuracy_identity_ref_g[0].value = 0x17;

	strcpy(clock_accuracy_identity_ref_g[1].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-2500-fs");
	clock_accuracy_identity_ref_g[1].value = 0x18;

	strcpy(clock_accuracy_identity_ref_g[2].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-10-ps");
	clock_accuracy_identity_ref_g[2].value = 0x19;

	strcpy(clock_accuracy_identity_ref_g[3].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-25ps");
	clock_accuracy_identity_ref_g[3].value = 0x1A;

	strcpy(clock_accuracy_identity_ref_g[4].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-100-ps");
	clock_accuracy_identity_ref_g[4].value = 0x1B;

	strcpy(clock_accuracy_identity_ref_g[5].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-250-ps");
	clock_accuracy_identity_ref_g[5].value = 0x1C;

	strcpy(clock_accuracy_identity_ref_g[6].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-1000-ps");
	clock_accuracy_identity_ref_g[6].value = 0x1D;

	strcpy(clock_accuracy_identity_ref_g[7].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-2500-ps");
	clock_accuracy_identity_ref_g[7].value = 0x1E;

	strcpy(clock_accuracy_identity_ref_g[8].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-10-ns");
	clock_accuracy_identity_ref_g[8].value = 0x1F;

	strcpy(clock_accuracy_identity_ref_g[9].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-25-ns");
	clock_accuracy_identity_ref_g[9].value = 0x20;

	strcpy(clock_accuracy_identity_ref_g[10].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-100-ns");
	clock_accuracy_identity_ref_g[10].value = 0x21;

	strcpy(clock_accuracy_identity_ref_g[11].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-250-ns");
	clock_accuracy_identity_ref_g[11].value = 0x22;

	strcpy(clock_accuracy_identity_ref_g[12].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-1000-ns");
	clock_accuracy_identity_ref_g[12].value = 0x23;

	strcpy(clock_accuracy_identity_ref_g[13].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-2500-ns");
	clock_accuracy_identity_ref_g[13].value = 0x24;

	strcpy(clock_accuracy_identity_ref_g[14].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-10-us");
	clock_accuracy_identity_ref_g[14].value = 0x25;

	strcpy(clock_accuracy_identity_ref_g[15].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-25-us");
	clock_accuracy_identity_ref_g[15].value = 0x26;

	strcpy(clock_accuracy_identity_ref_g[16].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-100-us");
	clock_accuracy_identity_ref_g[16].value = 0x27;

	strcpy(clock_accuracy_identity_ref_g[17].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-250-us");
	clock_accuracy_identity_ref_g[17].value = 0x28;

	strcpy(clock_accuracy_identity_ref_g[18].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-1000-us");
	clock_accuracy_identity_ref_g[18].value = 0x29;

	strcpy(clock_accuracy_identity_ref_g[19].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-2500-us");
	clock_accuracy_identity_ref_g[19].value = 0x2A;

	strcpy(clock_accuracy_identity_ref_g[20].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-10-ms");
	clock_accuracy_identity_ref_g[20].value = 0x2B;

	strcpy(clock_accuracy_identity_ref_g[21].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-25-ms");
	clock_accuracy_identity_ref_g[21].value = 0x2C;

	strcpy(clock_accuracy_identity_ref_g[22].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-100-ms");
	clock_accuracy_identity_ref_g[22].value = 0x2D;

	strcpy(clock_accuracy_identity_ref_g[23].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-250-ms");
	clock_accuracy_identity_ref_g[23].value = 0x2E;

	strcpy(clock_accuracy_identity_ref_g[24].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-1-s");
	clock_accuracy_identity_ref_g[24].value = 0x2F;

	strcpy(clock_accuracy_identity_ref_g[25].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-10-s");
	clock_accuracy_identity_ref_g[25].value = 0x30;

	strcpy(clock_accuracy_identity_ref_g[26].identity_ref,"ieee1588-ptp-tt:ca-time-accurate-to-gt-10-s");
	clock_accuracy_identity_ref_g[26].value = 0x31;

	return;
}

/*
   Get clock-accuracy identity ref string from value
	input: value - identity ref value
	output: str  - identity ref string
*/
int gptp_clock_accuracy_get_identity_ref_from_value(char *str, uint8_t value)
{
	int i;

	for (i = 0;i < MAX_CLOCK_ACCURACY_IDENTITY_REFS;i++) {
		if (value == clock_accuracy_identity_ref_g[i].value) {
			strcpy(str,clock_accuracy_identity_ref_g[i].identity_ref);
			return 0;
		}
	}

	return -1;
}

/*
   Get clock-accuracy value from identity ref string
	input: str  - identity ref string
	output: value - identity ref value
*/
int gptp_clock_accuracy_get_value_from_identity_ref(char *str, uint8_t *value)
{
	int i;

	for (i = 0;i < MAX_CLOCK_ACCURACY_IDENTITY_REFS;i++) {
		if (!strcmp(str,clock_accuracy_identity_ref_g[i].identity_ref)) {
			*value = clock_accuracy_identity_ref_g[i].value;
			return 0;
		}
	}

	return -1;

}

void gptp_time_source_identity_ref_init(void)
{
	/* time-source identity ref to value mapping entries */
	strcpy(time_source_identity_ref_g[0].identity_ref,"ieee1588-ptp-tt:atomic-clock");
	time_source_identity_ref_g[0].value = 0x10;

	strcpy(time_source_identity_ref_g[1].identity_ref,"ieee1588-ptp-tt:gnss");
	time_source_identity_ref_g[1].value = 0x20;

	strcpy(time_source_identity_ref_g[2].identity_ref,"ieee1588-ptp-tt:terrestrial-radio");
	time_source_identity_ref_g[2].value = 0x30;

	strcpy(time_source_identity_ref_g[3].identity_ref,"ieee1588-ptp-tt:serial-time-code");
	time_source_identity_ref_g[3].value = 0x39;

	strcpy(time_source_identity_ref_g[4].identity_ref,"ieee1588-ptp-tt:ptp");
	time_source_identity_ref_g[4].value = 0x40;

	strcpy(time_source_identity_ref_g[5].identity_ref,"ieee1588-ptp-tt:ntp");
	time_source_identity_ref_g[5].value = 0x50;

	strcpy(time_source_identity_ref_g[6].identity_ref,"ieee1588-ptp-tt:hand-set");
	time_source_identity_ref_g[6].value = 0x60;

	strcpy(time_source_identity_ref_g[7].identity_ref,"ieee1588-ptp-tt:other");
	time_source_identity_ref_g[7].value = 0x90;

	strcpy(time_source_identity_ref_g[8].identity_ref,"ieee1588-ptp-tt:internal-oscillator");
	time_source_identity_ref_g[8].value = 0xA0;

	return;
}

/*
   Get time-source identity ref string from value
	input: value - identity ref value
	output: str  - identity ref string
*/
int gptp_time_source_get_identity_ref_from_value(char *str, uint8_t value)
{
	int i;

	for (i = 0;i < MAX_TIME_SOURCE_IDENTITY_REFS;i++) {
		if (value == time_source_identity_ref_g[i].value) {
			strcpy(str,time_source_identity_ref_g[i].identity_ref);
			return 0;
		}
	}

	return -1;
}

/*
   Get time-source value from identity ref string
	input: str  - identity ref string
	output: value - identity ref value
*/
int gptp_time_source_get_value_from_identity_ref(char *str, uint8_t *value)
{
	int i;

	for (i = 0;i < MAX_TIME_SOURCE_IDENTITY_REFS;i++) {
		if (!strcmp(str,time_source_identity_ref_g[i].identity_ref)) {
			*value = time_source_identity_ref_g[i].value;
			return 0;
		}
	}

	return -1;

}

void gptp_identity_refs_init(void)
{
	gptp_clock_class_identity_ref_init();
	gptp_clock_accuracy_identity_ref_init();
	gptp_time_source_identity_ref_init();

	return;
}

int gptp_set_leaf_value(char *nodename, const char *ds_name,struct genavb_mobj_cmd *cmd,sr_val_t *value,int id)
{
	uint8_t val = 0;

	switch (value->type) {
		case SR_BOOL_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_BOOL_T, value: %d",nodename,ds_name,value->data.bool_val);
			if (genavb_mobj_cmd_set_leaf_u8(cmd, id, value->data.bool_val) < 0)
				goto err;
			break;
		case SR_INT8_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_INT8_T, value: %d",nodename,ds_name,value->data.int8_val);
			if (genavb_mobj_cmd_set_leaf_s8(cmd, id, value->data.int8_val) < 0)
				goto err;
			break;
		case SR_UINT8_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_UINT8_T, value: %d",nodename,ds_name,value->data.uint8_val);
			if (genavb_mobj_cmd_set_leaf_u8(cmd, id, value->data.uint8_val) < 0)
				goto err;
			break;
		case SR_INT16_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_INT16_T, value: %d",nodename,ds_name,value->data.int16_val);
			if (genavb_mobj_cmd_set_leaf_s16(cmd, id, value->data.int16_val) < 0)
				goto err;
			break;
		case SR_UINT16_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_UINT16_T, value: %d",nodename,ds_name,value->data.uint16_val);
			if (genavb_mobj_cmd_set_leaf_u16(cmd, id, value->data.uint16_val) < 0)
				goto err;
			break;
		case SR_INT32_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_INT32_T, value: %d",nodename,ds_name,value->data.int32_val);
			if (genavb_mobj_cmd_set_leaf_s32(cmd, id, value->data.int32_val) < 0)
				goto err;
			break;
		case SR_UINT32_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_UINT32_T, value: %d",nodename,ds_name,value->data.uint32_val);
			if (genavb_mobj_cmd_set_leaf_u32(cmd, id, value->data.uint32_val) < 0)
				goto err;
			break;
		case SR_INT64_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_INT64_T, value: %lu",nodename,ds_name,value->data.int64_val);
			if (genavb_mobj_cmd_set_leaf_s64(cmd, id, value->data.int64_val) < 0)
				goto err;
			break;
		case SR_UINT64_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_UINT64_T, value: %lu",nodename,ds_name,value->data.uint64_val);
			if (genavb_mobj_cmd_set_leaf_u64(cmd, id, value->data.uint64_val) < 0)
				goto err;
			break;
		case SR_STRING_T:
			LOG_DBG(" setting node: %s, ds: %s, SR_STRING_T, string: %sd",
						nodename,ds_name,value->data.string_val);
			break;
		case SR_IDENTITYREF_T:
			if (!strcmp(nodename,"clock-class")) {
				if (gptp_clock_class_get_value_from_identity_ref(value->data.identityref_val,&val) != 0)
					goto err;
			} else if (!strcmp(nodename,"clock-accuracy")) {
				if (gptp_clock_accuracy_get_value_from_identity_ref(value->data.identityref_val,&val) != 0)
					goto err;
			} else if (!strcmp(nodename,"time-source")) {
				if (gptp_time_source_get_value_from_identity_ref(value->data.identityref_val,&val) != 0)
					goto err;
			} else {
				LOG_ERR(" invalid IDENTITYREF id");
				goto err;
			}

			LOG_DBG(" setting node: %s, ds: %s, SR_IDENTITYREF_T, recvd string: %s, int value: %d",
						nodename,ds_name,value->data.identityref_val,val);
			if (genavb_mobj_cmd_set_leaf_u8(cmd, id, val) < 0)
				goto err;
			break;
		default :
			LOG_DBG(" setting node: %s, ds: %s, default type",nodename,ds_name);
			goto err;
	}

	return 0;

err:
	return -1;
}

int config_gptp(sr_val_t *value,char *nodename, const char *ds_name,
		uint32_t instance_id, bool is_port, uint16_t port_id,
		bool is_cntr_present, const char *cntr_name)
{
	struct genavb_msg_managed_set_response set_response;
	struct genavb_mobj_cmd cmd;
	uint16_t buf[BUF_LEN];
	int id = 0;;
	int ret = -1;
	const char *name = ds_name;

	genavb_mobj_cmd_init(&cmd, (uint8_t *)buf, BUF_LEN);

	if ((id = genavb_mobj_gptp_node_id(NULL, "instance")) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if ((id = genavb_mobj_gptp_node_id("instance", "instance-index")) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (genavb_mobj_cmd_set_list_index(&cmd, id, instance_id) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (!is_port) {
		if ((id = genavb_mobj_gptp_node_id("instance", ds_name)) < 0) {
			LOG_ERR(" %s: genavb_mobj_gptp_node_id for failed ds %s",__FUNCTION__,ds_name);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	} else {
		if ((id = genavb_mobj_gptp_node_id("instance", "ports")) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if ((id = genavb_mobj_gptp_node_id("ports", "port")) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if ((id = genavb_mobj_gptp_node_id("port", "port-index")) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_set_list_index(&cmd, id, port_id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if ((id = genavb_mobj_gptp_node_id("ports", ds_name)) < 0) {
			LOG_ERR(" %s: failed at line %d ds_name=%s",__FUNCTION__, __LINE__, ds_name);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	}

	if (is_cntr_present) {
		if ((id = genavb_mobj_gptp_node_id(ds_name,cntr_name)) < 0) {
			LOG_ERR(" %s: genavb_mobj_gptp_node_id for container %s, ds %s",__FUNCTION__,cntr_name,ds_name);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		name = cntr_name;
	}

	if ((id = genavb_mobj_gptp_node_id(name, nodename)) < 0) {
		LOG_ERR(" %s: genavb_mobj_gptp_node_id failed for container %s, node %s",__FUNCTION__,name,nodename);
		goto err;
	}

	if (gptp_set_leaf_value(nodename,ds_name,&cmd,value,id) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (is_cntr_present) {
		if (genavb_mobj_cmd_end_node(&cmd) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	}

	if (is_port) {
		if (genavb_mobj_cmd_end_node(&cmd) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_end_node(&cmd) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	}

	if (genavb_mobj_cmd_end_node(&cmd) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (genavb_mobj_cmd_end_node(&cmd) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (managed_set(gptp_get_genavb_ctrl(), genavb_mobj_cmd_buf(&cmd), genavb_mobj_cmd_len(&cmd), &set_response, sizeof(set_response)) < 0) {
		LOG_ERR(" %s: failed at line %d, cmd len %d",__FUNCTION__, __LINE__,genavb_mobj_cmd_len(&cmd));
		goto err;
	}

	if (genavb_mobj_rsp_check((u_int8_t *)&set_response) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	ret = 0;

err:
	return ret;
}

void get_actual_node_name_if_augmented(char *name)
{
	char *pch;

	if (strstr(name, "ieee802-dot1as-gptp") != NULL) {
		pch = strtok (name,":");
		if (pch != NULL) {
			pch = strtok (NULL, "\0");
			strcpy(name,pch);
		}
	}
	return;
}

int get_data_set_name_based_on_nodename(sr_session_ctx_t *session,sr_val_t *value,const struct lysc_node **parent_out)
{
	struct lysc_node *schema_node = NULL; 
	struct lysc_node *parent = NULL; 
	const struct ly_ctx *ctx = NULL; 
	struct ly_set *set = NULL;
	int ret = -1;

	ctx = sr_session_acquire_context(session);
	if (!ctx) {
		LOG_ERR(" ctx failed");
		return ret;
	}

	if (lys_find_xpath(ctx,NULL,value->xpath,0,&set) != LY_SUCCESS) {
		LOG_ERR(" lys_find_xpath failed");
		return ret;
	}

	if (!set || set->count == 0) {
		LOG_ERR(" set is NULL or count is 0");
		return ret;
	}

	for (int i = 0; i < set->count; ++i) {
		schema_node = (struct lysc_node *)set->snodes[i];
		if (!schema_node) {
			LOG_ERR(" schema node is NULL");
			return ret;
		}

		parent = schema_node->parent; 
		while (parent && parent->nodetype != LYS_CONTAINER) {
			parent = parent->parent;
		}

		if (parent && parent->name) {
			//LOG_DBG(" value->xpath %s, parent->name %s",value->xpath,parent->name);
			*parent_out = parent;
			ret = 0;
			break;
		}
	}

	ly_set_free(set,NULL);
	return ret;
}

int gptp_port_parse(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	sr_change_oper_t oper;
	char *index;
	char *index_instance;
	uint32_t port_id = 0;
	uint32_t instance_index = 0;
        char *nodename = NULL;
        const struct lysc_node *parent = NULL;

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		LOG_ERR("%s sr_get_changes_iter: %s\n", __func__, sr_strerror(rc));
		goto err;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
						     &oper, &old_value, &new_value))) {

		value = new_value ? new_value : old_value;
		if (!value)
			continue;

		/* skip the new created node with the default value */
		if (new_value && (oper == SR_OP_CREATED) && new_value->dflt) {
			sr_free_val(old_value);
			sr_free_val(new_value);
			continue;
		}

		if (value->type == SR_LIST_T || value->type == SR_CONTAINER_T ||
						value->type == SR_CONTAINER_PRESENCE_T) {
			sr_free_val(old_value);
			sr_free_val(new_value);
			continue;
		}

                index_instance = sr_xpath_key_value(value->xpath, "instance", "instance-index",
                              	             &xp_ctx);
                if (!index_instance) {
                        sr_free_val(old_value);
                        sr_free_val(new_value);
                        continue;
                }
                instance_index = strtoul(index_instance, NULL, 0);

		sr_xpath_recover(&xp_ctx);
                index = sr_xpath_key_value(value->xpath, "port", "port-index",
                                           &xp_ctx);

                if (!index) {
                        sr_free_val(old_value);
                        sr_free_val(new_value);
                        continue;
                }
                port_id = strtoul(index, NULL, 0);

		sr_xpath_recover(&xp_ctx);
		nodename = sr_xpath_node_name(value->xpath);
		if (!nodename) {
			LOG_ERR(" nodename is NULL");
			rc = SR_ERR_INVAL_ARG;
			sr_free_val(old_value);
			sr_free_val(new_value);
			goto err;
		}

		get_actual_node_name_if_augmented(nodename);

		if (get_data_set_name_based_on_nodename(session, value, &parent) != 0) {
			LOG_ERR(" get_data_set_name_based_on_nodename failed");
			rc = SR_ERR_INVAL_ARG;
			sr_free_val(old_value);
			sr_free_val(new_value);
			goto err;
		}

		if (!strcmp(parent->name,GPTP_NAME_PORT_DS)) {
			if (config_gptp(value, nodename, parent->name, instance_index, true, port_id, 0, NULL) != 0) {
				LOG_ERR(" config_gptp failed");
				rc = SR_ERR_INVAL_ARG;
				sr_free_val(old_value);
				sr_free_val(new_value);
				goto err;
			}
		}

		sr_free_val(old_value);
		sr_free_val(new_value);
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
err:
	sr_free_change_iter(it);
	return rc;
}

int gptp_parse(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	sr_change_oper_t oper;
	char *index;
	uint32_t instance_id = 0;
	char *nodename = NULL;
	const struct lysc_node *parent = NULL; 
	const struct lysc_node *ds = NULL;
	bool is_cntr_present;

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		sr_session_set_error_message(session, "Get changes from %s failed", path);
		LOG_ERR("%s sr_get_changes_iter: %s\n", __func__, sr_strerror(rc));
		goto err;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
						     &oper, &old_value, &new_value))) {

		value = new_value ? new_value : old_value;
		if (!value)
			continue;

		/* skip the new created node with the default value */
		if (new_value && (oper == SR_OP_CREATED) && new_value->dflt) {
			sr_free_val(old_value);
			sr_free_val(new_value);
			continue;
		}

		if (value->type == SR_LIST_T || value->type == SR_CONTAINER_T ||
						value->type == SR_CONTAINER_PRESENCE_T) {
			sr_free_val(old_value);
			sr_free_val(new_value);
			continue;
		}

                index = sr_xpath_key_value(value->xpath, "instance", "instance-index",&xp_ctx);
                if (!index) {
                        sr_free_val(old_value);
                        sr_free_val(new_value);
                        continue;
                }

                instance_id = strtoul(index, NULL, 0);

		sr_xpath_recover(&xp_ctx);
		nodename = sr_xpath_node_name(value->xpath);
		if (!nodename) {
			LOG_ERR(" nodename is NULL");
			rc = SR_ERR_INVAL_ARG;
			sr_free_val(old_value);
			sr_free_val(new_value);
			goto err;
		}

		get_actual_node_name_if_augmented(nodename);

		if (get_data_set_name_based_on_nodename(session, value, &parent) != 0) {
			LOG_ERR(" get_data_set_name_based_on_nodename failed");
			rc = SR_ERR_INVAL_ARG;
			sr_free_val(old_value);
			sr_free_val(new_value);
			goto err;
		}

		if (!strcmp(parent->name,"clock-quality") || !strcmp(parent->name,"current-time")) {
			ds = parent->parent;
			is_cntr_present = 1;
		} else {
			ds = parent;
			is_cntr_present = 0;
		}

		if (!strcmp(ds->name,GPTP_NAME_DEFAULT_DS) ||
				!strcmp(ds->name,GPTP_NAME_TIME_PROPERTIES_DS)) {
			if (config_gptp(value,nodename,ds->name,instance_id,false,0,
					is_cntr_present,parent->name) != 0) {
				LOG_ERR(" config_gptp failed");
				rc = SR_ERR_INVAL_ARG;
				sr_free_val(old_value);
				sr_free_val(new_value);
				goto err;
			}
		}

		sr_free_val(old_value);
		sr_free_val(new_value);
	}


	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
err:
	sr_free_change_iter(it);
	return rc;
}

int gptp_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
			const char *module_name, const char *path,
			sr_event_t event, uint32_t request_id,
			void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	RETURN_IF_NOT_DEFAULT_EV(event);

	LOG_DBG(" gPTP: start callback(%d): %s", (int)event, path);

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", PTP_INSTANCE_XPATH);
	rc = gptp_parse(session, xpath, false);

	if (rc) {
		return SR_ERR_CALLBACK_FAILED;
	} else {
		return SR_ERR_OK;
	}
}

int gptp_port_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
			const char *module_name, const char *path,
			sr_event_t event, uint32_t request_id,
			void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	RETURN_IF_NOT_DEFAULT_EV(event);

	LOG_DBG(" gPTP: start port callback(%d): %s", (int)event, path);

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", PTP_PORT_XPATH);
	rc = gptp_port_parse(session, xpath, false);

	if (rc) {
		return SR_ERR_CALLBACK_FAILED;
	} else {
		return SR_ERR_OK;
	}
}

int get_data_type_and_size(const struct lysc_node *snode,uint8_t *data_type, uint8_t *data_size)
{
	const struct lysc_node_leaf *leaf = (const struct lysc_node_leaf *)snode;
	const struct lysc_type *type = leaf->type;

	*data_type = type->basetype;
#if 1
	if (type->basetype == LY_TYPE_STRING) {
		const struct lysc_type_str *str = (const struct lysc_type_str *)type;

		if (str->length) {
			LOG_DBG(" String min %u, max %u",str->length->parts->min_64, str->length->parts->max_64);
		}
		//*data_size = 
	}
#endif
	return 0;
}

int prepare_output_string_from_data(char *str, uint8_t size, uint8_t *data,
					const struct lysc_node *snode,
					uint8_t data_type, uint8_t string_size)
{
	uint8_t data_size = 0;
	uint8_t i,j;
	int64_t int64_value = 0;
	int64_t uint64_value = 0;

	switch (data_type) {
		case LY_TYPE_UINT8:
			LOG_DBG(" node: %s, type: LY_TYPE_UINT8, value %d ",snode->name,((uint8_t *)data)[0]);
			snprintf(str, size - 1, "%d",((uint8_t *)data)[0]);
			break;
		case LY_TYPE_INT8:
			LOG_DBG(" node: %s, type: LY_TYPE_INT8, value %d ",snode->name,((int8_t *)data)[0]);
			snprintf(str, size - 1, "%d",((int8_t *)data)[0]);
			break;
		case LY_TYPE_UINT16:
			LOG_DBG(" node: %s, type: LY_TYPE_UINT16, value %d ",snode->name,((uint16_t *)data)[0]);
			snprintf(str, size - 1, "%d",((uint16_t *)data)[0]);
			break;
		case LY_TYPE_INT16:
			LOG_DBG(" node: %s, type: LY_TYPE_INT16, value %d ",snode->name,((int16_t *)data)[0]);
			snprintf(str, size - 1, "%d",((int16_t *)data)[0]);
			break;
		case LY_TYPE_UINT32:
#ifdef __linux__
			LOG_DBG(" node: %s, type: LY_TYPE_UINT32, value %d ",snode->name,((uint32_t *)data)[0]);
			snprintf(str, size - 1, "%d",((uint32_t *)data)[0]);
#else
			LOG_DBG(" node: %s, type: LY_TYPE_UINT32, value %ld ",snode->name,((uint32_t *)data)[0]);
			snprintf(str, size - 1, "%ld",((uint32_t *)data)[0]);
#endif
			break;
		case LY_TYPE_INT32:
#ifdef __linux__
			LOG_DBG(" node: %s, type: LY_TYPE_INT32, value %d ",snode->name,((int32_t *)data)[0]);
			snprintf(str, size - 1, "%d",((int32_t *)data)[0]);
#else
			LOG_DBG(" node: %s, type: LY_TYPE_INT32, value %ld ",snode->name,((int32_t *)data)[0]);
			snprintf(str, size - 1, "%ld",((int32_t *)data)[0]);
#endif
			break;
		case LY_TYPE_UINT64:
			memcpy(&uint64_value,data,sizeof(uint64_value));
#ifdef __linux__
			LOG_DBG(" node: %s, type: LY_TYPE_UINT64, value %lu ",snode->name,uint64_value);
			snprintf(str, size - 1, "%lu",uint64_value);
#else
			LOG_DBG(" node: %s, type: LY_TYPE_UINT64, value %llu ",snode->name,uint64_value);
			snprintf(str, size - 1, "%llu",uint64_value);
#endif
			break;
		case LY_TYPE_INT64:
			memcpy(&int64_value,data,sizeof(int64_value));
#ifdef __linux__
			LOG_DBG(" node: %s, type: LY_TYPE_INT64, value %lu ",snode->name,int64_value);
			snprintf(str, size - 1, "%lu",int64_value);
#else
			LOG_DBG(" node: %s, type: LY_TYPE_INT64, value %llu ",snode->name,int64_value);
			snprintf(str, size - 1, "%llu",int64_value);
#endif
			break;
		case LY_TYPE_BOOL:
			LOG_DBG(" node: %s, type: LY_TYPE_BOOL, value %d ",snode->name,((uint8_t *)data)[0]);
			if (((uint8_t *)data)[0] == 0)
				snprintf(str, size - 1, "%s","false");
			else if (((uint8_t *)data)[0] == 1)
				snprintf(str, size - 1, "%s","true");
			else {
				LOG_ERR(" invalid bool value");
			}

			break;
		case LY_TYPE_ENUM:
			LOG_DBG(" node: %s, type: LY_TYPE_ENUM, value %d ",snode->name,((uint8_t *)data)[0]);
			j = ((uint8_t *)data)[0];
			if (!strcmp(snode->name, "port-state") && (j >= 1) && (j <= 9)) {
				strcpy(str,port_state_string[j]);
			}
			break;
		case LY_TYPE_IDENT:
			LOG_DBG(" node: %s, type: LY_TYPE_IDENT, value %d ",snode->name,((uint8_t *)data)[0]);
			if (!strcmp(snode->name, "time-source")) {
				if (gptp_time_source_get_identity_ref_from_value(str,((uint8_t *)data)[0]) != 0)
					goto err;
			} else if (!strcmp(snode->name, "clock-class")) {
				if (gptp_clock_class_get_identity_ref_from_value(str,((uint8_t *)data)[0]) != 0)
					goto err;
			} else if (!strcmp(snode->name, "clock-accuracy")) {
				if (gptp_clock_accuracy_get_identity_ref_from_value(str,((uint8_t *)data)[0]) != 0)
					goto err;
			} else {
				LOG_ERR(" invalid indentityref type");
				goto err;
			}
			break;
		case LY_TYPE_STRING:
			LOG_DBG(" node: %s, type: LY_TYPE_STRING ",snode->name);
			if (!strcmp(snode->name,"clock-identity") || !strcmp(snode->name,"grandmaster-identity") ||
								!strcmp(snode->name,"last-gm-freq-change")) {
				string_size = 23;	
			} else if (!strcmp(snode->name,"last-gm-phase-change") ||
						!strcmp(snode->name,"sync-receipt-timeout-interval")) {
				string_size = 35;	
			} else {
				LOG_ERR(" invalid string type");
				goto err;
			}

			data_size = (string_size+1)/3;

			for (i = 0,j = 0;i < data_size;i++) {
				sprintf(&str[(i*2) + j], "%02X",((uint8_t *)data)[i]);
				if (j < (data_size -1))
					str[((i+1)*2) + j] = '-';
				j++;
			}
			break;
		default:
			LOG_DBG(" data_type is default");
			goto err;
	}

	return 0;

err:
	return -1;
}

int gptp_get_node_value(char *str, uint8_t size, const char *ds_name,
			const struct lysc_node *snode, uint32_t instance_id,
			bool is_port, uint16_t port_id,
			bool is_cntr_present, const char *cntr_name)
{
	struct genavb_msg_managed_get_response get_response;
	struct genavb_mobj_cmd cmd;
	uint8_t buf[BUF_LEN];
	uint16_t length, status, total_length, node_id;
	int id;
	uint8_t *data;
	uint8_t data_type = 0, string_size = 0;
	const char *name = ds_name;

	if (get_data_type_and_size(snode,&data_type,&string_size) != 0) {
		LOG_ERR(" get_data_type_and_size failed");
		goto err;
	}

	genavb_mobj_cmd_init(&cmd, (uint8_t *)buf, BUF_LEN);

	if ((id = genavb_mobj_gptp_node_id(NULL, "instance")) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if ((id = genavb_mobj_gptp_node_id("instance", "instance-index")) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (genavb_mobj_cmd_set_list_index(&cmd, id, instance_id) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (!is_port) {
		if ((id = genavb_mobj_gptp_node_id("instance", ds_name)) < 0) {
			LOG_ERR(" %s: genavb_mobj_gptp_node_id for failed ds %s",__FUNCTION__,ds_name);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	} else {
		if ((id = genavb_mobj_gptp_node_id("instance", "ports")) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if ((id = genavb_mobj_gptp_node_id("ports", "port")) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if ((id = genavb_mobj_gptp_node_id("port", "port-index")) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_set_list_index(&cmd, id, port_id) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if ((id = genavb_mobj_gptp_node_id("ports", ds_name)) < 0) {
			LOG_ERR(" %s: failed at line %d ds_name=%s",__FUNCTION__, __LINE__, ds_name);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	}

	if (is_cntr_present) {
		if ((id = genavb_mobj_gptp_node_id(ds_name,cntr_name)) < 0) {
			LOG_ERR(" %s: genavb_mobj_gptp_node_id failed for container %s in ds %s",__FUNCTION__,cntr_name,ds_name);
			goto err;
		}

		if (genavb_mobj_cmd_start_node(&cmd, id) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		name = cntr_name;
	}

	if ((id = genavb_mobj_gptp_node_id(name, snode->name)) < 0) {
		LOG_ERR(" %s: genavb_mobj_gptp_node_id failed for container %s, node %s",__FUNCTION__,name,snode->name);
		goto err;
	}

	if (genavb_mobj_cmd_get_leaf(&cmd, id) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (is_cntr_present) {
		if (genavb_mobj_cmd_end_node(&cmd) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	}

	if (genavb_mobj_cmd_end_node(&cmd) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	if (is_port) {
		if (genavb_mobj_cmd_end_node(&cmd) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}

		if (genavb_mobj_cmd_end_node(&cmd) < 0) {
			LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
			goto err;
		}
	}

	if (genavb_mobj_cmd_end_node(&cmd) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	LOG_INF(" %s: genavb_mobj_cmd_len %u",__FUNCTION__, genavb_mobj_cmd_len(&cmd));
	uint16_t *tmpU16 = (uint16_t *)genavb_mobj_cmd_buf(&cmd);
	for (int i = 0; i < genavb_mobj_cmd_len(&cmd) / 2; i++)
		LOG_INF("%s: cmd[%u] = %u",__FUNCTION__, i, tmpU16[i]);

	LOG_INF(" %s: name %s snode->name %s",__FUNCTION__, name, snode->name);

	int rc = managed_get(gptp_get_genavb_ctrl(), genavb_mobj_cmd_buf(&cmd), genavb_mobj_cmd_len(&cmd), &get_response, sizeof(get_response));
	if (rc < 0) {
		LOG_ERR(" %s: failed at line %d - rc %d",__FUNCTION__, __LINE__, rc);
		goto err;
	}

	if (genavb_mobj_rsp_check((u_int8_t *)&get_response) < 0) {
		LOG_ERR(" %s: failed at line %d",__FUNCTION__, __LINE__);
		goto err;
	}

	/* instance node header */
	data = get_node_header((uint8_t *)&get_response, &node_id, &total_length, &status);
	LOG_INF("id %u total_length %u status %u", node_id, total_length, status);

	/* instance entry key header */
	data = get_node_header(data, &node_id, &length, &status);
	LOG_INF("id %u length %u status %u", node_id, length, status);
	data = get_node_next(data, length);

	if (is_port) {
		/* ports node header */
		data = get_node_header(data, &node_id, &length, &status);
		LOG_INF("id %u length %u status %u", node_id, length, status);

		/* port node header */
		data = get_node_header(data, &node_id, &length, &status);
		LOG_INF("id %u length %u status %u", node_id, length, status);

		/* port entry key header */
		data = get_node_header(data, &node_id, &length, &status);
		LOG_INF("id %u length %u status %u", node_id, length, status);
		data = get_node_next(data, length);
	}

	/* container ds */
	data = get_node_header(data, &node_id, &length, &status);
	LOG_INF("id %u length %u status %u", node_id, length, status);

	if (is_cntr_present) {
		/* optional sub-container header */
		data = get_node_header(data, &node_id, &length, &status);
		LOG_INF("id %u length %u status %u", node_id, length, status);
	}

	/* leaf header */
	data = get_node_header(data, &node_id, &length, &status);
	LOG_INF("id %u length %u status %u", node_id, length, status);
	if (!status) {
		for (int i = 0; i < length - 2; i++)
			LOG_INF(" data[%u] %u ", i, data[i]);
		if (prepare_output_string_from_data(str, size, data, snode,data_type,string_size) != 0) {
			LOG_ERR(" prepare_output_string_from_data failed");
			goto err;
		}
		return 0;
	} else {
		LOG_ERR(" get_node_header, status is non-zero for node %s, ds %s",snode->name,ds_name);
	}

err:
	return -1;
}


void get_node_name_from_lysc_path(const struct lysc_node *snode, const char *match_name, char *name)
{
	char *s_path = NULL;
        char *pch;
        int stop = 0;

	s_path = lysc_path(snode,LYSC_PATH_DATA,NULL,0);
	if (s_path == NULL) {
		LOG_ERR(" lysc_path failed");
		return;
	}

	//LOG_DBG(" s_path %s",s_path);
        pch = strtok (s_path,"/");
        while (pch != NULL)
        {
                pch = strtok (NULL, "/");
                if (stop == 1) {
			strcpy(name,pch);
                        break;
		}
                if (!strcmp(pch,match_name))
                        stop = 1;
        }

	free(s_path);
	return;
}


int gptp_write_port_nodes(struct lyd_node **root, const struct ly_ctx *ctx,
			const struct lysc_node *ds,const struct lysc_node *snode,
			uint32_t instance_id,uint16_t port_id,
			bool is_cntr_present, const char *cntr_name)
{
	int rc = SR_ERR_INTERNAL;
	char xpath[XPATH_MAX_LEN] = {};
	char str[MAX_SIZE];
	char name[64];

	if (!strcmp(ds->name, "port-ds")) {
		if (is_cntr_present) {
			get_node_name_from_lysc_path(snode, cntr_name, name);
			PREPARE_PORT_XPATH_WITH_CNTR(PTP_INSTANCE_XPATH, instance_id, port_id, ds->name, cntr_name, name);
		} else {
			get_node_name_from_lysc_path(snode, ds->name, name);
			PREPARE_PORT_XPATH(PTP_INSTANCE_XPATH, instance_id, port_id, ds->name, name);
		}
	} else if (!strcmp(ds->name, "port-statistics-ds")) {
		get_node_name_from_lysc_path(snode, "port", name);
		PREPARE_PORT_XPATH(PTP_INSTANCE_XPATH, instance_id, port_id, name, snode->name);
	} else {
		goto cleanup;
	}

	if (gptp_get_node_value(str, MAX_SIZE,ds->name, snode, instance_id,
				true, port_id,is_cntr_present,cntr_name) == 0) {
		LOG_DBG(" writing %s with value %s",xpath,str);
		LY_NEW_PATH(*root, ctx, xpath, str, 0, NULL);
	}

	rc = SR_ERR_OK;

cleanup:
	return rc;
}

int gptp_write_instance_nodes(struct lyd_node **root, const struct ly_ctx *ctx,
		const struct lysc_node *ds,const struct lysc_node *snode,
		uint32_t instance_id, bool is_cntr_present, const char *cntr_name)
{
	int rc = SR_ERR_INTERNAL;
	char xpath[XPATH_MAX_LEN] = {};
	char name[64];
	char str[MAX_SIZE];

	if (is_cntr_present) {
		get_node_name_from_lysc_path(snode,cntr_name, name);
		PREPARE_XPATH_WITH_CNTR(PTP_INSTANCE_XPATH, instance_id,ds->name,cntr_name,name)
	} else {
		get_node_name_from_lysc_path(snode,ds->name, name);
		PREPARE_XPATH(PTP_INSTANCE_XPATH, instance_id,ds->name,name);
	}

	if (gptp_get_node_value(str, MAX_SIZE,ds->name, snode, instance_id,
				false, 0,is_cntr_present,cntr_name) == 0) {
		LOG_DBG(" writing %s with value %s",xpath,str);
		LY_NEW_PATH(*root, ctx, xpath, str, 0, NULL);
	}

	rc = SR_ERR_OK;

cleanup:
	return rc;
}

int traverse_instance_schema_nodes_and_write_data(const struct ly_ctx *ctx,struct lyd_node **root,
			const struct lysc_node *snode,uint32_t instance_id, uint16_t port_id)
{
	const struct lysc_node *child;
	const struct lysc_node *parent = NULL; 
	const struct lysc_node *ds = NULL; 
	bool is_cntr_present;

	LOG_INF(" LEAF snode %s, nodetype %d parent %s",snode->name, snode->nodetype, snode->parent->name);

	if ((snode->flags & LYS_CONFIG_R) && (snode->nodetype & LYS_LEAF)) {
		parent = snode->parent; 
		while (parent && parent->nodetype != LYS_CONTAINER) {
			parent = parent->parent;
		}

		LOG_INF(" parent %s", parent->name);

		if (!strcmp(parent->name,"parent-port-identity") ||
			!strcmp(parent->name,"grandmaster-clock-quality") ||
			!strcmp(parent->name,"current-time") ||
			!strcmp(parent->name,"clock-quality")) {
			ds = parent->parent;
			is_cntr_present = 1;
		} else {
			ds = parent;
			is_cntr_present = 0;
		}

		if (!strcmp(ds->name,"default-ds") || !strcmp(ds->name,"current-ds") ||
					!strcmp(ds->name,"parent-ds")) {
			if (gptp_write_instance_nodes(root,ctx,ds,snode,instance_id,
							is_cntr_present,parent->name) != SR_ERR_OK) {
				LOG_ERR(" gptp_write_instance_nodes failed for node %s",snode->name);
				return SR_ERR_INTERNAL;
			}
		}
	}

	for (child = lysc_node_child(snode);child;child = child->next) {
		if (traverse_instance_schema_nodes_and_write_data(ctx,root,child,instance_id,port_id) != SR_ERR_OK) {
			return SR_ERR_INTERNAL;
		}
	}

	return SR_ERR_OK;
}

int traverse_port_schema_nodes_and_write_data(const struct ly_ctx *ctx,struct lyd_node **root,
			const struct lysc_node *snode,uint32_t instance_id, uint16_t port_id)
{
	const struct lysc_node *child;
	const struct lysc_node *parent = NULL; 
	const struct lysc_node *ds = NULL;
	bool is_cntr_present;

	if ((snode->flags & LYS_CONFIG_R) && (snode->nodetype & LYS_LEAF)) {
		//LOG_DBG(" LEAF snode %s, nodetype %d",snode->name,snode->nodetype);

		parent = snode->parent; 
		while (parent && parent->nodetype != LYS_CONTAINER) {
			parent = parent->parent;
		}

		if (!strcmp(parent->name,"port-identity")) {
			ds = parent->parent;
			is_cntr_present = 1;
		} else {
			ds = parent;
			is_cntr_present = 0;
		}

		if (!strcmp(ds->name,"port-ds") || !strcmp(ds->name,"port-statistics-ds")) {
			if (gptp_write_port_nodes(root,ctx,ds,snode,instance_id,port_id,
						is_cntr_present,parent->name) != SR_ERR_OK) {
				LOG_ERR(" gptp_write_port_nodes failed for node %s",snode->name);
				return SR_ERR_INTERNAL;
			}
		}
	}

	for (child = lysc_node_child(snode);child;child = child->next) {
		if (traverse_port_schema_nodes_and_write_data(ctx,root,child,instance_id,port_id) != SR_ERR_OK) {
			return SR_ERR_INTERNAL;
		}
	}

	return SR_ERR_OK;
}

int verify_received_instance_id(sr_session_ctx_t *session,uint32_t instance_id)
{
	sr_val_t *vals = NULL;
	size_t count = 0;
	int rc, i, ret = -1;
	sr_session_ctx_t *new_sess = NULL;
	
	GET_RUNNING_DS_SESS_ANG_GET_ITEMS(session,new_sess,PTP_INSTANCE_INDEX_XPATH,vals,count);

	for (i = 0;i < count;i++) {
		if (instance_id == vals[i].data.uint32_val) {
			LOG_DBG(" instance_id %d matched with running DS",instance_id);
			ret = 0;
			break;
		}
	}

	sr_free_values(vals, count);
	sr_session_stop(new_sess);
	return ret;

}

int verify_received_port_id(sr_session_ctx_t *session,uint32_t instance_id, uint16_t port_id)
{
	sr_val_t *port_vals = NULL;
	size_t port_count = 0;
	int rc, j, ret = -1;
	sr_session_ctx_t *new_sess = NULL;
	char xpath[XPATH_MAX_LEN] = {0,};
	
	snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%d']/ports/port/port-index",PTP_INSTANCE_XPATH,instance_id);
	GET_RUNNING_DS_SESS_ANG_GET_ITEMS(session,new_sess,xpath,port_vals,port_count);

	for (j = 0;j < port_count;j++) {
		if (port_id == port_vals[j].data.uint16_val) {
			LOG_DBG(" port_id %d matched with running DS",port_id);
			ret = 0;
			break;
		}
	}

	sr_free_values(port_vals, port_count);
	sr_session_stop(new_sess);
	return ret;

}

int get_port_ids_from_running_ds(sr_session_ctx_t *session, uint32_t instance_id)
{
	sr_val_t *port_vals = NULL;
	size_t port_count = 0;
	int rc,j;
	sr_session_ctx_t *new_sess = NULL;
	char xpath[XPATH_MAX_LEN] = {0,};
	
	snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%d']/ports/port/port-index",PTP_INSTANCE_XPATH,instance_id);
	GET_RUNNING_DS_SESS_ANG_GET_ITEMS(session,new_sess,xpath,port_vals,port_count);

	for (j = 0;j < port_count;j++) {
		SET_PORT_ID_INFO(instance_id,instance_id_g[instance_id],port_vals[j].data.uint16_val,j,port_info_g[instance_id].max_ports +1);
		LOG_DBG(" From running DS: port_id %d",port_info_g[instance_id].port_id[j]);
	}

	sr_free_values(port_vals, port_count);
	sr_session_stop(new_sess);
	return 0;
}

int get_instance_and_port_ids_from_running_ds(sr_session_ctx_t *session)
{
	sr_val_t *vals = NULL;
	sr_val_t *port_vals = NULL;
	size_t count = 0;
	size_t port_count = 0;
	int rc, i, j;
	sr_session_ctx_t *new_sess = NULL;
	char xpath[XPATH_MAX_LEN] = {0,};
	
	GET_RUNNING_DS_SESS_ANG_GET_ITEMS(session,new_sess,PTP_INSTANCE_INDEX_XPATH,vals,count);

	for (i = 0;i < count;i++) {
		SET_INSTANCE_INFO(i,vals[i].data.uint32_val,(num_instances_g + 1));
		LOG_DBG(" From running DS: instance_id %d",instance_id_g[i]);

		snprintf(xpath, XPATH_MAX_LEN, "%s[instance-index='%d']/ports/port/port-index",PTP_INSTANCE_XPATH,instance_id_g[i]);
		rc = sr_get_items(new_sess,xpath,0,0,&port_vals,&port_count);
		if (rc == SR_ERR_OK) {
			for (j = 0;j < port_count;j++) {
				SET_PORT_ID_INFO(i,instance_id_g[i],port_vals[j].data.uint16_val,j,port_info_g[i].max_ports +1);
				LOG_DBG(" From running DS: port_id %d",port_info_g[i].port_id[j]);
			}
			sr_free_values(port_vals, port_count);
		}
	}

	sr_free_values(vals, count);
	sr_session_stop(new_sess);
	return 0;
}

int get_instance_and_port_ids(sr_session_ctx_t *session,const char *request_xpath)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *index = NULL;

	memset(&instance_id_g,0,(sizeof(uint32_t)*MAX_INDICES));
	num_instances_g = 0;
	memset(&port_info_g,0,(sizeof(struct gptp_port_instance)*MAX_INDICES));

	/* Get instance-index and port-index from the provided request_xpath. */
	index = sr_xpath_key_value((char *)request_xpath, "instance", "instance-index",&xp_ctx);
	if (index) {
		SET_INSTANCE_INFO(0,strtoul(index, NULL, 0),1);

		if (verify_received_instance_id(session,instance_id_g[0]) != 0) {
			LOG_ERR(" Requested instance_id %d is not valid",instance_id_g[0]);
			return -1;
		}
		LOG_DBG(" Requested instance_id is %d ",instance_id_g[0]);

		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value((char *)request_xpath, "port", "port-index",&xp_ctx);
		if (index) {
			SET_PORT_ID_INFO(0,(instance_id_g[0]),strtoul(index, NULL, 0),0,1);

			if (verify_received_port_id(session,instance_id_g[0], port_info_g[0].port_id[0]) != 0) {
				LOG_ERR(" Requested port id is %d is not valid",port_info_g[0].port_id[0]);
				return -1;
			}
			LOG_DBG(" Requested port id is %d",port_info_g[0].port_id[0]);

		} else {
			LOG_DBG(" Getting port_indices from the running data store");
			if (get_port_ids_from_running_ds(session,instance_id_g[0]) != 0) {
				LOG_ERR(" get_port_ids_from_running_ds failed");
			}
		}
	} else {
		/* Get configured instance-index and port-index from the running data store. */
		LOG_DBG(" Getting instance_indices and port_indices from the running data store");
		if (get_instance_and_port_ids_from_running_ds(session) != 0) {
			LOG_ERR(" get_instance_and_port_ids_from_running_ds failed");
		}
	}

	return 0;
}

static int gptp_subtree_get_cb(sr_session_ctx_t *session, uint32_t sub_id,
		       const char *module_name, const char *path,
		       const char *request_xpath, uint32_t operation_id,
		       struct lyd_node **parent, void *private_data)
{
	int rc = SR_ERR_INTERNAL;
	const struct lysc_node *snode = NULL; 
	const struct ly_ctx *ctx = NULL; 
	struct ly_set *set = NULL;
	uint32_t instance_id = 0;
	uint16_t port_id = 0;
	int i, j, k;

	LOG_DBG(" %s:%d, gPTP get callback operation_id %d, path %s, req_xpath %s  ", __FUNCTION__, __LINE__, operation_id, path, request_xpath);

	if (operation_id != gptp_get_operation_id_g) {
		gptp_get_operation_id_g = operation_id;
	} else {
		LOG_DBG(" %s:%d, gPTP get callback called for same oper id, %d, %d ", __FUNCTION__, __LINE__, gptp_get_operation_id_g, operation_id);
		return SR_ERR_OK;
	}

	ctx = sr_session_acquire_context(session);
	if (!ctx) {
		LOG_ERR(" ctx failed");
		goto cleanup;
	}

	if (lys_find_xpath(ctx,NULL,request_xpath,0,&set) != LY_SUCCESS) {
		LOG_ERR(" lys_find_xpath failed");
		goto cleanup;
	}

	if (!set || set->count == 0) {
		LOG_ERR(" set is NULL or count is 0");
		goto cleanup;
	}

	if (get_instance_and_port_ids(session,request_xpath) != 0) {
		LOG_DBG(" get_instance_and_port_ids failed");
		rc = SR_ERR_OK;
		goto cleanup;
	}

	for (j = 0;j < num_instances_g;j++) {
		LOG_DBG(" j %d, instance_id %d, num_instances_g %d",j,instance_id_g[j],num_instances_g);
		instance_id = instance_id_g[j];
		for (i = 0; i < set->count; i++) {
			GET_SCHEMA_NODE(snode,set,i);
			if (traverse_instance_schema_nodes_and_write_data(ctx,parent,
					snode,instance_id,port_id) != SR_ERR_OK) {
				goto cleanup;
			}
		}

		for (k = 0;k < port_info_g[j].max_ports;k++) {
			LOG_DBG(" k %d, instance_id %d, port_id %d, max_ports %d",k,instance_id_g[j],port_info_g[j].port_id[k],port_info_g[j].max_ports);
			port_id = port_info_g[j].port_id[k];
			for (i = 0; i < set->count; i++) {
				GET_SCHEMA_NODE(snode,set,i);
				if (traverse_port_schema_nodes_and_write_data(ctx,parent,snode,
					instance_id,port_id)!= SR_ERR_OK) {
					goto cleanup;
				}
			}
		}
	}

        rc = SR_ERR_OK;

cleanup:
	if (set)
		ly_set_free(set,NULL);

        if (ctx)
                sr_session_release_context(session);

	return rc;
}

int sysrepo_genavb_gptp_init(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription)
{
	int rc;

	/* Below two macros return error incase of failure while subscribing */

	/* Subscribe to gPTP subtree */
	rc = sr_module_change_subscribe(session, PTP_MODULE, PTP_INSTANCE_XPATH, gptp_subtree_change_cb, NULL, 0,
			SR_SUBSCR_ENABLED | SR_SUBSCR_DONE_ONLY, subscription);
    if (rc != SR_ERR_OK) {
		LOG_ERR("Failed to subscribe for \"%s\" (%s).", PTP_INSTANCE_XPATH, sr_strerror(rc));
		goto error;
    } else {
		LOG_INF("Subscribed changes for %s", PTP_INSTANCE_XPATH);
	}

	/* Subscribe to gPTP subtree */
	rc = sr_module_change_subscribe(session, PTP_MODULE, PTP_PORT_XPATH, gptp_port_subtree_change_cb, NULL, 0,
			SR_SUBSCR_ENABLED | SR_SUBSCR_DONE_ONLY, subscription);
    if (rc != SR_ERR_OK) {
		LOG_ERR("Failed to subscribe for \"%s\" (%s).", PTP_PORT_XPATH, sr_strerror(rc));
		goto error;
	} else {
        LOG_INF("Subscribed changes for %s", PTP_PORT_XPATH);
	}

	/* Subscribe to get gPTP subtree */
	rc = sr_oper_get_subscribe(session, PTP_MODULE, PTP_INSTANCES_XPATH, gptp_subtree_get_cb, NULL, 0, subscription);
	if (rc != SR_ERR_OK) {
		LOG_ERR("Failed to subscribe for \"%s\" (%s).", PTP_INSTANCES_XPATH, sr_strerror(rc));
		goto error;
	} else {
		LOG_INF("Subscribed get for %s", PTP_INSTANCES_XPATH);
	}

	gptp_identity_refs_init();

error:
	return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	char *xpath = PTP_ROOT_XPATH;
	void *avb_h = NULL;
	int rc;

	rc = gptp_genavb_init(&avb_h);
	if (rc < 0) {
		LOG_ERR("gptp_genavb_init() error");
		rc = SR_ERR_INTERNAL;
		goto error_genavb_init;
	}

	*private_data = avb_h;

	rc = sysrepo_genavb_gptp_init(session, &subscription);
	if (rc < 0) {
		LOG_ERR("sysrepo_genavb_gptp_init() error");
		goto error_subscribe;
	}

	LOG_INF("GenAVB/TSN PTP plugin subscribed for %s", xpath);

	return SR_ERR_OK;

error_subscribe:
	if (avb_h)
		gptp_genavb_exit(avb_h);

error_genavb_init:
	return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *running_session, void *private_data)
{
	sr_unsubscribe(subscription);

	if (private_data)
		gptp_genavb_exit(private_data);

	LOG_INF("GenAVB/TSN PTP plugin cleanup finished.");
}

