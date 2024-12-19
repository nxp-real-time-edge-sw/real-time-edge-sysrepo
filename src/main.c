/**
 * @file main.c
 * @author Xiaolin He
 * @brief Application to configure TSN function based on sysrepo datastore.
 *
 * Copyright 2019-2024 NXP
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <cjson/cJSON.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "main.h"
#include "qbv.h"
#include "qbu.h"
#include "file_mon.h"
#include "cb_streamid.h"
#include "qci.h"
#include "ip_cfg.h"
#include "vlan_cfg.h"
#include "mac_cfg.h"
#include "brtc_cfg.h"
#include "cb.h"


#define SR_CONFIG_SUBSCR(mod_name, xpath, cb)								\
    rc = sr_module_change_subscribe(session, mod_name, xpath, cb, NULL, 0, 	\
           	SR_SUBSCR_DONE_ONLY | SR_SUBSCR_ENABLED, &subscription);		\
    if (rc != SR_ERR_OK) {													\
        fprintf(stderr, "Subscribing for \"%s\" data changes failed (%s).",	\
                mod_name, sr_strerror(rc));									\
        goto cleanup;														\
    }

static volatile uint8_t exit_application;

static void sigint_handler(int signum)
{
	exit_application = 1;
}

/* tsn_operation_monitor_cb()
 * file callback
 */
void tsn_operation_monitor_cb(void)
{
}

struct sr_tsn_callback file_clbks = {
	.callbacks_count = 1,
	.callbacks = {
		{
			.f_path = "/tmp/tsn-oper-record.json",
			.func = tsn_operation_monitor_cb
		},
	}
};

void check_pid_file(void)
{
	char pid_file[] = "/var/run/sysrepo-tsn.pid";
	char str[20] = { 0 };
	int ret = 0;
	int fd;

	/* open PID file */
	fd = open(pid_file, O_RDWR | O_CREAT, 0640);
	if (fd < 0) {
		printf("Unable to open sysrepo PID file '%s': %s.\n",
		       pid_file, strerror(errno));
		exit(1);
	}

	/* acquire lock on the PID file */
	if (lockf(fd, F_TLOCK, 0) < 0) {
		if (EACCES == errno || EAGAIN == errno) {
			printf("Another instance of sysrepo-tsn %s\n",
			       "daemon is running, unable to start.");
		} else {
			printf("Unable to lock sysrepo PID file '%s': %s.",
			       pid_file, strerror(errno));
		}
		close(fd);
		exit(1);
	}

	/* write PID into the PID file */
	snprintf(str, 20, "%d\n", getpid());
	ret = write(fd, str, strlen(str));
	if (-1 == ret) {
		printf("ERR: Unable to write into sysrepo PID file '%s': %s.",
		       pid_file, strerror(errno));
		close(fd);
		exit(1);
	}

	close(fd);
}

int main(int argc, char **argv)
{
	int rc = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	sr_subscription_ctx_t *subscription = NULL;
	int daemonize = 1;
    char *mod_name = NULL;
    char *xpath = NULL;

	exit_application = 0;

	if ((argc >= 2) && !strncmp(argv[1], "-d", 2)) {
		printf("Enter Debug Mode!\n");
		daemonize = 0;
	}

	/* daemonize */
	if (daemonize == 1) {
		if (daemon(0, 0) != 0) {
			printf("Daemonizing sysrepo-tsn failed (%s)",
					strerror(errno));
			return rc;
		}
	}

	/* Check pid file */
	check_pid_file();

#ifdef CONF_MONITOR
	/* Init file callbacks */
	sr_tsn_fcb_init();
#endif

	/* Init tsn mutex */
	init_tsn_mutex();

#ifdef SYSREPO_TSN_TC
	qci_init_para();
#endif

	/* Connect to sysrepo */
	rc = sr_connect(SR_CONN_DEFAULT, &connection);
	if (rc != SR_ERR_OK) {
		fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
		goto cleanup;
	}

	/* Start session */
	rc = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (rc != SR_ERR_OK) {
		fprintf(stderr, "Error by sr_session_start: %s\n",
			sr_strerror(rc));
		goto cleanup;
	}

    mod_name = "ietf-interfaces";

    /* Subscribe to IP_CFG subtree */
    xpath = "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4";
    SR_CONFIG_SUBSCR(mod_name, xpath, ip_subtree_change_cb);

	/* Subscribe to QBV subtree */
	xpath = QBV_GATE_PARA_XPATH;
    SR_CONFIG_SUBSCR(mod_name, xpath, qbv_subtree_change_cb);
	rc = sr_enable_module_feature(connection, QBV_MODULE, QBV_FEATURE);
	if (rc) {
		goto cleanup;
	}

    /* Subscribe to QBU subtree */
	xpath = QBU_PARA_XPATH;
    SR_CONFIG_SUBSCR(mod_name, xpath, qbu_subtree_change_cb);
	rc = sr_enable_module_feature(connection, QBU_MODULE, QBU_FEATURE);
	if (rc) {
		goto cleanup;
	}

    mod_name = "ieee802-dot1q-bridge";

    /* Subscribe to QCI-Stream-Filter subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component"
            "/ieee802-dot1q-psfp-bridge:stream-filters";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_sf_subtree_change_cb);

    /* Subscribe to QCI-Stream-Gate subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component"
            "ieee802-dot1q-psfp-bridge:stream-gates";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_sg_subtree_change_cb);

    /* Subscribe to QCI-Flow-Meter subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component"
            "/ieee802-dot1q-psfp-bridge:flow-meters";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_fm_subtree_change_cb);

    /* Subscribe to VLAN_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component"
            "/bridge-vlan";
    SR_CONFIG_SUBSCR(mod_name, xpath, vlan_subtree_change_cb);

    /* Subscribe to MAC_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/address";
    SR_CONFIG_SUBSCR(mod_name, xpath, mac_subtree_change_cb);

    /* Subscribe to BR_TC_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/"
            "/nxp-bridge-vlan-tc-flower:traffic-control";
    SR_CONFIG_SUBSCR(mod_name, xpath, brtc_subtree_change_cb);


    mod_name = "ieee802-dot1cb-stream-identification";

    /* Subscribe to CB-StreamID subtree */
    xpath = "/ieee802-dot1cb-stream-identification:stream-identity";
    SR_CONFIG_SUBSCR(mod_name, xpath, cb_streamid_subtree_change_cb);


    mod_name = "ieee802-dot1cb-frer";

    /* Subscribe to CB */
    xpath = "/ieee802-dot1cb-frer:frer";
    SR_CONFIG_SUBSCR(mod_name, xpath, cb_subtree_change_cb);

	/* Loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application)
		sleep(1);  /* Or do some more useful work... */

cleanup:
	destroy_tsn_mutex();
	if (subscription)
		sr_unsubscribe(subscription);
	if (session)
		sr_session_stop(session);
	if (connection)
		sr_disconnect(connection);

	return rc;
}
