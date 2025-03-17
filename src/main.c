/**
 * @file main.c
 * @author Xiaolin He
 * @brief Application to configure TSN function based on sysrepo datastore.
 *
 * Copyright 2019-2025 NXP
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
#include "lldp.h"
#include "ptp.h"

#ifdef RT_HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define SR_CONFIG_SUBSCR(mod_name, xpath, cb, prio)							\
    rc = sr_module_change_subscribe(session, mod_name, xpath, cb, NULL, prio, 	\
           	SR_SUBSCR_DONE_ONLY, &subscription);		                    \
    if (rc != SR_ERR_OK) {													\
        LOG_ERR("Failed to subscribe for \"%s\" (%s).",	                    \
                xpath, sr_strerror(rc));									\
    } else {                                                                \
        LOG_INF("Subscribed changes for %s", xpath);                        \
    }

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static volatile uint32_t exit_application = 0;

static int open_pid_file(const char *pid_file)
{
	int fd;

	fd = open(pid_file, O_RDWR | O_CREAT, 0640);
	if (fd < 0) {
		LOG_ERR("Unable to open the PID file '%s' (%s).",
		       pid_file, strerror(errno));
        return -1;
	}

	if (lockf(fd, F_TLOCK, 0) < 0) {
		if (EACCES == errno || EAGAIN == errno) {
			LOG_ERR("Another instance of sysrepo-tsn daemon is running.");
		} else {
			LOG_ERR("Unable to lock sysrepo PID file '%s': %s.",
			       pid_file, strerror(errno));
		}
		close(fd);
        return -1;
	}

    return fd;
}

static int write_pid_file(int pidfd)
{
    char pid[30] = {0};
    int pid_len;

    if (ftruncate(pidfd, 0)) {
        LOG_ERR("Failed to truncate pid file (%s).", strerror(errno));
        return -1;
    }

    snprintf(pid, sizeof(pid) - 1, "%ld\n", (long) getpid());

    pid_len = strlen(pid);
    if (write(pidfd, pid, pid_len) < pid_len) {
        LOG_ERR("Failed to write PID into pid file (%s).", strerror(errno));
        return -1;
    }
    return 0;
}

static void signal_handler(int signum)
{
    pthread_mutex_lock(&lock);

    if (!exit_application) {

	    exit_application = 1;
        pthread_cond_signal(&cond);
    } else {
        LOG_ERR("Exit by force.");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_unlock(&lock);
}

static void handle_signals(void)
{
    struct sigaction action;
    sigset_t block_mask;

    /* set the signal handler */
    sigfillset(&block_mask);
    action.sa_handler = signal_handler;
    action.sa_mask = block_mask;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    /* ignore */
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGTSTP, &action, NULL);
    sigaction(SIGTTIN, &action, NULL);
    sigaction(SIGTTOU, &action, NULL);
}

static void print_usage(char *name)
{
    printf("Usage: %s [-dhv]\r\n", name);
    printf("Options:\r\n");
    printf(" -d         Do not daemonize.\r\n");
    printf(" -v<level>  Change verbosity to a level (1:error, 2:warning, 3:info, 4:debug). 4 by default.\r\n");
    printf(" -h         Display help.\r\n");
}

int main(int argc, char **argv)
{
	int rc = SR_ERR_INTERNAL;
    int ret = EXIT_FAILURE;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	sr_subscription_ctx_t *subscription = NULL;
	int daemonize = 1;
    char *mod_name = NULL;
    char *xpath = NULL;
    char *pid_file = "/var/run/sysrepo-tsn.pid";
    int pid_fd = -1;
    int opt;
    int log_level;

	exit_application = 0;

    while ((opt = getopt(argc, argv, "dhv::")) != -1) {

        switch (opt) {
        case 'd':
		    daemonize = 0;
            break;
        case 'v':
            log_level = LOG_LEVEL_DBG;
            if (optarg) {
                log_level = atoi(optarg);
                log_level = (log_level >= 1) && (log_level <= 4) ?
                                            log_level - 1 : LOG_LEVEL_DBG;
            }
            log_set_output_level(log_level);
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            break;
        }
    }

	/* daemonize */
	if (daemonize == 1) {
        LOG_INF("Enter daemon mode.");
		if (daemon(0, 0) != 0) {
			LOG_ERR("Daemonizing sysrepo-tsn failed (%s)", strerror(errno));
			return EXIT_FAILURE;
		}
	}

    handle_signals();

	/* Check pid file */
	pid_fd = open_pid_file(pid_file);
	if (pid_fd < 0) {
        goto cleanup;
    }

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
		LOG_ERR("sr_connect() error: %s\n", sr_strerror(rc));
		goto cleanup;
	}

	/* Start a session */
	rc = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (rc != SR_ERR_OK) {
		LOG_ERR("sr_session_start() error: %s\n", sr_strerror(rc));
		goto cleanup;
	}

    mod_name = "ietf-interfaces";

    /* Subscribe to the ipv4 subtree */
    xpath = "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4";
    SR_CONFIG_SUBSCR(mod_name, xpath, ip_subtree_change_cb, 1);

    /* Subscribe to QBU subtree */
	xpath = QBU_PARA_XPATH;
    SR_CONFIG_SUBSCR(mod_name, xpath, qbu_subtree_change_cb, 0);

	/* Subscribe to QBV subtree */
	xpath = QBV_GATE_PARA_XPATH;
    SR_CONFIG_SUBSCR(mod_name, xpath, qbv_subtree_change_cb, 0);

    mod_name = "ieee802-dot1q-bridge";

    /* Subscribe to QCI-Stream-Filter subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/ieee802-dot1q-psfp-bridge:stream-filters";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_sf_subtree_change_cb, 0);

    /* Subscribe to QCI-Stream-Gate subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/ieee802-dot1q-psfp-bridge:stream-gates";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_sg_subtree_change_cb, 0);

    /* Subscribe to QCI-Flow-Meter subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/ieee802-dot1q-psfp-bridge:flow-meters";
    SR_CONFIG_SUBSCR(mod_name, xpath, qci_fm_subtree_change_cb, 0);

    /* Subscribe to VLAN_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/bridge-vlan";
    SR_CONFIG_SUBSCR(mod_name, xpath, vlan_subtree_change_cb, 1);

    /* Subscribe to MAC_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/address";
    SR_CONFIG_SUBSCR(mod_name, xpath, mac_subtree_change_cb, 2);

    /* Subscribe to BR_TC_CFG subtree */
    xpath = "/ieee802-dot1q-bridge:bridges/bridge/component/nxp-bridge-vlan-tc-flower:traffic-control";
    SR_CONFIG_SUBSCR(mod_name, xpath, brtc_subtree_change_cb, 0);

    mod_name = "ieee802-dot1cb-stream-identification";
    /* Subscribe to CB-StreamID subtree */
    xpath = "/ieee802-dot1cb-stream-identification:stream-identity";
    SR_CONFIG_SUBSCR(mod_name, xpath, cb_streamid_subtree_change_cb, 0);

    mod_name = "ieee802-dot1cb-frer";
    /* Subscribe to CB */
    xpath = "/ieee802-dot1cb-frer:frer";
    SR_CONFIG_SUBSCR(mod_name, xpath, cb_subtree_change_cb, 0);

    lldp_module_init(session, &subscription);

    ptp_module_init(session, &subscription);

	if (write_pid_file(pid_fd) < 0) {
        goto cleanup;
    }

#ifdef RT_HAVE_SYSTEMD
    /* notify systemd */
    sd_notify(0, "READY=1");
#endif

    pthread_mutex_lock(&lock);
	while (!exit_application) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

#ifdef RT_HAVE_SYSTEMD
    /* notify systemd */
    sd_notify(0, "STOPPING=1");
#endif

    ret = EXIT_SUCCESS;

cleanup:
	destroy_tsn_mutex();
	if (subscription)
		sr_unsubscribe(subscription);
	if (session)
		sr_session_stop(session);
	if (connection)
		sr_disconnect(connection);
    if (pid_fd >= 0) {
        close(pid_fd);
        unlink(pid_file);
    }

	return ret;
}
