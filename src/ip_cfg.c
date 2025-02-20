/**
 * @file ip_cfg.c
 * @author hongbo wang
 * @brief Application to configure IP address based on sysrepo datastore.
 *
 * Copyright 2020-2025 NXP
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

#include <libyang/libyang.h>

#include "ip_cfg.h"

#define ADDR_LEN (sizeof(struct in_addr))

struct sub_item_cfg {
	struct in_addr ip;
	struct in_addr mask;
};

struct item_cfg {
	bool valid;
	bool enabled;
	char ifname[IF_NAME_MAX_LEN];
	int ipv4_cnt;
	struct sub_item_cfg ipv4[MAX_IP_NUM];
};
static struct item_cfg sitem_conf;

#if 0
static int get_inet_cfg(char *ifname, int req, void *buf, int len)
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr = {0};
	struct sockaddr_in *sin = NULL;

	if (!ifname || !buf)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		LOG_ERR("create socket failed! ret:%d", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	ret = ioctl(sockfd, req, &ifr);
	close(sockfd);
	if (ret < 0) {
		LOG_ERR("ioctl error! ret:%d", ret);
		return -3;
	}

	if (req == SIOCGIFHWADDR) {
		memcpy(buf, &ifr.ifr_ifru.ifru_hwaddr.sa_data, len);
	} else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		memcpy((struct in_addr *)buf, &sin->sin_addr, len);
	}

	return 0;
}

static int get_inet_ip(char *ifname, struct in_addr *ip)
{
	return get_inet_cfg(ifname, SIOCGIFADDR, ip, ADDR_LEN);
}

static int get_inet_mask(char *ifname, struct in_addr *mask)
{
	return get_inet_cfg(ifname, SIOCGIFNETMASK, mask, ADDR_LEN);
}
#endif

static int set_inet_cfg(char *ifname, int req, void *buf, int len)
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr = {0};
	struct sockaddr_in *sin = NULL;

	if (!ifname || !buf)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		LOG_ERR("create socket failed! ret:%d", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		LOG_ERR("%s:can not find \"%s\"", __func__, ifname);
		return -3;
	}

	if (req == SIOCSIFHWADDR) {
		memcpy(&ifr.ifr_ifru.ifru_hwaddr.sa_data, buf, len);
		ifr.ifr_addr.sa_family = ARPHRD_ETHER;
	} else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, (struct in_addr *)buf, len);
	}

	ret = ioctl(sockfd, req, &ifr);
	close(sockfd);
	if (ret < 0) {
		LOG_ERR("%s ioctl error! ret:%d", __func__, ret);
		return -4;
	}

	return 0;
}

static int set_inet_ip(char *ifname, struct in_addr *ip)
{
	return set_inet_cfg(ifname, SIOCSIFADDR, ip, ADDR_LEN);
}

static int set_inet_mask(char *ifname, struct in_addr *mask)
{
	return set_inet_cfg(ifname, SIOCSIFNETMASK, mask, ADDR_LEN);
}

static int set_inet_updown(char *ifname, bool upflag)
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr = {0};
	struct sockaddr_in *sin = NULL;

	if (!ifname)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)	{
		LOG_ERR("create socket failed! ret: %d", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		LOG_ERR("get interface flag ret: %d", ret);
		return -3;
	}

	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;

	if (upflag)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	close(sockfd);
	if (ret < 0) {
		LOG_ERR("ioctl error! ret: %d, need root account!", ret);
		return -4;
	}

	return 0;
}

static int set_config(sr_session_ctx_t *session, bool abort)
{
	int i = 0;
	int ret = 0;
	int rc = SR_ERR_OK;
	char *ifname = NULL;
	struct sub_item_cfg *ipv4 = NULL;
	struct item_cfg *conf = &sitem_conf;

	if (abort) {
		memset(conf, 0, sizeof(struct item_cfg));
		return rc;
	}

	if (!conf->valid || strlen(conf->ifname) == 0) {
		return rc;
	}

	if (!conf->enabled) {
		set_inet_updown(conf->ifname, false);
        LOG_DBG("%s: disable the interface", conf->ifname);
		return rc;
	}

	/* config ip and netmask */
	for (i = 0; i < conf->ipv4_cnt; i++) {
		ipv4 = &conf->ipv4[i];
		ifname = conf->ifname;

		if (ipv4->ip.s_addr) {
			ret = set_inet_ip(conf->ifname, &ipv4->ip);
			if (ret != 0)
				return SR_ERR_INVAL_ARG;

			LOG_DBG("%s: set IP address to %s", ifname, inet_ntoa(ipv4->ip));
		}

		if (ipv4->mask.s_addr) {
			ret = set_inet_mask(conf->ifname, &ipv4->mask);
			if (ret != 0)
				return SR_ERR_INVAL_ARG;

			LOG_DBG("%s: set netmask to %s", ifname, inet_ntoa(ipv4->mask));
		}
	}
	set_inet_updown(conf->ifname, true);

	return rc;
}

static int parse_ipv4_address(const struct lyd_node *node, struct sub_item_cfg *ipv4)
{
    const struct lyd_node *iter;
	const char *nodename;

	LY_LIST_FOR(lyd_child(node), iter) {
        nodename = LYD_NAME(iter);

        if (!strcmp(nodename, "ip")) {
            if (!inet_aton(lyd_get_value(iter), &ipv4->ip)) {
                goto err;
            }
        } else if (!strcmp(nodename, "netmask")) {
            if (!inet_aton(lyd_get_value(iter), &ipv4->mask)) {
                goto err;
            }
        }
    }
    return SR_ERR_OK;

err:
    return SR_ERR_INVAL_ARG;
}

static int parse_ipv4(sr_session_ctx_t *session, struct item_cfg *conf)
{
    const struct lyd_node_term *term;
    const struct lyd_node *iter;
    const struct lyd_node *node;
    sr_data_t *subtree = NULL;
	const char *nodename;
    char *xpath;
    int rc = SR_ERR_OK;

    conf->ipv4_cnt = 0;
    conf->enabled = false;

    rc = asprintf(&xpath, "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4",
             &conf->ifname[0]);
    if (rc < 0) {
        rc = SR_ERR_NO_MEMORY;
        goto err;
    }

    rc = sr_get_subtree(session, xpath, 0, &subtree);
    free(xpath);
    if (rc) {
        goto err;
    }
    node = subtree->tree;

    print_node_tree_xml(node);

	LY_LIST_FOR(lyd_child(node), iter) {

        nodename = LYD_NAME(iter);
        if (!strcmp(nodename, "enabled")) {
            term = (struct lyd_node_term *)iter;
            conf->enabled = term->value.boolean ? true : false;

        } else if (!strcmp(nodename, "address")) {
            if ((rc = parse_ipv4_address(iter, &conf->ipv4[conf->ipv4_cnt]))) {
                goto err;
            }
            conf->ipv4_cnt++;
        }
    }
    conf->valid = true;
    sr_release_data(subtree);
    return SR_ERR_OK;

err:
    sr_release_data(subtree);
    return rc;
}

/*

module: ietf-interfaces
  +--rw interfaces
     +--rw interface* [name]
        +--rw ip:ipv4!
           +--rw ip:enabled?      boolean
           +--rw ip:forwarding?   boolean
           +--rw ip:mtu?          uint16
           +--rw ip:address* [ip]
           |  +--rw ip:ip                     inet:ipv4-address-no-zone
           |  +--rw (ip:subnet)
           |  |  +--:(ip:prefix-length)
           |  |  |  +--rw ip:prefix-length?   uint8
           |  |  +--:(ip:netmask)
           |  |     +--rw ip:netmask?         yang:dotted-quad {ipv4-non-contiguous-netmasks}?
           |  +--ro ip:origin?                ip-address-origin
           +--rw ip:neighbor* [ip]
              +--rw ip:ip                    inet:ipv4-address-no-zone
              +--rw ip:link-layer-address    yang:phys-address
              +--ro ip:origin?               neighbor-origin
*/

int ip_subtree_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
                         const char *module_name, const char *path,
                         sr_event_t event, uint32_t request_id,
                         void *private_ctx)
{
    const struct lyd_node *node = NULL;
	sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
	int rc = SR_ERR_OK;
    char *xpath;

    LOG_DBG("ipv4: start callback(%d): %s", (int)event, path);

    rc = asprintf(&xpath, "%s//*", path);
    if (rc < 0) {
        return SR_ERR_CALLBACK_FAILED;
    }

	rc = sr_get_changes_iter(session, xpath, &iter);
    free(xpath);
	if (rc != SR_ERR_OK) {
        sr_session_set_error_message(session, "Getting changes iter failed(%s).",
                sr_strerror(rc));
		return rc;
	}

    do {
        rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL);
        if (rc != SR_ERR_OK) {
            break;
        }
        LOG_DBG("node name: %s, opt: %d", LYD_NAME(node), (int)op);

        if (op == SR_OP_CREATED || op == SR_OP_MODIFIED) {

            sitem_conf.ifname[0] = 0;
            strncpy(sitem_conf.ifname, get_ifname(node), sizeof(sitem_conf.ifname) - 1);
            rc = parse_ipv4(session, &sitem_conf);
            break;
        }
    } while(1);

    sr_free_change_iter(iter);

    if (rc != SR_ERR_OK && rc != SR_ERR_NOT_FOUND) {
        sr_session_set_error_message(session, "Parsing IPv4 address failed(%s).",
                sr_strerror(rc));
        LOG_ERR("Parsing IPv4 address failed(%s).", sr_strerror(rc));
		return SR_ERR_CALLBACK_FAILED;
    }

	rc = set_config(session, false);
    if (rc != SR_ERR_OK) {
        sr_session_set_error_message(session, "Setting IPv4 address failed(%s).",
                sr_strerror(rc));
        LOG_ERR("Setting IPv4 address failed(%s).", sr_strerror(rc));
        return SR_ERR_CALLBACK_FAILED;
    }

    LOG_DBG("ipv4: end callback(%d): %s", (int)event, path);
    return SR_ERR_OK;
}
