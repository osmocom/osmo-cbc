/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/netif/sctp.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sbcap/sbcap_common.h>

#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/sbcap_link_fsm.h>
#include <osmocom/cbc/sbcap_msg.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/debug.h>

struct cbc_sbcap_link *cbc_sbcap_link_alloc(struct cbc_sbcap_mgr *cbc, struct cbc_peer *peer)
{
	struct cbc_sbcap_link *link;
	char *name;

	link = talloc_zero(cbc, struct cbc_sbcap_link);
	OSMO_ASSERT(link);

	link->peer = peer;
	link->is_client = (peer->link_mode == CBC_PEER_LINK_MODE_CLIENT);

	name = talloc_strdup(link, peer->name);
	osmo_identifier_sanitize_buf(name, NULL, '_');
	link->fi = osmo_fsm_inst_alloc(&sbcap_link_fsm, link, link, LOGL_DEBUG, name);
	if (!link->fi) {
		LOGPSBCAPC(link, LOGL_ERROR, "Unable to allocate FSM\n");
		talloc_free(link);
		return NULL;
	}
	talloc_free(name);

	llist_add_tail(&link->list, &cbc->links);
	return link;
}

void cbc_sbcap_link_free(struct cbc_sbcap_link *link)
{
	if (!link)
		return;
	llist_del(&link->list);
	if (link->fi)
		osmo_fsm_inst_free(link->fi);
	talloc_free(link);
}

const char *cbc_sbcap_link_name(const struct cbc_sbcap_link *link)
{
	struct osmo_fd *ofd;
	OSMO_ASSERT(link);

	if (link->peer && link->peer->name)
		return link->peer->name;

	if (link->is_client)
		ofd = osmo_stream_cli_get_ofd(link->cli_conn);
	else
		ofd = osmo_stream_srv_get_ofd(link->srv_conn);
	return osmo_sock_get_name2(ofd->fd);
}

/*
 * SCTP client
 */
static int cbc_sbcap_link_cli_connect_cb(struct osmo_stream_cli *conn)
{
	struct cbc_sbcap_link *link = osmo_stream_cli_get_data(conn);
	LOGPSBCAPC(link, LOGL_NOTICE, "Connected\n");
	osmo_fsm_inst_dispatch(link->fi, SBcAP_LINK_E_CMD_RESET, NULL);
	return 0;
}

static int cbc_sbcap_link_cli_disconnect_cb(struct osmo_stream_cli *conn)
{
	struct cbc_sbcap_link *link = osmo_stream_cli_get_data(conn);
	LOGPSBCAPC(link, LOGL_NOTICE, "Disconnected.\n");
	LOGPSBCAPC(link, LOGL_NOTICE, "Reconnecting...\n");
	osmo_stream_cli_reconnect(conn);
	return 0;
}

static int cbc_sbcap_link_cli_read_cb(struct osmo_stream_cli *conn)
{
	struct cbc_sbcap_link *link = osmo_stream_cli_get_data(conn);
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);
	SBcAP_SBC_AP_PDU_t *pdu;
	struct msgb *msg = msgb_alloc_c(g_cbc, 1500, "SBcAP-rx");
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
	int rc;

	/* read SBc-AP message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGPSBCAPC(link, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		   __func__, rc, flags);
	if (rc < 0) {
		osmo_stream_cli_reconnect(conn);
		goto out;
	} else if (rc == 0) {
		osmo_stream_cli_reconnect(conn);
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		LOGPSBCAPC(link, LOGL_DEBUG, "Rx sctp notif %s\n",
			osmo_sctp_sn_type_str(notif->sn_header.sn_type));
		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_cli_reconnect(conn);
			break;
		case SCTP_ASSOC_CHANGE:
			LOGPSBCAPC(link, LOGL_DEBUG, "Rx sctp notif SCTP_ASSOC_CHANGE: %s\n",
				   osmo_sctp_assoc_chg_str(notif->sn_assoc_change.sac_state));
			break;
		default:
			LOGPSBCAPC(link, LOGL_DEBUG, "Rx sctp notif %s (%u)\n",
				   osmo_sctp_sn_type_str(notif->sn_header.sn_type),
				   notif->sn_header.sn_type);
			break;
		}
		rc = 0;
	}

	if (rc == 0)
		goto out;

	LOGPSBCAPC(link, LOGL_DEBUG, "Rx SBc-AP %s\n", msgb_hexdump(msg));

	/* decode + dispatch message */
	pdu = sbcap_decode(msg);
	if (pdu) {
		LOGPSBCAPC(link, LOGL_INFO, "Rx SBc-AP %s\n",
			   sbcap_pdu_get_name(pdu));
		g_cbc->sbcap.mgr->rx_cb(link, pdu);
	} else {
		LOGPSBCAPC(link, LOGL_ERROR, "Unable to decode %s\n", msgb_hexdump(msg));
		pdu = sbcap_gen_error_ind(link, SBcAP_Cause_unrecognised_message, NULL);
		if (pdu) {
			cbc_sbcap_link_tx(link, pdu);
		} else {
			LOGPSBCAPC(link, LOGL_ERROR,
				   "Tx SBc-AP Error-Indication: msg gen failed\n");
		}
	}
out:
	msgb_free(msg);
	return rc;
}

int cbc_sbcap_link_open_cli(struct cbc_sbcap_link *link)
{
	struct osmo_stream_cli *conn;
	struct cbc_peer *peer = link->peer;
	int rc;

	OSMO_ASSERT(link->is_client);
	OSMO_ASSERT(peer->link_mode == CBC_PEER_LINK_MODE_CLIENT);

	conn = osmo_stream_cli_create(link);
	osmo_stream_cli_set_data(conn, link);
	osmo_stream_cli_set_nodelay(conn, true);
	osmo_stream_cli_set_reconnect_timeout(conn, 5);
	osmo_stream_cli_set_proto(conn, IPPROTO_SCTP);
	osmo_stream_cli_set_connect_cb(conn, cbc_sbcap_link_cli_connect_cb);
	osmo_stream_cli_set_disconnect_cb(conn, cbc_sbcap_link_cli_disconnect_cb);
	osmo_stream_cli_set_read_cb(conn, cbc_sbcap_link_cli_read_cb);
	OSMO_ASSERT(g_cbc->config.sbcap.num_local_host > 0);
	rc = osmo_stream_cli_set_local_addrs(conn, (const char **)&g_cbc->config.sbcap.local_host,
					     g_cbc->config.sbcap.num_local_host);
	if (rc < 0)
		goto free_ret;
	/* We assign free local port for client links:
	 * osmo_stream_cli_set_local_port(conn, g_cbc->sbcap.local_port);
	 */
	OSMO_ASSERT(peer->num_remote_host > 0);
	rc = osmo_stream_cli_set_addrs(conn, (const char **)peer->remote_host, peer->num_remote_host);
	if (rc < 0)
		goto free_ret;
	osmo_stream_cli_set_port(conn, peer->remote_port);
	rc = osmo_stream_cli_open(conn);
	if (rc < 0)
		goto free_ret;
	link->cli_conn = conn;
	return 0;
free_ret:
	osmo_stream_cli_destroy(conn);
	return rc;
}

/*
 * SCTP server
 */
/* data from MME has arrived at CBC */
static int sbcap_cbc_srv_read_cb(struct osmo_stream_srv *conn)
{
	struct osmo_stream_srv_link *srv_link = osmo_stream_srv_get_master(conn);
	struct cbc_sbcap_link *link = osmo_stream_srv_get_data(conn);
	struct cbc_sbcap_mgr *cbc = osmo_stream_srv_link_get_data(srv_link);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	SBcAP_SBC_AP_PDU_t *pdu;
	struct msgb *msg = msgb_alloc_c(g_cbc, 1500, "SBcAP-rx");
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
	int rc;

	/* read SBc-AP message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGPSBCAPC(link, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		   __func__, rc, flags);
	if (rc < 0) {
		cbc_sbcap_link_close(link);
		goto out;
	} else if (rc == 0) {
		cbc_sbcap_link_close(link);
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		LOGPSBCAPC(link, LOGL_DEBUG, "Rx sctp notif %s\n",
			osmo_sctp_sn_type_str(notif->sn_header.sn_type));
		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			cbc_sbcap_link_close(link);
			break;
		case SCTP_ASSOC_CHANGE:
			LOGPSBCAPC(link, LOGL_DEBUG, "Rx sctp notif SCTP_ASSOC_CHANGE: %s\n",
				   osmo_sctp_assoc_chg_str(notif->sn_assoc_change.sac_state));
			break;
		default:
			LOGPSBCAPC(link, LOGL_DEBUG, "Rx sctp notif %s (%u)\n",
				   osmo_sctp_sn_type_str(notif->sn_header.sn_type),
				   notif->sn_header.sn_type);
			break;
		}
		rc = 0;
	}

	if (rc == 0)
		goto out;

	LOGPSBCAPC(link, LOGL_DEBUG, "Rx SBc-AP %s\n", msgb_hexdump(msg));

	/* decode + dispatch message */
	pdu = sbcap_decode(msg);
	if (pdu) {
		LOGPSBCAPC(link, LOGL_INFO, "Rx SBc-AP %s\n",
			   sbcap_pdu_get_name(pdu));
		cbc->rx_cb(link, pdu);
	} else {
		LOGPSBCAPC(link, LOGL_ERROR, "Unable to decode %s\n", msgb_hexdump(msg));
	}
out:
	msgb_free(msg);
	return rc;
}

/* connection from MME to CBC has been closed */
static int sbcap_cbc_srv_closed_cb(struct osmo_stream_srv *conn)
{
	struct cbc_sbcap_link *link = osmo_stream_srv_get_data(conn);
	LOGPSBCAPC(link, LOGL_NOTICE, "connection closed\n");

	if (link->peer)
		link->peer->link.sbcap = NULL;
	link->conn = NULL;
	if (link->fi)
		osmo_fsm_inst_dispatch(link->fi, SBcAP_LINK_E_CMD_CLOSE, NULL);

	return 0;
}

/* new connection from MME has arrived at CBC */
static int sbcap_cbc_accept_cb(struct osmo_stream_srv_link *srv_link, int fd)
{
	struct cbc_sbcap_mgr *cbc = osmo_stream_srv_link_get_data(srv_link);
	struct cbc_peer *peer;
	struct cbc_sbcap_link *link;
	char remote_ip[INET6_ADDRSTRLEN], portbuf[6];
	int remote_port;

	remote_ip[0] = '\0';
	portbuf[0] = '\0';
	osmo_sock_get_ip_and_port(fd, remote_ip, sizeof(remote_ip), portbuf, sizeof(portbuf), false);
	remote_port = atoi(portbuf);

	LOGP(DSBcAP, LOGL_NOTICE, "New SBc-AP link connection from %s:%u\n", remote_ip, remote_port);

	/* Match link to peer */
	peer = cbc_peer_by_addr_proto(remote_ip, remote_port, CBC_PEER_PROTO_SBcAP);
	if (!peer) {
		if (!g_cbc->config.permit_unknown_peers) {
			LOGP(DSBcAP, LOGL_NOTICE,
			     "Rejecting unknown SBc-AP peer %s:%d (not permitted)\n",
			     remote_ip, remote_port);
			close(fd);
			return -1;
		}
		LOGP(DSBcAP, LOGL_NOTICE, "Accepting unknown SBc-AP peer %s:%d\n",
		     remote_ip, remote_port);
		peer = cbc_peer_create(NULL, CBC_PEER_PROTO_SBcAP);
		OSMO_ASSERT(peer);
		peer->unknown_dynamic_peer = true;
	} else { /* peer is known */
		switch (peer->link_mode) {
		case CBC_PEER_LINK_MODE_DISABLED:
			LOGP(DSBcAP, LOGL_NOTICE,
			     "Rejecting conn for disabled SBc-AP peer %s:%d\n",
			     remote_ip, remote_port);
			close(fd);
			return -1;
		case CBC_PEER_LINK_MODE_CLIENT:
			LOGP(DSBcAP, LOGL_NOTICE,
			     "Rejecting conn for SBc-AP peer %s:%d configured as 'client'\n",
			     remote_ip, remote_port);
			close(fd);
			return -1;
		default: /* MODE_SERVER */
			break;
		}
	}
	if (peer->link.sbcap) {
		LOGPSBCAPC(peer->link.sbcap, LOGL_ERROR,
			   "We already have a connection for peer %s, closing it\n",
			   peer->name);
		cbc_sbcap_link_close(peer->link.sbcap);
	}
	link = cbc_sbcap_link_alloc(cbc, peer);
	OSMO_ASSERT(link);

	link->srv_conn = osmo_stream_srv_create(srv_link, srv_link, fd,
						sbcap_cbc_srv_read_cb, sbcap_cbc_srv_closed_cb,
						link);
	if (!link->srv_conn) {
		LOGPSBCAPC(link, LOGL_ERROR,
			   "Unable to create stream server for %s:%u\n",
			   remote_ip, remote_port);
		cbc_sbcap_link_free(link);
		return -1;
	}
	peer->link.sbcap = link;

	osmo_fsm_inst_dispatch(link->fi, SBcAP_LINK_E_CMD_RESET, NULL);
	return 0;
}

int cbc_sbcap_link_tx(struct cbc_sbcap_link *link, SBcAP_SBC_AP_PDU_t *pdu)
{
	struct msgb *msg;
	int rc = 0;

	if (!pdu) {
		LOGP(DSBcAP, LOGL_NOTICE, "Cannot transmit msg: no pdu\n");
		return -ENOMSG;
	}

	if (!link) {
		LOGP(DSBcAP, LOGL_NOTICE, "Cannot transmit msg %s: no connection\n",
		     sbcap_pdu_get_name(pdu));
		rc = -ENOLINK;
		goto ret_free;
	} else if (link->is_client && !osmo_stream_cli_is_connected(link->cli_conn)) {
		LOGPSBCAPC(link, LOGL_NOTICE, "Cannot transmit msg %s: reconnecting\n",
		     sbcap_pdu_get_name(pdu));
		rc = -ENOTCONN;
		goto ret_free;
	}

	LOGPSBCAPC(link, LOGL_INFO, "Tx msg %s\n",
		   sbcap_pdu_get_name(pdu));
	OSMO_ASSERT(link->conn);
	msg = sbcap_encode(pdu);
	if (!msg) {
		rc = -EINVAL;
		goto ret_free;
	}
	LOGPSBCAPC(link, LOGL_DEBUG, "Encoded message %s: %s\n",
		   sbcap_pdu_get_name(pdu), msgb_hexdump(msg));
	if (link->is_client)
		osmo_stream_cli_send(link->cli_conn, msg);
	else
		osmo_stream_srv_send(link->srv_conn, msg);
ret_free:
	sbcap_pdu_free(pdu);
	return rc;
}

void cbc_sbcap_link_close(struct cbc_sbcap_link *link)
{
	if (!link->conn)
		return;

	if (link->is_client) {
		osmo_stream_cli_destroy(link->cli_conn);
		osmo_stream_cli_destroy(link->cli_conn);
		if (link->peer)
			link->peer->link.sbcap = NULL;
		link->cli_conn = NULL;
		if (link->fi)
			osmo_fsm_inst_dispatch(link->fi, SBcAP_LINK_E_CMD_CLOSE, NULL);
	} else {
		osmo_stream_srv_destroy(link->srv_conn);
		/* Same as waht's done for cli is done for srv in closed_cb() */
	}
}

/*
 * CBSP Manager
 */
struct cbc_sbcap_mgr *cbc_sbcap_mgr_alloc(void *ctx)
{
	struct cbc_sbcap_mgr *mgr;

	mgr = talloc_zero(ctx, struct cbc_sbcap_mgr);
	OSMO_ASSERT(mgr);
	mgr->rx_cb = cbc_sbcap_link_rx_cb;
	INIT_LLIST_HEAD(&mgr->links);

	return mgr;
}

/* initialize the CBC-side SBc-AP server */
int cbc_sbcap_mgr_open_srv(struct cbc_sbcap_mgr *mgr)
{
	int bind_port = g_cbc->config.sbcap.local_port;
	struct osmo_stream_srv_link *srv_link;
	int rc;

	srv_link = osmo_stream_srv_link_create(mgr);
	osmo_stream_srv_link_set_proto(srv_link, IPPROTO_SCTP);
	osmo_stream_srv_link_set_data(srv_link, mgr);
	osmo_stream_srv_link_set_nodelay(srv_link, true);
	osmo_stream_srv_link_set_port(srv_link, bind_port);
	osmo_stream_srv_link_set_addrs(srv_link,
				       (const char **)g_cbc->config.sbcap.local_host,
				       g_cbc->config.sbcap.num_local_host);
	osmo_stream_srv_link_set_accept_cb(srv_link, sbcap_cbc_accept_cb);
	rc = osmo_stream_srv_link_open(srv_link);
	if (rc < 0) {
		osmo_stream_srv_link_destroy(srv_link);
		talloc_free(mgr);
		return -EIO;
	}
	mgr->srv_link = srv_link;
	LOGP(DSBcAP, LOGL_NOTICE, "Listening for SBc-AP at %s\n",
		osmo_stream_srv_link_get_sockname(mgr->srv_link));

	return 0;
}
