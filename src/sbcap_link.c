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
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/debug.h>

const char *cbc_sbcap_link_name(const struct cbc_sbcap_link *link)
{
	struct osmo_fd *ofd;
	OSMO_ASSERT(link);

	if (link->peer && link->peer->name) {
		return link->peer->name;
	}

	ofd = osmo_stream_srv_get_ofd(link->conn);
	return osmo_sock_get_name2(ofd->fd);
}

/* data from MME has arrived at CBC */
static int sbcap_cbc_read_cb(struct osmo_stream_srv *conn)
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
		osmo_stream_srv_destroy(conn);
		goto out;
	} else if (rc == 0) {
		osmo_stream_srv_destroy(conn);
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		LOGPSBCAPC(link, LOGL_DEBUG, "Rx sctp notif %s\n",
			osmo_sctp_sn_type_str(notif->sn_header.sn_type));
		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_srv_destroy(conn);
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

	LOGPSBCAPC(link, LOGL_DEBUG, "Received SBc-AP %s\n", msgb_hexdump(msg));

	/* decode + dispatch message */
	pdu = sbcap_decode(msg);
	if (pdu) {
		LOGPSBCAPC(link, LOGL_INFO, "Received SBc-AP %d\n",
			   pdu->present);
		cbc->rx_cb(link, pdu);
	} else {
		LOGPSBCAPC(link, LOGL_ERROR, "Unable to decode %s\n", msgb_hexdump(msg));
	}
out:
	msgb_free(msg);
	return rc;
}

/* connection from MME to CBC has been closed */
static int sbcap_cbc_closed_cb(struct osmo_stream_srv *conn)
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
	struct cbc_sbcap_link *link = talloc_zero(cbc, struct cbc_sbcap_link);
	char remote_ip[INET6_ADDRSTRLEN], portbuf[6];
	int remote_port;
	OSMO_ASSERT(link);

	remote_ip[0] = '\0';
	portbuf[0] = '\0';
	osmo_sock_get_ip_and_port(fd, remote_ip, sizeof(remote_ip), portbuf, sizeof(portbuf), false);
	remote_port = atoi(portbuf);

	LOGP(DSBcAP, LOGL_NOTICE, "New SBc-AP link connection from %s:%u\n", remote_ip, remote_port);

	link->conn = osmo_stream_srv_create(srv_link, srv_link, fd, sbcap_cbc_read_cb, sbcap_cbc_closed_cb, link);
	if (!link->conn) {
		LOGP(DSBcAP, LOGL_ERROR, "Unable to create stream server for %s:%d\n",
			remote_ip, remote_port);
		talloc_free(link);
		return -1;
	}
	link->fi = osmo_fsm_inst_alloc(&sbcap_link_fsm, link, link, LOGL_DEBUG, NULL);
	if (!link->fi) {
		LOGPSBCAPC(link, LOGL_ERROR, "Unable to allocate FSM\n");
		osmo_stream_srv_destroy(link->conn);
		talloc_free(link);
		return -1;
	}
	llist_add_tail(&link->list, &cbc->links);

	/* Match link to peer */
	link->peer = cbc_peer_by_addr_proto(remote_ip, remote_port, CBC_PEER_PROTO_SBcAP);
	if (!link->peer) {
		if (g_cbc->config.permit_unknown_peers) {
			LOGPSBCAPC(link, LOGL_NOTICE, "Accepting unknown SBc-AP peer %s:%d\n",
				remote_ip, remote_port);
			link->peer = cbc_peer_create(NULL, CBC_PEER_PROTO_SBcAP);
			OSMO_ASSERT(link->peer);
			link->peer->unknown_dynamic_peer = true;
		} else {
			LOGPSBCAPC(link, LOGL_NOTICE, "Rejecting unknown SBc-AP peer %s:%d (not permitted)\n",
				remote_ip, remote_port);
			osmo_stream_srv_destroy(link->conn);
			return -1;
		}
	} else {
		if (link->peer->link.sbcap) {
			LOGPSBCAPC(link, LOGL_ERROR, "We already have a connection for peer %s\n",
				link->peer->name);
			/* FIXME */
		}
		link->peer->link.sbcap = link;
	}

	osmo_fsm_inst_dispatch(link->fi, SBcAP_LINK_E_CMD_RESET, NULL);
	return 0;
}

void cbc_sbcap_link_tx(struct cbc_sbcap_link *link, SBcAP_SBC_AP_PDU_t *pdu)
{
	struct msgb *msg;

	if (!pdu) {
		LOGP(DSBcAP, LOGL_NOTICE, "Cannot transmit msg: no pdu\n");
		return;
	}

	if (!link) {
		LOGP(DSBcAP, LOGL_NOTICE, "Cannot transmit msg: no connection\n");
		return;
	}

	LOGPSBCAPC(link, LOGL_INFO, "Transmitting msg\n");
	OSMO_ASSERT(link->conn);
	msg = sbcap_encode(pdu);
	if (!msg)
		goto ret_free;
	LOGPSBCAPC(link, LOGL_DEBUG, "Encoded message: %s\n", msgb_hexdump(msg));
	osmo_stream_srv_send(link->conn, msg);
ret_free:
	sbcap_pdu_free(pdu);
}

void cbc_sbcap_link_close(struct cbc_sbcap_link *link)
{
	osmo_stream_srv_destroy(link->conn);
}

/* initialize the CBC-side SBc-AP server */
struct cbc_sbcap_mgr *cbc_sbcap_mgr_create(void *ctx)
{
	struct cbc_sbcap_mgr *cbc = talloc_zero(ctx, struct cbc_sbcap_mgr);
	int rc;
	int bind_port = g_cbc->config.sbcap.local_port;

	if (bind_port == -1)
		bind_port = SBcAP_SCTP_PORT;

	OSMO_ASSERT(cbc);
	cbc->rx_cb = cbc_sbcap_link_rx_cb;
	INIT_LLIST_HEAD(&cbc->links);
	cbc->srv_link = osmo_stream_srv_link_create(cbc);
	osmo_stream_srv_link_set_proto(cbc->srv_link, IPPROTO_SCTP);
	osmo_stream_srv_link_set_data(cbc->srv_link, cbc);
	osmo_stream_srv_link_set_nodelay(cbc->srv_link, true);
	osmo_stream_srv_link_set_port(cbc->srv_link, bind_port);
	osmo_stream_srv_link_set_addrs(cbc->srv_link, (const char **)g_cbc->config.sbcap.local_host,
				       g_cbc->config.sbcap.num_local_host);
	osmo_stream_srv_link_set_accept_cb(cbc->srv_link, sbcap_cbc_accept_cb);
	rc = osmo_stream_srv_link_open(cbc->srv_link);
	OSMO_ASSERT(rc == 0);
	LOGP(DSBcAP, LOGL_NOTICE, "Listening for SBc-AP at %s\n",
		osmo_stream_srv_link_get_sockname(cbc->srv_link));

	return cbc;
}
