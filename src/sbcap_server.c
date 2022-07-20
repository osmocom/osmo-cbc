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

#include <osmocom/cbc/internal.h>
#include <osmocom/cbc/sbcap_server.h>

const char *sbcap_cbc_client_name(const struct osmo_sbcap_cbc_client *client)
{
	struct osmo_fd *ofd;
	OSMO_ASSERT(client);

	if (client->peer && client->peer->name) {
		return client->peer->name;
	}

	ofd = osmo_stream_srv_get_ofd(client->conn);
	return osmo_sock_get_name2(ofd->fd);
}

/* data from MME has arrived at CBC */
static int sbcap_cbc_read_cb(struct osmo_stream_srv *conn)
{
	struct osmo_stream_srv_link *link = osmo_stream_srv_get_master(conn);
	struct osmo_sbcap_cbc_client *client = osmo_stream_srv_get_data(conn);
	struct osmo_sbcap_cbc *cbc = osmo_stream_srv_link_get_data(link);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	SBcAP_SBC_AP_PDU_t *pdu;
	struct msgb *msg = msgb_alloc_c(g_cbc, 1500, "SBcAP-rx");
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
	int rc;

	/* read SBc-AP message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGPSBCAPC(client, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
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
		LOGPSBCAPC(client, LOGL_DEBUG, "Rx sctp notif %s\n",
			osmo_sctp_sn_type_str(notif->sn_header.sn_type));
		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_srv_destroy(conn);
			break;
		case SCTP_ASSOC_CHANGE:
			LOGPSBCAPC(client, LOGL_DEBUG, "Rx sctp notif SCTP_ASSOC_CHANGE: %s\n",
				   osmo_sctp_assoc_chg_str(notif->sn_assoc_change.sac_state));
			break;
		default:
			LOGPSBCAPC(client, LOGL_DEBUG, "Rx sctp notif %s (%u)\n",
				   osmo_sctp_sn_type_str(notif->sn_header.sn_type),
				   notif->sn_header.sn_type);
			break;
		}
		rc = 0;
	}

	if (rc == 0)
		goto out;

	LOGPSBCAPC(client, LOGL_DEBUG, "Received SBc-AP %s\n", msgb_hexdump(msg));

	/* decode + dispatch message */
	pdu = sbcap_decode(msg);
	if (pdu) {
		LOGPSBCAPC(client, LOGL_INFO, "Received SBc-AP %d\n",
			   pdu->present);
		cbc->rx_cb(client, pdu);
	} else {
		LOGPSBCAPC(client, LOGL_ERROR, "Unable to decode %s\n", msgb_hexdump(msg));
	}
out:
	msgb_free(msg);
	return rc;
}

/* connection from MME to CBC has been closed */
static int sbcap_cbc_closed_cb(struct osmo_stream_srv *conn)
{
	struct osmo_sbcap_cbc_client *client = osmo_stream_srv_get_data(conn);
	LOGPSBCAPC(client, LOGL_NOTICE, "connection closed\n");

	if (client->peer)
		client->peer->client.sbcap = NULL;
	client->conn = NULL;
	if (client->fi)
		osmo_fsm_inst_dispatch(client->fi, SBcAP_SRV_E_CMD_CLOSE, NULL);

	return 0;
}

/* new connection from MME has arrived at CBC */
static int sbcap_cbc_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_sbcap_cbc *cbc = osmo_stream_srv_link_get_data(link);
	struct osmo_sbcap_cbc_client *client = talloc_zero(cbc, struct osmo_sbcap_cbc_client);
	char remote_ip[INET6_ADDRSTRLEN], portbuf[6];
	int remote_port;
	OSMO_ASSERT(client);

	remote_ip[0] = '\0';
	portbuf[0] = '\0';
	osmo_sock_get_ip_and_port(fd, remote_ip, sizeof(remote_ip), portbuf, sizeof(portbuf), false);
	remote_port = atoi(portbuf);

	LOGP(DSBcAP, LOGL_NOTICE, "New SBc-AP client connection from %s:%u\n", remote_ip, remote_port);

	client->conn = osmo_stream_srv_create(link, link, fd, sbcap_cbc_read_cb, sbcap_cbc_closed_cb, client);
	if (!client->conn) {
		LOGP(DSBcAP, LOGL_ERROR, "Unable to create stream server for %s:%d\n",
			remote_ip, remote_port);
		talloc_free(client);
		return -1;
	}
	client->fi = osmo_fsm_inst_alloc(&sbcap_server_fsm, client, client, LOGL_DEBUG, NULL);
	if (!client->fi) {
		LOGPSBCAPC(client, LOGL_ERROR, "Unable to allocate FSM\n");
		osmo_stream_srv_destroy(client->conn);
		talloc_free(client);
		return -1;
	}
	llist_add_tail(&client->list, &cbc->clients);

	/* Match client to peer */
	client->peer = cbc_peer_by_addr_proto(remote_ip, remote_port, CBC_PEER_PROTO_SBcAP);
	if (!client->peer) {
		if (g_cbc->config.permit_unknown_peers) {
			LOGPSBCAPC(client, LOGL_NOTICE, "Accepting unknown SBc-AP peer %s:%d\n",
				remote_ip, remote_port);
			client->peer = cbc_peer_create(NULL, CBC_PEER_PROTO_SBcAP);
			OSMO_ASSERT(client->peer);
			client->peer->unknown_dynamic_peer = true;
		} else {
			LOGPSBCAPC(client, LOGL_NOTICE, "Rejecting unknown SBc-AP peer %s:%d (not permitted)\n",
				remote_ip, remote_port);
			osmo_stream_srv_destroy(client->conn);
			return -1;
		}
	} else {
		if (client->peer->client.sbcap) {
			LOGPSBCAPC(client, LOGL_ERROR, "We already have a connection for peer %s\n",
				client->peer->name);
			/* FIXME */
		}
		client->peer->client.sbcap = client;
	}

	osmo_fsm_inst_dispatch(client->fi, SBcAP_SRV_E_CMD_RESET, NULL);
	return 0;
}

void sbcap_cbc_client_tx(struct osmo_sbcap_cbc_client *client, SBcAP_SBC_AP_PDU_t *pdu)
{
	struct msgb *msg;

	if (!pdu) {
		LOGP(DSBcAP, LOGL_NOTICE, "Cannot transmit msg: no pdu\n");
		return;
	}

	if (!client) {
		LOGP(DSBcAP, LOGL_NOTICE, "Cannot transmit msg: no connection\n");
		return;
	}

	LOGPSBCAPC(client, LOGL_INFO, "Transmitting msg\n");
	OSMO_ASSERT(client->conn);
	msg = sbcap_encode(pdu);
	if (!msg)
		goto ret_free;
	LOGPSBCAPC(client, LOGL_DEBUG, "Encoded message: %s\n", msgb_hexdump(msg));
	osmo_stream_srv_send(client->conn, msg);
ret_free:
	sbcap_pdu_free(pdu);
}

void sbcap_cbc_client_close(struct osmo_sbcap_cbc_client *client)
{
	osmo_stream_srv_destroy(client->conn);
}

/* initialize the CBC-side SBc-AP server */
struct osmo_sbcap_cbc *sbcap_cbc_create(void *ctx)
{
	struct osmo_sbcap_cbc *cbc = talloc_zero(ctx, struct osmo_sbcap_cbc);
	int rc;
	int bind_port = g_cbc->config.sbcap.local_port;

	if (bind_port == -1)
		bind_port = SBcAP_SCTP_PORT;

	OSMO_ASSERT(cbc);
	cbc->rx_cb = sbcap_cbc_client_rx_cb;
	INIT_LLIST_HEAD(&cbc->clients);
	cbc->link = osmo_stream_srv_link_create(cbc);
	osmo_stream_srv_link_set_proto(cbc->link, IPPROTO_SCTP);
	osmo_stream_srv_link_set_data(cbc->link, cbc);
	osmo_stream_srv_link_set_nodelay(cbc->link, true);
	osmo_stream_srv_link_set_port(cbc->link, bind_port);
	osmo_stream_srv_link_set_addrs(cbc->link, (const char **)g_cbc->config.sbcap.local_host,
				       g_cbc->config.sbcap.num_local_host);
	osmo_stream_srv_link_set_accept_cb(cbc->link, sbcap_cbc_accept_cb);
	rc = osmo_stream_srv_link_open(cbc->link);
	OSMO_ASSERT(rc == 0);
	LOGP(DSBcAP, LOGL_NOTICE, "Listening for SBc-AP at %s\n",
		osmo_stream_srv_link_get_sockname(cbc->link));

	return cbc;
}
