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

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/cbsp.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/netif/stream.h>

#include "internal.h"
#include "cbsp_server.h"

#if 0
struct osmo_cbsp_bsc {
	/* libosmo-netif stream client */
	struct osmo_stream_cli *stream;
};
#endif


const char *cbsp_cbc_client_name(const struct osmo_cbsp_cbc_client *client)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(client->conn);
	return osmo_sock_get_name2(ofd->fd);
}

/* data from BSC has arrived at CBC */
static int cbsp_cbc_read_cb(struct osmo_stream_srv *conn)
{
	struct osmo_stream_srv_link *link = osmo_stream_srv_get_master(conn);
	struct osmo_cbsp_cbc_client *client = osmo_stream_srv_get_data(conn);
	struct osmo_cbsp_cbc *cbc = osmo_stream_srv_link_get_data(link);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_cbsp_decoded *decoded;
	struct msgb *msg = NULL;
	int rc;

	LOGPCC(client, LOGL_DEBUG, "read_cb rx_msg=%p\n", client->rx_msg);

	/* message de-segmentation */
	rc = osmo_cbsp_recv_buffered(conn, ofd->fd, &msg, &client->rx_msg);
	if (rc <= 0) {
		if (rc == -EAGAIN || rc == -EINTR) {
			/* more data needs to be read */
			return 0;
		} else if (rc == -EPIPE || rc == -ECONNRESET) {
			/* lost connection with server */
		} else if (rc == 0) {
			/* connection closed with server */

		}
		/* destroy connection */
		osmo_stream_srv_destroy(conn);
		return -EBADF;
	}
	OSMO_ASSERT(msg);
	LOGPCC(client, LOGL_DEBUG, "Received CBSP %s\n", msgb_hexdump(msg));
	/* decode + dispatch message */
	decoded = osmo_cbsp_decode(client, msg);
	if (decoded) {
		LOGPCC(client, LOGL_INFO, "Received CBSP %s\n",
			get_value_string(cbsp_msg_type_names, decoded->msg_type));
		cbc->rx_cb(client, decoded);
	} else {
		LOGPCC(client, LOGL_ERROR, "Unable to decode %s\n", msgb_hexdump(msg));
	}
	msgb_free(msg);
	return 0;
}

/* connection from BSC to CBC has been closed */
static int cbsp_cbc_closed_cb(struct osmo_stream_srv *conn)
{
	struct osmo_cbsp_cbc_client *client = osmo_stream_srv_get_data(conn);
	LOGPCC(client, LOGL_INFO, "connection closed\n");

	client->conn = NULL;
	osmo_fsm_inst_dispatch(client->fi, CBSP_SRV_E_CMD_CLOSE, NULL);

	return 0;
}

/* new connection from BSC has arrived at CBC */
static int cbsp_cbc_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_cbsp_cbc *cbc = osmo_stream_srv_link_get_data(link);
	struct osmo_cbsp_cbc_client *client = talloc_zero(cbc, struct osmo_cbsp_cbc_client);
	char remote_ip[INET6_ADDRSTRLEN], portbuf[6];
	int remote_port;
	OSMO_ASSERT(client);

	remote_ip[0] = '\0';
	portbuf[0] = '\0';
	osmo_sock_get_ip_and_port(fd, remote_ip, sizeof(remote_ip), portbuf, sizeof(portbuf), false);
	remote_port = atoi(portbuf);

	client->conn = osmo_stream_srv_create(link, link, fd, cbsp_cbc_read_cb, cbsp_cbc_closed_cb, client);
	if (!client->conn) {
		LOGP(DCBSP, LOGL_ERROR, "Unable to create stream server for %s:%d\n",
			remote_ip, remote_port);
		talloc_free(client);
		return -1;
	}
	client->fi = osmo_fsm_inst_alloc(&cbsp_server_fsm, client, client, LOGL_DEBUG, NULL);
	if (!client->fi) {
		LOGPCC(client, LOGL_ERROR, "Unable to allocate FSM\n");
		osmo_stream_srv_destroy(client->conn);
		talloc_free(client);
		return -1;
	}
	llist_add_tail(&client->list, &cbc->clients);

	/* Match client to peer */
	client->peer = cbc_peer_by_addr_proto(remote_ip, remote_port, CBC_PEER_PROTO_CBSP);
	if (!client->peer) {
		if (g_cbc->config.permit_unknown_peers) {
			LOGPCC(client, LOGL_INFO, "Accepting unknown CBSP peer %s:%d\n",
				remote_ip, remote_port);
			client->peer = cbc_peer_create(NULL, CBC_PEER_PROTO_CBSP);
			OSMO_ASSERT(client->peer);
		} else {
			LOGPCC(client, LOGL_NOTICE, "Rejecting unknown CBSP peer %s:%d (not permitted)\n",
				remote_ip, remote_port);
			osmo_stream_srv_destroy(client->conn);
			/* FIXME: further cleanup needed? or does close_cb handle everything? */
			return -1;
		}
	} else {
		if (client->peer->client.cbsp) {
			LOGPCC(client, LOGL_ERROR, "We already have a connection for peer %s\n");
			/* FIXME */
		}
		client->peer->client.cbsp = client;
	}

	LOGPCC(client, LOGL_INFO, "New CBSP client connection\n");
	osmo_fsm_inst_dispatch(client->fi, CBSP_SRV_E_CMD_RESET, NULL);

	return 0;
}

void cbsp_cbc_client_tx(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *cbsp)
{
	struct msgb *msg = osmo_cbsp_encode(client, cbsp);
	LOGPCC(client, LOGL_INFO, "Transmitting %s\n",
		get_value_string(cbsp_msg_type_names, cbsp->msg_type));
	if (!msg) {
		LOGPCC(client, LOGL_ERROR, "Failed to encode CBSP %s: %s\n",
			get_value_string(cbsp_msg_type_names, cbsp->msg_type), osmo_cbsp_errstr);
		talloc_free(cbsp);
		return;
	}
	talloc_free(cbsp);
	osmo_stream_srv_send(client->conn, msg);
}

void cbsp_cbc_client_close(struct osmo_cbsp_cbc_client *client)
{
	if (client->fi)
		osmo_fsm_inst_dispatch(client->fi, CBSP_SRV_E_CMD_CLOSE, NULL);
	osmo_stream_srv_destroy(client->conn);
	/* FIXME: do we need to unlink/free the client? */
}

/* initialize the CBC-side CBSP server */
struct osmo_cbsp_cbc *cbsp_cbc_create(void *ctx, const char *bind_ip, int bind_port,
				      int (*rx_cb)(struct osmo_cbsp_cbc_client *client,
						   struct osmo_cbsp_decoded *dec))
{
	struct osmo_cbsp_cbc *cbc = talloc_zero(ctx, struct osmo_cbsp_cbc);
	int rc;

	if (bind_port == -1)
		bind_port = CBSP_TCP_PORT;

	OSMO_ASSERT(cbc);
	cbc->rx_cb = rx_cb;
	INIT_LLIST_HEAD(&cbc->clients);
	cbc->link = osmo_stream_srv_link_create(cbc);
	osmo_stream_srv_link_set_data(cbc->link, cbc);
	osmo_stream_srv_link_set_nodelay(cbc->link, true);
	osmo_stream_srv_link_set_port(cbc->link, bind_port);
	if (bind_ip)
		osmo_stream_srv_link_set_addr(cbc->link, bind_ip);
	osmo_stream_srv_link_set_accept_cb(cbc->link, cbsp_cbc_accept_cb);
	rc = osmo_stream_srv_link_open(cbc->link);
	OSMO_ASSERT(rc == 0);
	LOGP(DCBSP, LOGL_NOTICE, "Listening for CBSP at %s\n",
		osmo_stream_srv_link_get_sockname(cbc->link));

	return cbc;
}
