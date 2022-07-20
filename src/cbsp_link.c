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
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/cbsp.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/netif/stream.h>

#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/cbsp_link.h>
#include <osmocom/cbc/cbsp_link_fsm.h>
#include <osmocom/cbc/cbc_peer.h>

const char *cbc_cbsp_link_name(const struct cbc_cbsp_link *link)
{
	OSMO_ASSERT(link);

	if (link->peer && link->peer->name) {
		return link->peer->name;
	} else {
		struct osmo_fd *ofd = osmo_stream_srv_get_ofd(link->conn);
		return osmo_sock_get_name2(ofd->fd);
	}
}

/* data from BSC has arrived at CBC */
static int cbsp_cbc_read_cb(struct osmo_stream_srv *conn)
{
	struct osmo_stream_srv_link *srv_link = osmo_stream_srv_get_master(conn);
	struct cbc_cbsp_link *link = osmo_stream_srv_get_data(conn);
	struct cbc_cbsp_mgr *cbc = osmo_stream_srv_link_get_data(srv_link);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_cbsp_decoded *decoded;
	struct msgb *msg = NULL;
	int rc;

	LOGPCC(link, LOGL_DEBUG, "read_cb rx_msg=%p\n", link->rx_msg);

	/* message de-segmentation */
	rc = osmo_cbsp_recv_buffered(conn, ofd->fd, &msg, &link->rx_msg);
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
	LOGPCC(link, LOGL_DEBUG, "Received CBSP %s\n", msgb_hexdump(msg));
	/* decode + dispatch message */
	decoded = osmo_cbsp_decode(link, msg);
	if (decoded) {
		LOGPCC(link, LOGL_INFO, "Received CBSP %s\n",
			get_value_string(cbsp_msg_type_names, decoded->msg_type));
		cbc->rx_cb(link, decoded);
	} else {
		LOGPCC(link, LOGL_ERROR, "Unable to decode %s\n", msgb_hexdump(msg));
	}
	msgb_free(msg);
	return 0;
}

/* connection from BSC to CBC has been closed */
static int cbsp_cbc_closed_cb(struct osmo_stream_srv *conn)
{
	struct cbc_cbsp_link *link = osmo_stream_srv_get_data(conn);
	LOGPCC(link, LOGL_NOTICE, "connection closed\n");

	if (link->peer)
		link->peer->link.cbsp = NULL;
	link->conn = NULL;
	if (link->fi)
		osmo_fsm_inst_dispatch(link->fi, CBSP_LINK_E_CMD_CLOSE, NULL);

	return 0;
}

/* new connection from BSC has arrived at CBC */
static int cbsp_cbc_accept_cb(struct osmo_stream_srv_link *srv_link, int fd)
{
	struct cbc_cbsp_mgr *cbc = osmo_stream_srv_link_get_data(srv_link);
	struct cbc_cbsp_link *link = talloc_zero(cbc, struct cbc_cbsp_link);
	char remote_ip[INET6_ADDRSTRLEN], portbuf[6];
	int remote_port;
	OSMO_ASSERT(link);

	remote_ip[0] = '\0';
	portbuf[0] = '\0';
	osmo_sock_get_ip_and_port(fd, remote_ip, sizeof(remote_ip), portbuf, sizeof(portbuf), false);
	remote_port = atoi(portbuf);

	LOGP(DCBSP, LOGL_NOTICE, "New CBSP link connection from %s:%u\n", remote_ip, remote_port);

	link->conn = osmo_stream_srv_create(srv_link, srv_link, fd, cbsp_cbc_read_cb, cbsp_cbc_closed_cb, link);
	if (!link->conn) {
		LOGP(DCBSP, LOGL_ERROR, "Unable to create stream server for %s:%d\n",
			remote_ip, remote_port);
		talloc_free(link);
		return -1;
	}
	link->fi = osmo_fsm_inst_alloc(&cbsp_link_fsm, link, link, LOGL_DEBUG, NULL);
	if (!link->fi) {
		LOGPCC(link, LOGL_ERROR, "Unable to allocate FSM\n");
		osmo_stream_srv_destroy(link->conn);
		talloc_free(link);
		return -1;
	}
	llist_add_tail(&link->list, &cbc->clients);

	/* Match link to peer */
	link->peer = cbc_peer_by_addr_proto(remote_ip, remote_port, CBC_PEER_PROTO_CBSP);
	if (!link->peer) {
		if (g_cbc->config.permit_unknown_peers) {
			LOGPCC(link, LOGL_NOTICE, "Accepting unknown CBSP peer %s:%d\n",
				remote_ip, remote_port);
			link->peer = cbc_peer_create(NULL, CBC_PEER_PROTO_CBSP);
			OSMO_ASSERT(link->peer);
			link->peer->unknown_dynamic_peer = true;
		} else {
			LOGPCC(link, LOGL_NOTICE, "Rejecting unknown CBSP peer %s:%d (not permitted)\n",
				remote_ip, remote_port);
			osmo_stream_srv_destroy(link->conn);
			return -1;
		}
	} else {
		if (link->peer->link.cbsp) {
			LOGPCC(link, LOGL_ERROR, "We already have a connection for peer %s\n",
				link->peer->name);
			/* FIXME */
		}
		link->peer->link.cbsp = link;
	}

	osmo_fsm_inst_dispatch(link->fi, CBSP_LINK_E_CMD_RESET, NULL);
	return 0;
}

void cbc_cbsp_link_tx(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *cbsp)
{
	struct msgb *msg;

	if (!link) {
		LOGP(DCBSP, LOGL_NOTICE, "Cannot transmit %s: no connection\n",
			get_value_string(cbsp_msg_type_names, cbsp->msg_type));
		return ;
	}

	LOGPCC(link, LOGL_INFO, "Transmitting %s\n",
		get_value_string(cbsp_msg_type_names, cbsp->msg_type));

	msg = osmo_cbsp_encode(link, cbsp);
	if (!msg) {
		LOGPCC(link, LOGL_ERROR, "Failed to encode CBSP %s: %s\n",
			get_value_string(cbsp_msg_type_names, cbsp->msg_type), osmo_cbsp_errstr);
		talloc_free(cbsp);
		return;
	}
	talloc_free(cbsp);
	osmo_stream_srv_send(link->conn, msg);
}

void cbc_cbsp_link_close(struct cbc_cbsp_link *link)
{
	osmo_stream_srv_destroy(link->conn);
}

/* initialize the CBC-side CBSP server */
struct cbc_cbsp_mgr *cbc_cbsp_mgr_create(void *ctx)
{
	struct cbc_cbsp_mgr *cbc = talloc_zero(ctx, struct cbc_cbsp_mgr);
	int rc;
	char *bind_ip = g_cbc->config.cbsp.local_host;
	int bind_port = g_cbc->config.cbsp.local_port;

	if (bind_port == -1)
		bind_port = CBSP_TCP_PORT;

	OSMO_ASSERT(cbc);
	cbc->rx_cb = cbc_cbsp_link_rx_cb;
	INIT_LLIST_HEAD(&cbc->clients);
	cbc->link = osmo_stream_srv_link_create(cbc);
	osmo_stream_srv_link_set_data(cbc->link, cbc);
	osmo_stream_srv_link_set_nodelay(cbc->link, true);
	osmo_stream_srv_link_set_port(cbc->link, bind_port);
	if (bind_ip)
		osmo_stream_srv_link_set_addr(cbc->link, bind_ip);
	osmo_stream_srv_link_set_accept_cb(cbc->link, cbsp_cbc_accept_cb);
	rc = osmo_stream_srv_link_open(cbc->link);
	if (rc < 0) {
		osmo_stream_srv_link_destroy(cbc->link);
		talloc_free(cbc);
		return NULL;
	}
	LOGP(DCBSP, LOGL_NOTICE, "Listening for CBSP at %s\n",
		osmo_stream_srv_link_get_sockname(cbc->link));

	return cbc;
}
