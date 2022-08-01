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

struct cbc_cbsp_link *cbc_cbsp_link_alloc(struct cbc_cbsp_mgr *cbc, struct cbc_peer *peer)
{
	struct cbc_cbsp_link *link;
	char *name;

	link = talloc_zero(cbc, struct cbc_cbsp_link);
	OSMO_ASSERT(link);

	link->peer = peer;
	link->is_client = (peer->link_mode == CBC_PEER_LINK_MODE_CLIENT);

	name = talloc_strdup(link, peer->name);
	osmo_identifier_sanitize_buf(name, NULL, '_');
	link->fi = osmo_fsm_inst_alloc(&cbsp_link_fsm, link, link, LOGL_DEBUG, name);
	if (!link->fi) {
		LOGPCC(link, LOGL_ERROR, "Unable to allocate FSM\n");
		talloc_free(link);
		return NULL;
	}
	talloc_free(name);

	llist_add_tail(&link->list, &cbc->links);
	return link;
}

void cbc_cbsp_link_free(struct cbc_cbsp_link *link)
{
	if (!link)
		return;
	llist_del(&link->list);
	if (link->fi)
		osmo_fsm_inst_free(link->fi);
	talloc_free(link);
}

const char *cbc_cbsp_link_name(const struct cbc_cbsp_link *link)
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
 * TCP client
 */
static int cbc_cbsp_link_cli_connect_cb(struct osmo_stream_cli *conn)
{
	struct cbc_cbsp_link *link = osmo_stream_cli_get_data(conn);
	LOGPCC(link, LOGL_NOTICE, "Connected\n");
	osmo_fsm_inst_dispatch(link->fi, CBSP_LINK_E_CMD_RESET, NULL);
	return 0;
}

static int cbc_cbsp_link_cli_disconnect_cb(struct osmo_stream_cli *conn)
{
	struct cbc_cbsp_link *link = osmo_stream_cli_get_data(conn);
	LOGPCC(link, LOGL_NOTICE, "Disconnected.\n");
	LOGPCC(link, LOGL_NOTICE, "Reconnecting...\n");
	osmo_stream_cli_reconnect(conn);
	return 0;
}

static int cbc_cbsp_link_cli_read_cb(struct osmo_stream_cli *conn)
{
	struct cbc_cbsp_link *link = osmo_stream_cli_get_data(conn);
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);
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
		cbc_cbsp_link_close(link);
		return -EBADF;
	}
	OSMO_ASSERT(msg);
	LOGPCC(link, LOGL_DEBUG, "Received CBSP %s\n", msgb_hexdump(msg));
	/* decode + dispatch message */
	decoded = osmo_cbsp_decode(link, msg);
	if (decoded) {
		LOGPCC(link, LOGL_INFO, "Received CBSP %s\n",
			get_value_string(cbsp_msg_type_names, decoded->msg_type));
		g_cbc->cbsp.mgr->rx_cb(link, decoded);
	} else {
		LOGPCC(link, LOGL_ERROR, "Unable to decode %s\n", msgb_hexdump(msg));
	}
	msgb_free(msg);
	return 0;
}

int cbc_cbsp_link_open_cli(struct cbc_cbsp_link *link)
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
	osmo_stream_cli_set_proto(conn, IPPROTO_TCP);
	osmo_stream_cli_set_connect_cb(conn, cbc_cbsp_link_cli_connect_cb);
	osmo_stream_cli_set_disconnect_cb(conn, cbc_cbsp_link_cli_disconnect_cb);
	osmo_stream_cli_set_read_cb(conn, cbc_cbsp_link_cli_read_cb);
	rc = osmo_stream_cli_set_local_addrs(conn, (const char **)&g_cbc->config.cbsp.local_host, 1);
	if (rc < 0)
		goto free_ret;
	/* We assign free local port for client links:
	 * osmo_stream_cli_set_local_port(conn, g_cbc->cbsp.local_port);
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
 * TCP server
 */
/* data from BSC has arrived at CBC */
static int cbsp_cbc_srv_read_cb(struct osmo_stream_srv *conn)
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
		cbc_cbsp_link_close(link);
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
static int cbsp_cbc_srv_closed_cb(struct osmo_stream_srv *conn)
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
	struct cbc_peer *peer;
	struct cbc_cbsp_link *link;
	char remote_ip[INET6_ADDRSTRLEN], portbuf[6];
	int remote_port;

	remote_ip[0] = '\0';
	portbuf[0] = '\0';
	osmo_sock_get_ip_and_port(fd, remote_ip, sizeof(remote_ip), portbuf, sizeof(portbuf), false);
	remote_port = atoi(portbuf);

	LOGP(DCBSP, LOGL_NOTICE, "New CBSP link connection from %s:%u\n", remote_ip, remote_port);

	/* Match link to peer */
	peer = cbc_peer_by_addr_proto(remote_ip, remote_port, CBC_PEER_PROTO_CBSP);
	if (!peer) {
		if (!g_cbc->config.permit_unknown_peers) {
			LOGP(DCBSP, LOGL_NOTICE,
			     "Rejecting unknown CBSP peer %s:%d (not permitted)\n",
			     remote_ip, remote_port);
			close(fd);
			return -1;
		}
		LOGP(DCBSP, LOGL_NOTICE, "Accepting unknown CBSP peer %s:%d\n",
		     remote_ip, remote_port);
		peer = cbc_peer_create(NULL, CBC_PEER_PROTO_CBSP);
		OSMO_ASSERT(peer);
		peer->unknown_dynamic_peer = true;
	} else { /* peer is known */
		switch (peer->link_mode) {
		case CBC_PEER_LINK_MODE_DISABLED:
			LOGP(DCBSP, LOGL_NOTICE,
			     "Rejecting conn for disabled CBSP peer %s:%d\n",
			     remote_ip, remote_port);
			close(fd);
			return -1;
		case CBC_PEER_LINK_MODE_CLIENT:
			LOGP(DCBSP, LOGL_NOTICE,
			     "Rejecting conn for CBSP peer %s:%d configured as 'client'\n",
			     remote_ip, remote_port);
			close(fd);
			return -1;
		default: /* MODE_SERVER */
			break;
		}
	}
	if (peer->link.cbsp) {
		LOGPCC(peer->link.cbsp, LOGL_ERROR,
		       "We already have a connection for peer %s, closing it\n",
		       peer->name);
		cbc_cbsp_link_close(peer->link.cbsp);
	}
	link = cbc_cbsp_link_alloc(cbc, peer);
	OSMO_ASSERT(link);

	link->srv_conn = osmo_stream_srv_create(srv_link, srv_link, fd,
						cbsp_cbc_srv_read_cb, cbsp_cbc_srv_closed_cb,
						link);
	if (!link->srv_conn) {
		LOGPCC(link, LOGL_ERROR,
		       "Unable to create stream server for %s:%u\n",
		       remote_ip, remote_port);
		cbc_cbsp_link_free(link);
		return -1;
	}
	peer->link.cbsp = link;

	osmo_fsm_inst_dispatch(link->fi, CBSP_LINK_E_CMD_RESET, NULL);
	return 0;
}

int cbc_cbsp_link_tx(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *cbsp)
{
	struct msgb *msg;

	if (!link) {
		LOGP(DCBSP, LOGL_NOTICE, "Cannot transmit %s: no connection\n",
			get_value_string(cbsp_msg_type_names, cbsp->msg_type));
		talloc_free(cbsp);
		return -ENOLINK;
	} else if (link->is_client && !osmo_stream_cli_is_connected(link->cli_conn)) {
		LOGPCC(link, LOGL_NOTICE, "Cannot transmit %s: reconnecting\n",
		     get_value_string(cbsp_msg_type_names, cbsp->msg_type));
		talloc_free(cbsp);
		return -ENOTCONN;
	}

	LOGPCC(link, LOGL_INFO, "Transmitting %s\n",
		get_value_string(cbsp_msg_type_names, cbsp->msg_type));

	msg = osmo_cbsp_encode(link, cbsp);
	if (!msg) {
		LOGPCC(link, LOGL_ERROR, "Failed to encode CBSP %s: %s\n",
			get_value_string(cbsp_msg_type_names, cbsp->msg_type), osmo_cbsp_errstr);
		talloc_free(cbsp);
		return -EINVAL;
	}
	talloc_free(cbsp);
	if (link->is_client)
		osmo_stream_cli_send(link->cli_conn, msg);
	else
		osmo_stream_srv_send(link->srv_conn, msg);
	return 0;
}

void cbc_cbsp_link_close(struct cbc_cbsp_link *link)
{
	if (!link->conn)
		return;

	if (link->is_client) {
		osmo_stream_cli_destroy(link->cli_conn);
		if (link->peer)
			link->peer->link.cbsp = NULL;
		link->cli_conn = NULL;
		if (link->fi)
			osmo_fsm_inst_dispatch(link->fi, CBSP_LINK_E_CMD_CLOSE, NULL);
	} else {
		osmo_stream_srv_destroy(link->srv_conn);
		/* Same as waht's done for cli is done for srv in closed_cb() */
	}
}

/*
 * CBSP Manager
 */
struct cbc_cbsp_mgr *cbc_cbsp_mgr_alloc(void *ctx)
{
	struct cbc_cbsp_mgr *mgr;

	mgr = talloc_zero(ctx, struct cbc_cbsp_mgr);
	OSMO_ASSERT(mgr);
	mgr->rx_cb = cbc_cbsp_link_rx_cb;
	INIT_LLIST_HEAD(&mgr->links);

	return mgr;
}

/* initialize the CBC-side CBSP server */
int cbc_cbsp_mgr_open_srv(struct cbc_cbsp_mgr *mgr)
{
	char *bind_ip = g_cbc->config.cbsp.local_host;
	int bind_port = g_cbc->config.cbsp.local_port;
	struct osmo_stream_srv_link *srv_link;
	int rc;

	srv_link = osmo_stream_srv_link_create(mgr);
	osmo_stream_srv_link_set_data(srv_link, mgr);
	osmo_stream_srv_link_set_nodelay(srv_link, true);
	osmo_stream_srv_link_set_port(srv_link, bind_port);
	if (bind_ip)
		osmo_stream_srv_link_set_addr(srv_link, bind_ip);
	osmo_stream_srv_link_set_accept_cb(srv_link, cbsp_cbc_accept_cb);
	rc = osmo_stream_srv_link_open(srv_link);
	if (rc < 0) {
		osmo_stream_srv_link_destroy(srv_link);
		talloc_free(mgr);
		return -EIO;
	}
	mgr->srv_link = srv_link;
	LOGP(DCBSP, LOGL_NOTICE, "Listening for CBSP at %s\n",
		osmo_stream_srv_link_get_sockname(mgr->srv_link));
	return 0;
}
