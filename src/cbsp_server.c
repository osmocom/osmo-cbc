#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/cbsp.h>
#include <osmocom/netif/stream.h>

/* a CBC server */
struct osmo_cbsp_cbc {
	/* libosmo-netif stream server */
	struct osmo_stream_srv_link *link;

	/* BSCs / clients connected to this CBC */
	struct llist_head clients;
};

/* a single (remote) client connected to the (local) CBC server */
struct osmo_cbsp_cbc_client {
	/* entry in osmo_cbsp_cbc.clients */
	struct llist_head list;
	/* stream server connection for this client */
	struct osmo_stream_srv *conn;
	/* partially received CBSP message (rx completion pending) */
	struct msgb *rx_msg;
	/* receive call-back; called for every received message */
	int (*rx_cb)(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *dec);
};


#if 0
struct osmo_cbsp_bsc {
	/* libosmo-netif stream client */
	struct osmo_stream_cli *stream;
};
#endif


/*! Read one CBSP message from socket fd or store part if still not fully received.
 *  \param[in] fd The fd for the socket to read from.
 *  \param[out] rmsg internally allocated msgb containing a fully received CBSP message.
 *  \param[inout] tmp_msg internally allocated msgb caching data for not yet fully received message.
 *
 *  Function is designed just like ipa_msg_recv_buffered()
 */
int osmo_cbsp_recv_buffered(int fd, struct msgb **rmsg, struct msgb **tmp_msg)
{
	struct msgb *msg = tmp_msg ? *tmp_msg : NULL;
	struct cbsp_header *h;
	int len, rc;
	int needed;

	if (!msg) {
		msg = osmo_cbsp_msgb_alloc(__func__);
		if (!msg) {
			return -ENOMEM;
			goto discard_msg;
		}
		msg->l1h = msg->tail;
	}

	if (msg->l2h == NULL) {
		/* first read the [missing part of the] header */
		needed = sizeof(*h) - msg->len;
		rc = recv(fd, msg->tail, needed, 0);
		if (rc == 0)
			goto discard_msg;
		else if (rc < 0) {
			if (errno == EAGAIN || errno == EINTR)
				rc = 0;
			else {
				rc = -errno;
				goto discard_msg;
			}
		}
		msgb_put(msg, rc);
		if (rc < needed) {
			if (msg->len == 0) {
				rc = -EAGAIN;
				goto discard_msg;
			}

			if (!tmp_msg) {
				rc = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}
		msg->l2h = msg->tail;
	}

	/* then read the length as specified in the header */
	len = h->len[0] << 16 | h->len[1] << 8 | h->len[0];

	needed = len - msgb_l2len(msg);
	if (needed > 0) {
		rc = recv(fd, msg->tail, needed, 0);
		if (rc == 0)
			goto discard_msg;
		else if (rc < 0) {
			if (errno == EAGAIN || errno == EINTR)
				rc = 0;
			else {
				rc = -errno;
				goto discard_msg;
			}
		}
		msgb_put(msg, rc);
		/* still not all of payload received? */
		if (rc < needed) {
			if (!tmp_msg) {
				rc = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}
	}
	/* else: complete message received */
	rc = msgb_l2len(msg);
	if (rc == 0) {
		/* drop empty message */
		rc = -EAGAIN;
		goto discard_msg;
	}
	if (tmp_msg)
		*tmp_msg = NULL;
	*rmsg = msg;
	return rc;

discard_msg:
	if (tmp_msg)
		*tmp_msg = NULL;
	msgb_free(msg);
	return rc;
}







/* data from BSC has arrived at CBC */
static int cbsp_cbc_read_cb(struct osmo_stream_srv *conn)
{
	struct osmo_cbsp_cbc_client *client = osmo_stream_srv_get_data(conn);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_cbsp_decoded *decoded;
	struct msgb *msg = NULL;
	int rc;

	/* message de-segmentation */
	rc = osmo_cbsp_recv_buffered(ofd->fd, &msg, &client->rx_msg);
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
		return -EBADF;
	}
	OSMO_ASSERT(msg);
	/* decode + dispatch message */
	decoded = osmo_cbsp_decode(client, msg);
	msgb_free(msg);
	if (decoded)
		client->rx_cb(client, decoded);
	return 0;
}

/* connection from BSC to CBC has been closed */
static int cbsp_cbc_closed_cb(struct osmo_stream_srv *conn)
{
	struct osmo_cbsp_cbc_client *client = osmo_stream_srv_get_data(conn);
	llist_del(&client->list);
	talloc_free(client);
	return 0;
}

/* new connection from BSC has arrived at CBC */
static int cbsp_cbc_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_cbsp_cbc *cbc = osmo_stream_srv_link_get_data(link);
	struct osmo_cbsp_cbc_client *client = talloc_zero(cbc, struct osmo_cbsp_cbc_client);
	OSMO_ASSERT(client);

	client->conn = osmo_stream_srv_create(link, link, fd, cbsp_cbc_read_cb, cbsp_cbc_closed_cb, client);
	if (!client->conn) {
		talloc_free(client);
		return -1;
	}
	llist_add_tail(&client->list, &cbc->clients);

	return 0;
}

void cbsp_cbc_client_tx(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *cbsp)
{
	struct msgb *msg = osmo_cbsp_encode(cbsp);
	talloc_free(cbsp);
	if (!msg) {
		/* FIXME */
		return;
	}
	osmo_stream_srv_send(client->conn, msg);
}

/* initialize the CBC-side CBSP server */
struct osmo_cbsp_cbc *cbsp_cbc_create(void *ctx)
{
	struct osmo_cbsp_cbc *cbc = talloc_zero(ctx, struct osmo_cbsp_cbc);
	int rc;

	OSMO_ASSERT(cbc);
	INIT_LLIST_HEAD(&cbc->clients);
	cbc->link = osmo_stream_srv_link_create(cbc);
	osmo_stream_srv_link_set_data(cbc->link, cbc);
	osmo_stream_srv_link_set_nodelay(cbc->link, true);
	osmo_stream_srv_link_set_port(cbc->link, 48049);
	osmo_stream_srv_link_set_accept_cb(cbc->link, cbsp_cbc_accept_cb);
	rc = osmo_stream_srv_link_open(cbc->link);
	OSMO_ASSERT(rc == 0);

	return cbc;
}
