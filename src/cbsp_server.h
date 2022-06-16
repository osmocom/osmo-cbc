#pragma once
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/cbsp.h>
#include <osmocom/netif/stream.h>

#include "cbc_data.h"

#define LOGPCC(client, level, fmt, args...) \
	LOGP(DCBSP, level, "%s: " fmt, cbsp_cbc_client_name(client), ## args)

struct osmo_cbsp_cbc_client;
struct osmo_fsm_inst;

/* a CBC server */
struct osmo_cbsp_cbc {
	/* libosmo-netif stream server */
	struct osmo_stream_srv_link *link;

	/* BSCs / clients connected to this CBC */
	struct llist_head clients;

	/* receive call-back; called for every received message */
	int (*rx_cb)(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *dec);
};

struct osmo_cbsp_cbc *cbsp_cbc_create(void *ctx, const char *bind_ip, int bind_port,
				      int (*rx_cb)(struct osmo_cbsp_cbc_client *client,
						   struct osmo_cbsp_decoded *dec));

/* a single (remote) client connected to the (local) CBC server */
struct osmo_cbsp_cbc_client {
	/* entry in osmo_cbsp_cbc.clients */
	struct llist_head list;
	/* stream server connection for this client */
	struct osmo_stream_srv *conn;
	/* partially received CBSP message (rx completion pending) */
	struct msgb *rx_msg;

	struct osmo_fsm_inst *fi;

	struct cbc_peer *peer;
};

const char *cbsp_cbc_client_name(const struct osmo_cbsp_cbc_client *client);
void cbsp_cbc_client_tx(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *cbsp);
void cbsp_cbc_client_close(struct osmo_cbsp_cbc_client *client);
