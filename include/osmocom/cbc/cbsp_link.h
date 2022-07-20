#pragma once
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/cbsp.h>
#include <osmocom/netif/stream.h>

#include <osmocom/cbc/cbc_data.h>

#define LOGPCC(link, level, fmt, args...) \
	LOGP(DCBSP, level, "%s: " fmt, cbc_cbsp_link_name(link), ## args)

struct cbc_cbsp_link;
struct osmo_fsm_inst;
struct cbc_peer;

/* Holder of all CBSP conn related information: */
struct cbc_cbsp_mgr {
	/* libosmo-netif stream server */
	struct osmo_stream_srv_link *link;

	/* BSCs / clients connected to this CBC */
	struct llist_head clients;

	/* receive call-back; called for every received message */
	int (*rx_cb)(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *dec);
};

struct cbc_cbsp_mgr *cbc_cbsp_mgr_create(void *ctx);

/* a CBSP link with a single (remote) peer connected to us */
struct cbc_cbsp_link {
	/* entry in osmo_cbsp_cbc.clients */
	struct llist_head list;
	/* stream server connection for this link */
	struct osmo_stream_srv *conn;
	/* partially received CBSP message (rx completion pending) */
	struct msgb *rx_msg;

	struct osmo_fsm_inst *fi;

	struct cbc_peer *peer;
};

const char *cbc_cbsp_link_name(const struct cbc_cbsp_link *link);
void cbc_cbsp_link_tx(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *cbsp);
void cbc_cbsp_link_close(struct cbc_cbsp_link *link);
int cbc_cbsp_link_rx_cb(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *dec);
