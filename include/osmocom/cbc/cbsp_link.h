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
	struct osmo_stream_srv_link *srv_link;

	/* BSCs / links connected to this CBC */
	struct llist_head links;

	/* receive call-back; called for every received message */
	int (*rx_cb)(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *dec);
};

struct cbc_cbsp_mgr *cbc_cbsp_mgr_alloc(void *ctx);
int cbc_cbsp_mgr_open_srv(struct cbc_cbsp_mgr *mgr);

/* a CBSP link with a single (remote) peer connected to us */
struct cbc_cbsp_link {
	/* entry in osmo_cbsp_cbc.links */
	struct llist_head list;
	/* partially received CBSP message (rx completion pending) */
	struct msgb *rx_msg;
	struct osmo_fsm_inst *fi;
	struct cbc_peer *peer;
	bool is_client;
	union {
		struct osmo_stream_srv *srv_conn;
		struct osmo_stream_cli *cli_conn;
		void *conn; /* used when we just care about the pointer */
	};
};

struct cbc_cbsp_link *cbc_cbsp_link_alloc(struct cbc_cbsp_mgr *cbc, struct cbc_peer *peer);
void cbc_cbsp_link_free(struct cbc_cbsp_link *link);
const char *cbc_cbsp_link_name(const struct cbc_cbsp_link *link);
int cbc_cbsp_link_open_cli(struct cbc_cbsp_link *link);
int cbc_cbsp_link_tx(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *cbsp);
void cbc_cbsp_link_close(struct cbc_cbsp_link *link);
int cbc_cbsp_link_rx_cb(struct cbc_cbsp_link *link, struct osmo_cbsp_decoded *dec);
