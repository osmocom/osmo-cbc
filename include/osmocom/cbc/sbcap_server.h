#pragma once
#include <osmocom/core/linuxlist.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sbcap/sbcap_common.h>

#include "cbc_data.h"

#define SBcAP_SCTP_PORT 29168
typedef struct SBcAP_SBC_AP_PDU SBcAP_SBC_AP_PDU_t;
#define LOGPSBCAPC(client, level, fmt, args...) \
	LOGP(DSBcAP, level, "%s: " fmt, sbcap_cbc_client_name(client), ## args)

struct osmo_sbcap_cbc_client;
struct osmo_fsm_inst;

/* a CBC server */
struct osmo_sbcap_cbc {
	/* libosmo-netif stream server */
	struct osmo_stream_srv_link *link;

	/* MMEs / clients connected to this CBC */
	struct llist_head clients;

	/* receive call-back; called for every received message */
	int (*rx_cb)(struct osmo_sbcap_cbc_client *client, SBcAP_SBC_AP_PDU_t *pdu);
};
struct osmo_sbcap_cbc *sbcap_cbc_create(void *ctx);

/* a single (remote) client connected to the (local) CBC server */
struct osmo_sbcap_cbc_client {
	/* entry in osmo_sbcap_cbc.clients */
	struct llist_head list;
	/* stream server connection for this client */
	struct osmo_stream_srv *conn;
	/* partially received sbcap message (rx completion pending) */
	struct msgb *rx_msg;

	struct osmo_fsm_inst *fi;

	struct cbc_peer *peer;
};

const char *sbcap_cbc_client_name(const struct osmo_sbcap_cbc_client *client);
void sbcap_cbc_client_tx(struct osmo_sbcap_cbc_client *client, SBcAP_SBC_AP_PDU_t *pdu);
void sbcap_cbc_client_close(struct osmo_sbcap_cbc_client *client);
int sbcap_cbc_client_rx_cb(struct osmo_sbcap_cbc_client *client, SBcAP_SBC_AP_PDU_t *pdu);
