#pragma once
#include <osmocom/core/linuxlist.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sbcap/sbcap_common.h>

#include "cbc_data.h"

#define SBcAP_SCTP_PORT 29168
typedef struct SBcAP_SBC_AP_PDU SBcAP_SBC_AP_PDU_t;
#define LOGPSBCAPC(link, level, fmt, args...) \
	LOGP(DSBcAP, level, "%s: " fmt, cbc_sbcap_link_name(link), ## args)

struct cbc_sbcap_link;
struct osmo_fsm_inst;
struct cbc_peer;

/* Holder of all SBc-AP conn related information: */
struct cbc_sbcap_mgr {
	/* libosmo-netif stream server */
	struct osmo_stream_srv_link *link;

	/* MMEs / clients connected to this CBC */
	struct llist_head clients;

	/* receive call-back; called for every received message */
	int (*rx_cb)(struct cbc_sbcap_link *link, SBcAP_SBC_AP_PDU_t *pdu);
};
struct cbc_sbcap_mgr *cbc_sbcap_mgr_create(void *ctx);

/* an SBc-AP link with a single (remote) peer connected to us */
struct cbc_sbcap_link {
	/* entry in osmo_sbcap_cbc.clients */
	struct llist_head list;
	/* stream server connection for this link */
	struct osmo_stream_srv *conn;
	struct osmo_fsm_inst *fi;
	struct cbc_peer *peer;
};

const char *cbc_sbcap_link_name(const struct cbc_sbcap_link *link);
void cbc_sbcap_link_tx(struct cbc_sbcap_link *link, SBcAP_SBC_AP_PDU_t *pdu);
void cbc_sbcap_link_close(struct cbc_sbcap_link *link);
int cbc_sbcap_link_rx_cb(struct cbc_sbcap_link *link, SBcAP_SBC_AP_PDU_t *pdu);
