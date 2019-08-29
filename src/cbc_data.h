#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/it_q.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>

struct osmo_cbsp_cbc_client;
struct osmo_sabp_cbc_client;

/*********************************************************************************
 * CBC Peer
 *********************************************************************************/

enum cbc_peer_protocol {
	CBC_PEER_PROTO_CBSP,
	CBC_PEER_PROTO_SABP,
};

struct cbc_peer {
	struct llist_head list;		/* linked to cbc.peers */
	const char *name;

	char *remote_host;	/* remote IP address in string format */
	int remote_port;		/* remote port number or -1 for random */

	enum cbc_peer_protocol proto;
	union {
		struct osmo_cbsp_cbc_client *cbsp;
		struct osmo_sabp_cbc_client *sabp;
	} client;
};

extern const struct value_string cbc_peer_proto_name[];

/*********************************************************************************
 * CBC Message
 *********************************************************************************/

/* a single SMSCB page of 82 user bytes (excluding any GSM specific header) */
#define SMSCB_RAW_PAGE_LEN	82
#define SMSCB_MAX_NUM_PAGES	15

/* representation of a plain SMSCB message without any metadata such as cell lists */
struct smscb_message {
	uint16_t message_id;
	uint16_t serial_nr;

	bool is_etws;
	union {
		struct {
			/* data coding scheme */
			uint8_t dcs;
			/* number of pages containing valid information */
			unsigned int num_pages;
			/* actual page data, concatenated */
			uint8_t data[SMSCB_MAX_NUM_PAGES][SMSCB_RAW_PAGE_LEN];
			/* FIXME: do we need information on the total length to
			 * determine which is the last block used in [at least the last]
			 * page? */
		} cbs;
		struct {
			/* WarningType 16bit parameter as per 23.041 9.3.24 */
			uint16_t warning_type;
			uint8_t warning_sec_info[50];
		} etws;
	};
};

enum cbc_message_scope {
	CBC_MSG_SCOPE_PLMN,
	/* FIXME: more local/regional scopes than PLMN-wide */
};

/* link between a SMSCB message and a peer (BSC, RNC, MME) */
struct cbc_message_peer {
	struct llist_head list;		/* lined to cbc_message.peers */
	struct cbc_peer *peer;		/* peer */
	bool acknowledged;		/* did peer acknowledge this message yet? */
};

/* internal representation of a CBC message */
struct cbc_message {
	struct llist_head list;		/* global list of currently active CBCs */

	const char *cbe_name;		/* name of the CBE originating this SMSCB */
	enum cbsp_category priority;
	uint16_t rep_period;		/* repetition period (1..4095) */
	bool extended_cbch;		/* basic (false) or extended (true) CBCH */
	uint32_t warning_period_sec;	/* warning period in seconds (0xffffffff = unlimited) */
	uint16_t num_bcast;		/* number of broadcasts requested (0=unlimited) */

	enum cbc_message_scope scope;
	/* FIXME: data for other scopes than PLMN-wide */

	/* SMSCB message with id, serial, dcs, pages, ... */
	struct smscb_message msg;

	/* CBC peers (BSCs, RNCs, MMEs) to which this message has already been sent */
	struct llist_head peers;
};

/*********************************************************************************
 * CBC itself
 *********************************************************************************/

struct cbc {
	struct {
		bool permit_unknown_peers;
	} config;

	struct llist_head messages;	/* cbc_message.list */
	struct llist_head peers;	/* cbc_peer.list */
	struct {
		struct osmo_it_q *rest2main;
	} it_q;
};

extern struct cbc *g_cbc;



int cbc_message_del_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer);
int cbc_message_add_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer);
struct cbc_peer *cbc_peer_by_name(const char *name);
struct cbc_peer *cbc_peer_by_addr_proto(const char *remote_host, uint16_t remote_port,
					enum cbc_peer_protocol proto);
struct cbc_peer *cbc_peer_create(const char *name, enum cbc_peer_protocol proto);
void cbc_peer_remove(struct cbc_peer *peer);
