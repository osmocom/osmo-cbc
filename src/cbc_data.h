#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/it_q.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/gsm/gsm23003.h>

struct osmo_cbsp_cbc_client;
struct osmo_sabp_cbc_client;
struct rest_it_op;

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

enum cbc_cell_id_type {
	CBC_CELL_ID_NONE,
	CBC_CELL_ID_BSS,
	CBC_CELL_ID_CGI,
	CBC_CELL_ID_LAC_CI,
	CBC_CELL_ID_LAI,
	CBC_CELL_ID_LAC,
	CBC_CELL_ID_CI,
};

struct cbc_cell_id {
	struct llist_head list;
	enum cbc_cell_id_type id_discr;
	union {
		struct osmo_cell_global_id cgi;
		struct osmo_lac_and_ci_id lac_and_ci;
		struct osmo_location_area_id lai;
		uint16_t lac;
		uint16_t ci;
	} u;
	/* only in failure list */
	struct {
		int cause;
	} fail;
	/* only in num_compl list */
	struct {
		uint32_t num_compl;
		uint32_t num_bcast_info;
	} num_compl;
};


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
			/* total number of octets user data over _all_ the pages */
			uint16_t data_user_len;
		} cbs;
		struct {
			/* WarningTypeValue 7bit parameter as per 23.041 9.3.24 */
			uint16_t warning_type;
			/* Emergency User Alert */
			bool user_alert;
			/* Popup on Display */
			bool popup_on_display;
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

	/* 'cbcmsg' is not really needed, as the fsm instance parent points to
	 * the fsm instance of cbc_message, so we could also dereference those */
	struct cbc_message *cbcmsg;	/* the SMSCB this relates to */
	struct cbc_peer *peer;		/* the peer thos relates to */
	struct osmo_fsm_inst *fi;	/* the FSM instance representing our state */

	/* cells in which this message has been established/installed */
	struct llist_head cell_list;
	/* cells in which this message has NOT been established/installed */
	struct llist_head fail_list;
	/* number of broadcasts completed in cells of this peer */
	struct llist_head num_compl_list;
};

/* internal representation of a CBC message */
struct cbc_message {
	struct llist_head list;		/* global list of currently active CBCs */

	const char *cbe_name;		/* name of the CBE originating this SMSCB */
	enum cbsp_category priority;
	uint16_t rep_period;		/* repetition period (1..4095) in units of 1.883s */
	bool extended_cbch;		/* basic (false) or extended (true) CBCH */
	uint32_t warning_period_sec;	/* warning period in seconds (0xffffffff = unlimited) */
	uint16_t num_bcast;		/* number of broadcasts requested (0=unlimited) */

	enum cbc_message_scope scope;
	/* FIXME: data for other scopes than PLMN-wide */

	/* SMSCB message with id, serial, dcs, pages, ... */
	struct smscb_message msg;

	struct osmo_fsm_inst *fi;	/* FSM instance (smscb_message_fsm) */

	/* CBC peers (BSCs, RNCs, MMEs) to which this message has already been sent */
	struct llist_head peers;

	struct rest_it_op *it_op;	/* inter-thread queue operation currently processing */

	struct {
		time_t created;		/* when was this message created? */
		time_t expired;		/* when has this message expired? */
	} time;
};

/*********************************************************************************
 * CBC itself
 *********************************************************************************/

struct cbc {
	struct {
		bool permit_unknown_peers;
		struct {
			char *local_host;
			int local_port;
		} cbsp;
		struct {
			char *local_host;
			int local_port;
		} ecbe;
	} config;

	struct llist_head messages;	/* cbc_message.list */
	struct llist_head expired_messages;	/* cbc_message.list */
	struct llist_head peers;	/* cbc_peer.list */
	struct {
		struct osmo_it_q *rest2main;
	} it_q;
};

extern struct cbc *g_cbc;



int cbc_message_del_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer);
int cbc_message_add_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer);
struct cbc_message_peer *smscb_peer_fsm_alloc(struct cbc_peer *peer, struct cbc_message *cbcmsg);
struct cbc_message_peer *cbc_message_peer_get(struct cbc_message *cbcmsg, struct cbc_peer *peer);
struct cbc_peer *cbc_peer_by_name(const char *name);
struct cbc_peer *cbc_peer_by_addr_proto(const char *remote_host, uint16_t remote_port,
					enum cbc_peer_protocol proto);
struct cbc_peer *cbc_peer_create(const char *name, enum cbc_peer_protocol proto);
void cbc_peer_remove(struct cbc_peer *peer);

