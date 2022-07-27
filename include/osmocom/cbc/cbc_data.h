#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/it_q.h>
#include <osmocom/gsm/protocol/gsm_48_049.h>
#include <osmocom/gsm/gsm23003.h>

#define CBC_MAX_LOC_ADDRS 8

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

const char *cbc_cell_id2str(const struct cbc_cell_id *cid);

/*********************************************************************************
 * CBC itself
 *********************************************************************************/
struct cbc_cbsp_mgr;
struct cbc_sbcap_mgr;

struct cbc {
	struct {
		bool permit_unknown_peers;
		struct {
			char *local_host;
			int local_port;
		} cbsp;
		struct {
			char *local_host[CBC_MAX_LOC_ADDRS];
			unsigned int num_local_host;
			int local_port;
		} sbcap;
		struct {
			char *local_host;
			int local_port;
		} ecbe;
	} config;

	struct {
		struct cbc_cbsp_mgr *mgr;
	} cbsp;
	struct {
		struct cbc_sbcap_mgr *mgr;
	} sbcap;

	struct llist_head messages;	/* cbc_message.list */
	struct llist_head expired_messages;	/* cbc_message.list */
	struct llist_head peers;	/* cbc_peer.list */
	struct {
		struct osmo_it_q *rest2main;
	} it_q;
};

extern struct cbc *g_cbc;
struct cbc *cbc_alloc(void *ctx);
int cbc_start(struct cbc *cbc);

/* rest_api.c */
int rest_api_init(void *ctx, const char *bind_addr, uint16_t port);
void rest_api_fin(void);
