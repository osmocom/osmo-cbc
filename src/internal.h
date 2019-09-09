#pragma once

#include <stdint.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>

#include "cbc_data.h"

enum {
	DCBSP,
	DREST,
};

extern struct osmo_fsm cbsp_server_fsm;

enum cbsp_server_event {
	CBSP_SRV_E_RX_RST_COMPL,
	CBSP_SRV_E_RX_RST_FAIL,
	CBSP_SRV_E_RX_KA_COMPL,
	CBSP_SRV_E_RX_RESTART,
	CBSP_SRV_E_CMD_RESET,
};


/* rest_api.c */
int rest_api_init(void *ctx, uint16_t port);
void rest_api_fin(void);

/* cbc_vty.c */
void cbc_vty_init(void);

/* message_handling.c */
int cbc_message_new(struct cbc_message *cbcmsg);
struct cbc_message *cbc_message_by_id(uint16_t message_id);

/* rest_it_op.c */
void rest2main_read_cb(struct osmo_it_q *q, void *item);


/* smscb_*fsm.c */
enum smscb_fsm_event {
	SMSCB_E_CHILD_DIED,
	/* create a message (from REST) */
	SMSCB_E_CREATE,
	/* replace a message (from REST) */
	SMSCB_E_REPLACE,
	/* get status of a message (from REST) */
	SMSCB_E_STATUS,
	/* delete a message (from REST) */
	SMSCB_E_DELETE,
	/* CBSP peer confirms write */
	SMSCB_E_CBSP_WRITE_ACK,
	SMSCB_E_CBSP_WRITE_NACK,
	/* CBSP peer confirms replace */
	SMSCB_E_CBSP_REPLACE_ACK,
	SMSCB_E_CBSP_REPLACE_NACK,
	/* CBSP peer confirms delete */
	SMSCB_E_CBSP_DELETE_ACK,
	SMSCB_E_CBSP_DELETE_NACK,
	/* CBSP peer confirms status query */
	SMSCB_E_CBSP_STATUS_ACK,
	SMSCB_E_CBSP_STATUS_NACK,
};
