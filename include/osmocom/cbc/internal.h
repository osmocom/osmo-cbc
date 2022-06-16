#pragma once

#include <stdint.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/vty/command.h>

#include <osmocom/cbc/cbc_data.h>

enum {
	DCBSP,
	DSBcAP,
	DREST,
};

extern struct osmo_fsm cbsp_server_fsm;

enum cbsp_server_event {
	CBSP_SRV_E_RX_RST_COMPL,	/* reset complete received */
	CBSP_SRV_E_RX_RST_FAIL,		/* reset failure received */
	CBSP_SRV_E_RX_KA_COMPL,		/* keep-alive complete received */
	CBSP_SRV_E_RX_RESTART,		/* restart received */
	CBSP_SRV_E_CMD_RESET,		/* RESET command from CBC */
	CBSP_SRV_E_CMD_CLOSE,		/* CLOSE command from CBC */
};

extern struct osmo_fsm sbcap_server_fsm;

enum sbcap_server_event {
	SBcAP_SRV_E_RX_RST_COMPL,	/* reset complete received */
	SBcAP_SRV_E_RX_RST_FAIL,		/* reset failure received */
	SBcAP_SRV_E_RX_KA_COMPL,		/* keep-alive complete received */
	SBcAP_SRV_E_RX_RESTART,		/* restart received */
	SBcAP_SRV_E_CMD_RESET,		/* RESET command from CBC */
	SBcAP_SRV_E_CMD_CLOSE,		/* CLOSE command from CBC */
};


/* rest_api.c */
int rest_api_init(void *ctx, const char *bind_addr, uint16_t port);
void rest_api_fin(void);

/* cbc_vty.c */
enum cbc_vty_node {
	CBC_NODE = _LAST_OSMOVTY_NODE + 1,
	PEER_NODE,
	CBSP_NODE,
	SBcAP_NODE,
	ECBE_NODE,
};
void cbc_vty_init(void);

/* message_handling.c */
struct cbc_message *cbc_message_alloc(void *ctx, const struct cbc_message *cbcmsg);
int cbc_message_new(const struct cbc_message *cbcmsg, struct rest_it_op *op);
void cbc_message_delete(struct cbc_message *cbcmsg, struct rest_it_op *op);
struct cbc_message *cbc_message_by_id(uint16_t message_id);
int peer_new_cbc_message(struct cbc_peer *peer, struct cbc_message *cbcmsg);

/* rest_it_op.c */
void rest2main_read_cb(struct osmo_it_q *q, struct llist_head *item);


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
	/* SBc-AP peer confirms write */
	SMSCB_E_SBCAP_WRITE_ACK,
	SMSCB_E_SBCAP_WRITE_NACK,
	/* SBc-AP peer confirms delete */
	SMSCB_E_SBCAP_DELETE_ACK,
	SMSCB_E_SBCAP_DELETE_NACK,
};

enum smscb_fsm_state {
	/* initial state after creation  */
	SMSCB_S_INIT,
	/* peer (BSC) have been notified of this SMSCB; we're waiting for ACK */
	SMSCB_S_WAIT_WRITE_ACK,
	/* peer (BSC) have confirmed it, message is active */
	SMSCB_S_ACTIVE,
	/* we have modified the message and sent REPLACE to peer; we're waiting for ACK */
	SMSCB_S_WAIT_REPLACE_ACK,
	/* we have modified the message and sent REPLACE to peer; we're waiting for ACK */
	SMSCB_S_WAIT_STATUS_ACK,
	/* we have deleted the message and sent KILL to peer; wait for ACK */
	SMSCB_S_WAIT_DELETE_ACK,
	SMSCB_S_DELETED,
};

enum smscb_p_fsm_timer {
	T_WAIT_WRITE_ACK,
	T_WAIT_REPLACE_ACK,
	T_WAIT_STATUS_ACK,
	T_WAIT_DELETE_ACK,
};

extern const struct value_string smscb_fsm_event_names[];
