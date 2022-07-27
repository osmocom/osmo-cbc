#pragma once

#include <stdint.h>
#include <osmocom/core/fsm.h>

enum smscb_peer_fsm_event {
	/* create a message (from REST) */
	SMSCB_PEER_E_CREATE,
	/* replace a message (from REST) */
	SMSCB_PEER_E_REPLACE,
	/* get status of a message (from REST) */
	SMSCB_PEER_E_STATUS,
	/* delete a message (from REST) */
	SMSCB_PEER_E_DELETE,
	/* CBSP peer confirms write */
	SMSCB_PEER_E_CBSP_WRITE_ACK,
	SMSCB_PEER_E_CBSP_WRITE_NACK,
	/* CBSP peer confirms replace */
	SMSCB_PEER_E_CBSP_REPLACE_ACK,
	SMSCB_PEER_E_CBSP_REPLACE_NACK,
	/* CBSP peer confirms delete */
	SMSCB_PEER_E_CBSP_DELETE_ACK,
	SMSCB_PEER_E_CBSP_DELETE_NACK,
	/* CBSP peer confirms status query */
	SMSCB_PEER_E_CBSP_STATUS_ACK,
	SMSCB_PEER_E_CBSP_STATUS_NACK,
	/* SBc-AP peer confirms write */
	SMSCB_PEER_E_SBCAP_WRITE_ACK,
	SMSCB_PEER_E_SBCAP_WRITE_NACK,
	/* SBc-AP peer confirms delete */
	SMSCB_PEER_E_SBCAP_DELETE_ACK,
	SMSCB_PEER_E_SBCAP_DELETE_NACK,
	/* SBc-AP peer sends Write Replace Warning Indication to us */
	SMSCB_PEER_E_SBCAP_WRITE_IND,
};

extern const struct value_string smscb_peer_fsm_event_names[];

extern struct osmo_fsm cbsp_smscb_peer_fsm;
extern struct osmo_fsm sbcap_smscb_peer_fsm;
