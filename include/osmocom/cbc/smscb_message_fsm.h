#pragma once

#include <stdint.h>
#include <osmocom/core/fsm.h>

enum smscb_message_fsm_event {
	SMSCB_MSG_E_CHILD_DIED,
	/* create a message (from REST) */
	SMSCB_MSG_E_CREATE,
	/* replace a message (from REST) */
	SMSCB_MSG_E_REPLACE,
	/* get status of a message (from REST) */
	SMSCB_MSG_E_STATUS,
	/* delete a message (from REST) */
	SMSCB_MSG_E_DELETE,
	/* peer confirms write */
	SMSCB_MSG_E_WRITE_ACK,
	SMSCB_MSG_E_WRITE_NACK,
	/* peer confirms replace */
	SMSCB_MSG_E_REPLACE_ACK,
	SMSCB_MSG_E_REPLACE_NACK,
	/* peer confirms delete */
	SMSCB_MSG_E_DELETE_ACK,
	SMSCB_MSG_E_DELETE_NACK,
	/* peer confirms status query */
	SMSCB_MSG_E_STATUS_ACK,
	SMSCB_MSG_E_STATUS_NACK
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

extern const struct value_string smscb_message_fsm_event_names[];
