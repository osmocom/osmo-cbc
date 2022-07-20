#pragma once

#include <stdint.h>
#include <osmocom/core/fsm.h>

extern struct osmo_fsm sbcap_link_fsm;

enum sbcap_link_event {
	SBcAP_LINK_E_RX_RST_COMPL,	/* reset complete received */
	SBcAP_LINK_E_RX_RST_FAIL,		/* reset failure received */
	SBcAP_LINK_E_RX_KA_COMPL,		/* keep-alive complete received */
	SBcAP_LINK_E_RX_RESTART,		/* restart received */
	SBcAP_LINK_E_CMD_RESET,		/* RESET command from CBC */
	SBcAP_LINK_E_CMD_CLOSE,		/* CLOSE command from CBC */
};
