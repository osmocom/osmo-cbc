#pragma once

#include <stdint.h>
#include <osmocom/core/fsm.h>

extern struct osmo_fsm sbcap_server_fsm;

enum sbcap_server_event {
	SBcAP_SRV_E_RX_RST_COMPL,	/* reset complete received */
	SBcAP_SRV_E_RX_RST_FAIL,		/* reset failure received */
	SBcAP_SRV_E_RX_KA_COMPL,		/* keep-alive complete received */
	SBcAP_SRV_E_RX_RESTART,		/* restart received */
	SBcAP_SRV_E_CMD_RESET,		/* RESET command from CBC */
	SBcAP_SRV_E_CMD_CLOSE,		/* CLOSE command from CBC */
};
