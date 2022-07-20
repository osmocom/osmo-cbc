#pragma once

#include <stdint.h>
#include <osmocom/core/fsm.h>

extern struct osmo_fsm cbsp_server_fsm;

enum cbsp_server_event {
	CBSP_SRV_E_RX_RST_COMPL,	/* reset complete received */
	CBSP_SRV_E_RX_RST_FAIL,		/* reset failure received */
	CBSP_SRV_E_RX_KA_COMPL,		/* keep-alive complete received */
	CBSP_SRV_E_RX_RESTART,		/* restart received */
	CBSP_SRV_E_CMD_RESET,		/* RESET command from CBC */
	CBSP_SRV_E_CMD_CLOSE,		/* CLOSE command from CBC */
};
