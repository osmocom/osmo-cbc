#pragma once

#include <stdint.h>
#include <osmocom/core/fsm.h>

extern struct osmo_fsm cbsp_link_fsm;

enum cbsp_link_event {
	CBSP_LINK_E_RX_RST_COMPL,	/* reset complete received */
	CBSP_LINK_E_RX_RST_FAIL,		/* reset failure received */
	CBSP_LINK_E_RX_KA_COMPL,		/* keep-alive complete received */
	CBSP_LINK_E_RX_RESTART,		/* restart received */
	CBSP_LINK_E_CMD_RESET,		/* RESET command from CBC */
	CBSP_LINK_E_CMD_CLOSE,		/* CLOSE command from CBC */
};
