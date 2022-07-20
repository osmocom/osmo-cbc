#pragma once

enum cbc_vty_node {
	CBC_NODE = _LAST_OSMOVTY_NODE + 1,
	PEER_NODE,
	CBSP_NODE,
	SBcAP_NODE,
	ECBE_NODE,
};
void cbc_vty_init(void);
