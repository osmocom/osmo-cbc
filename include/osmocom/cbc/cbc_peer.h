#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/linuxlist.h>

struct cbc_cbsp_link;
struct cbc_sabp_link;
struct cbc_sbcap_link;

#define CBC_MAX_REM_ADDRS 8

/*********************************************************************************
 * CBC Peer
 *********************************************************************************/

enum cbc_peer_protocol {
	CBC_PEER_PROTO_CBSP,
	CBC_PEER_PROTO_SABP,
	CBC_PEER_PROTO_SBcAP
};

enum cbc_peer_link_mode {
	CBC_PEER_LINK_MODE_DISABLED = 0,
	CBC_PEER_LINK_MODE_SERVER,
	CBC_PEER_LINK_MODE_CLIENT,
};

extern const struct value_string cbc_peer_link_mode_names[];
static inline const char *cbc_peer_link_mode_name(enum cbc_peer_link_mode val)
{ return get_value_string(cbc_peer_link_mode_names, val); }

struct cbc_peer {
	struct llist_head list;		/* linked to cbc.peers */
	const char *name;

	char *remote_host[CBC_MAX_REM_ADDRS];	/* remote IP address in string format */
	unsigned int num_remote_host;	/* number of addresses present in remote_host */
	int remote_port;		/* remote port number or -1 for random */
	bool unknown_dynamic_peer;	/* dynamic/unknown peer; not saved in VTY */

	enum cbc_peer_protocol proto;
	union {
		struct cbc_cbsp_link *cbsp;
		struct cbc_sabp_link *sabp;
		struct cbc_sbcap_link *sbcap;
	} link;
	enum cbc_peer_link_mode link_mode;
};

extern const struct value_string cbc_peer_proto_name[];

struct cbc_peer *cbc_peer_create(const char *name, enum cbc_peer_protocol proto);
void cbc_peer_remove(struct cbc_peer *peer);

struct cbc_peer *cbc_peer_by_name(const char *name);
struct cbc_peer *cbc_peer_by_addr_proto(const char *remote_host, uint16_t remote_port,
					enum cbc_peer_protocol proto);
int cbc_peer_apply_cfg_chg(struct cbc_peer *peer);
