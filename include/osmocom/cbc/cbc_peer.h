#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/linuxlist.h>

struct osmo_cbsp_cbc_client;
struct osmo_sabp_cbc_client;
struct osmo_sbcap_cbc_client;

#define CBC_MAX_REM_ADDRS 8

/*********************************************************************************
 * CBC Peer
 *********************************************************************************/

enum cbc_peer_protocol {
	CBC_PEER_PROTO_CBSP,
	CBC_PEER_PROTO_SABP,
	CBC_PEER_PROTO_SBcAP
};

struct cbc_peer {
	struct llist_head list;		/* linked to cbc.peers */
	const char *name;

	char *remote_host[CBC_MAX_REM_ADDRS];	/* remote IP address in string format */
	unsigned int num_remote_host;	/* number of addresses present in remote_host */
	int remote_port;		/* remote port number or -1 for random */
	bool unknown_dynamic_peer;	/* dynamic/unknown peer; not saved in VTY */

	enum cbc_peer_protocol proto;
	union {
		struct osmo_cbsp_cbc_client *cbsp;
		struct osmo_sabp_cbc_client *sabp;
		struct osmo_sbcap_cbc_client *sbcap;
	} client;
};

extern const struct value_string cbc_peer_proto_name[];

struct cbc_peer *cbc_peer_create(const char *name, enum cbc_peer_protocol proto);
void cbc_peer_remove(struct cbc_peer *peer);

struct cbc_peer *cbc_peer_by_name(const char *name);
struct cbc_peer *cbc_peer_by_addr_proto(const char *remote_host, uint16_t remote_port,
					enum cbc_peer_protocol proto);