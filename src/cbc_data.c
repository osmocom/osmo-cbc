#include <string.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "cbc_data.h"
#include "cbsp_server.h"

/* remove a peer from the message */
int cbc_message_del_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer)
{
	struct cbc_message_peer *mp, *mp2;
	unsigned int i = 0;

	llist_for_each_entry_safe(mp, mp2, &cbcmsg->peers, list) {
		if (mp->peer == peer) {
			llist_del(&mp->list);
			talloc_free(mp);
			i++;
		}
	}
	OSMO_ASSERT(i == 0 || i == 1);
	return i;
}

/* add a new peer to the message */
int cbc_message_add_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer)
{
	struct cbc_message_peer *mp = talloc_zero(cbcmsg, struct cbc_message_peer);
	if (mp)
		return -ENOMEM;

	mp->peer = peer;
	llist_add_tail(&mp->list, &cbcmsg->peers);
	return 0;
}


/* look-up of cbc_peer by name */
struct cbc_peer *cbc_peer_by_name(const char *name)
{
	struct cbc_peer *peer;

	llist_for_each_entry(peer, &g_cbc->peers, list) {
		if (peer->name && !strcmp(name, peer->name))
			return peer;
	}
	return NULL;
}

/* look-up of cbc_peer by tuple of (remote host, protocol) */
struct cbc_peer *cbc_peer_by_addr_proto(const char *remote_host, uint16_t remote_port,
					enum cbc_peer_protocol proto)
{
	struct cbc_peer *peer;

	llist_for_each_entry(peer, &g_cbc->peers, list) {
		if (!strcasecmp(remote_host, peer->remote_host)) {
			if (peer->remote_port == -1)
				return peer;
			else if (remote_port == peer->remote_port)
				return peer;
		}
	}
	return NULL;
}

/* create a new cbc_peer */
struct cbc_peer *cbc_peer_create(const char *name, enum cbc_peer_protocol proto)
{
	struct cbc_peer *peer;
	if (name && cbc_peer_by_name(name))
		return NULL;

	peer = talloc_zero(g_cbc, struct cbc_peer);
	if (!peer)
		return NULL;

	peer->proto = proto;
	peer->name = talloc_strdup(peer, name);
	llist_add_tail(&peer->list, &g_cbc->peers);

	return peer;
}

/* remove a cbc_peer */
void cbc_peer_remove(struct cbc_peer *peer)
{
	struct cbc_message *cbcmsg;

	/* close any existing client connection */
	switch (peer->proto) {
	case CBC_PEER_PROTO_CBSP:
		if (peer->client.cbsp)
			cbsp_cbc_client_close(peer->client.cbsp);
		break;
	default:
		OSMO_ASSERT(0);
	}

	/* iterate over messages; remove client from all message_peers */
	llist_for_each_entry(cbcmsg, &g_cbc->messages, list) {
		cbc_message_del_peer(cbcmsg, peer);
	}

	llist_del(&peer->list);
	talloc_free(peer);
}
