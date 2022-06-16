/* Osmocom CBC (Cell Broacast Centre) */

/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <string.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/cbsp_server.h>

const struct value_string cbc_peer_proto_name[] = {
	{ CBC_PEER_PROTO_CBSP, "CBSP" },
	{ CBC_PEER_PROTO_SABP, "SABP" },
	{ CBC_PEER_PROTO_SBcAP, "SBc-AP" },
	{ 0, NULL }
};

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

struct cbc_message_peer *cbc_message_peer_get(struct cbc_message *cbcmsg, struct cbc_peer *peer)
{
	struct cbc_message_peer *mp;

	llist_for_each_entry(mp, &cbcmsg->peers, list) {
		if (mp->peer == peer)
			return mp;
	}
	return NULL;
}

#if 0
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
#endif


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
		unsigned int i;
		for (i = 0; i < peer->num_remote_host; i++) {
			if (peer->proto != proto)
				continue;
			if (!strcasecmp(remote_host, peer->remote_host[i])) {
				if (peer->remote_port == -1)
					return peer;
				else if (remote_port == peer->remote_port)
					return peer;
			}
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
