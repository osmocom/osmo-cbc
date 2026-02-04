/* Osmocom CBC (Cell Broadcast Centre) */

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

#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/cbsp_link.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/debug.h>

const struct value_string cbc_peer_proto_name[] = {
	{ CBC_PEER_PROTO_CBSP, "CBSP" },
	{ CBC_PEER_PROTO_SABP, "SABP" },
	{ CBC_PEER_PROTO_SBcAP, "SBc-AP" },
	{ 0, NULL }
};


const struct value_string cbc_peer_link_mode_names[] = {
	{ CBC_PEER_LINK_MODE_DISABLED, "disabled" },
	{ CBC_PEER_LINK_MODE_SERVER, "server" },
	{ CBC_PEER_LINK_MODE_CLIENT, "client" },
	{}
};

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

	/* close any existing peer link connection */
	switch (peer->proto) {
	case CBC_PEER_PROTO_CBSP:
		if (peer->link.cbsp)
			cbc_cbsp_link_close(peer->link.cbsp);
		break;
	case CBC_PEER_PROTO_SBcAP:
		if (peer->link.sbcap)
			cbc_sbcap_link_close(peer->link.sbcap);
		break;
	case CBC_PEER_PROTO_SABP:
	default:
		OSMO_ASSERT(0);
	}

	/* iterate over messages; remove peer from all message_peers */
	llist_for_each_entry(cbcmsg, &g_cbc->messages, list) {
		cbc_message_del_peer(cbcmsg, peer);
	}

	llist_del(&peer->list);
	talloc_free(peer);
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

static int cbc_peer_apply_cfg_chg_cbsp(struct cbc_peer *peer)
{
	struct cbc_cbsp_link *link = peer->link.cbsp;
	int rc = 0;

	switch (peer->link_mode) {
	case CBC_PEER_LINK_MODE_DISABLED:
		if (link) {
			LOGPCC(link, LOGL_NOTICE,
			       "link mode changed to 'disabled', closing active link\n");
			cbc_cbsp_link_close(link);
		}
		/* Nothing to be done, cbc_cbsp_mgr->srv_link will refuse
		 * accepting() disabled peers. */
		OSMO_ASSERT(!peer->link.cbsp);
		break;
	case CBC_PEER_LINK_MODE_SERVER:
		if (link && link->is_client) {
			LOGPCC(link, LOGL_NOTICE,
			       "link mode changed 'client' -> 'server', closing active link\n");
			cbc_cbsp_link_close(link);
		}
		/* Nothing to be done, cbc_cbsp_mgr->srv_link will accept() and
		 * recreate the link */
		OSMO_ASSERT(!peer->link.cbsp);
		break;
	case CBC_PEER_LINK_MODE_CLIENT:
		if (link) {
			if (link->is_client) {
				/* nothing to be done, cli link already created */
				break;
			}
			LOGPCC(link, LOGL_NOTICE,
			       "link mode changed 'server' -> 'client', closing active link\n");
			cbc_cbsp_link_close(link);
		}
		OSMO_ASSERT(!peer->link.cbsp);
		link = cbc_cbsp_link_alloc(g_cbc->cbsp.mgr, peer);
		peer->link.cbsp = link;
		rc = cbc_cbsp_link_open_cli(link);
		break;
	}
	return rc;
}

static int cbc_peer_apply_cfg_chg_sbcap(struct cbc_peer *peer)
{
	struct cbc_sbcap_link *link = peer->link.sbcap;
	int rc = 0;

	switch (peer->link_mode) {
	case CBC_PEER_LINK_MODE_DISABLED:
		if (link) {
			LOGPSBCAPC(link, LOGL_NOTICE,
				   "link mode changed to 'disabled', closing active link\n");
			cbc_sbcap_link_close(link);
		}
		/* Nothing to be done, cbc_sbcap_mgr->srv_link will refuse
		 * accepting() disabled peers. */
		OSMO_ASSERT(!peer->link.sbcap);
		break;
	case CBC_PEER_LINK_MODE_SERVER:
		if (link && link->is_client) {
			LOGPSBCAPC(link, LOGL_NOTICE,
				   "link mode changed 'client' -> 'server', closing active link\n");
			cbc_sbcap_link_close(link);
		}
		/* Nothing to be done, cbc_sbcap_mgr->srv_link will accept() and
		 * recreate the link */
		OSMO_ASSERT(!peer->link.sbcap);
		break;
	case CBC_PEER_LINK_MODE_CLIENT:
		if (link) {
			if (link->is_client) {
				/* nothing to be done, cli link already created */
				break;
			}
			LOGPSBCAPC(link, LOGL_NOTICE,
				   "link mode changed 'server' -> 'client', closing active link\n");
			cbc_sbcap_link_close(link);
		}
		OSMO_ASSERT(!peer->link.sbcap);
		link = cbc_sbcap_link_alloc(g_cbc->sbcap.mgr, peer);
		peer->link.sbcap = link;
		rc = cbc_sbcap_link_open_cli(link);
		break;
	}
	return rc;
}

int cbc_peer_apply_cfg_chg(struct cbc_peer *peer)
{
	int rc = -ENOTSUP;

	switch (peer->proto) {
	case CBC_PEER_PROTO_CBSP:
		rc = cbc_peer_apply_cfg_chg_cbsp(peer);
		break;
	case CBC_PEER_PROTO_SBcAP:
		rc = cbc_peer_apply_cfg_chg_sbcap(peer);
		break;
	case CBC_PEER_PROTO_SABP:
		break;
	}
	return rc;
}
