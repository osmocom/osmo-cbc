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
#include <osmocom/core/logging.h>

#include <osmocom/cbc/cbsp_msg.h>
#include <osmocom/cbc/cbsp_link.h>
#include <osmocom/cbc/sbcap_msg.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/rest_it_op.h>
#include <osmocom/cbc/smscb_message_fsm.h>

/* determine if peer is within scope of cbc_msg */
static bool is_peer_in_scope(const struct cbc_peer *peer, const struct cbc_message *cbcmsg)
{
	switch (cbcmsg->scope) {
	case CBC_MSG_SCOPE_PLMN:
		return true;
	/* FIXME: differnt scopes */
	default:
		OSMO_ASSERT(0);
	}
}

/* send given new message to given peer */
int peer_new_cbc_message(struct cbc_peer *peer, struct cbc_message *cbcmsg)
{
	struct osmo_cbsp_decoded *cbsp;
	SBcAP_SBC_AP_PDU_t *sbcap;

	switch (peer->proto) {
	case CBC_PEER_PROTO_CBSP:
		/* skip peers without any current CBSP connection */
		if (!peer->link.cbsp) {
			LOGP(DCBSP, LOGL_NOTICE, "[%s] Tx CBSP: not connected\n",
			     peer->name);
			return -ENOTCONN;
		}
		if (!(cbsp = cbcmsg_to_cbsp(peer, cbcmsg))) {
			LOGP(DCBSP, LOGL_ERROR, "[%s] Tx CBSP: msg gen failed\n",
			     peer->name);
			return -EINVAL;
		}
		cbc_cbsp_link_tx(peer->link.cbsp, cbsp);
		break;
	case CBC_PEER_PROTO_SBcAP:
		/* skip peers without any current SBc-AP connection */
		if (!peer->link.sbcap) {
			LOGP(DSBcAP, LOGL_NOTICE, "[%s] Tx SBc-AP: not connected\n",
			     peer->name);
			return -ENOTCONN;
		}
		if (!(sbcap = cbcmsg_to_sbcap(peer, cbcmsg))) {
			LOGP(DSBcAP, LOGL_ERROR, "[%s] Tx SBc-AP: msg gen failed\n",
			     peer->name);
			return -EINVAL;
		}
		cbc_sbcap_link_tx(peer->link.sbcap, sbcap);
		break;
	case CBC_PEER_PROTO_SABP:
		LOGP(DLGLOBAL, LOGL_ERROR, "Sending message to peer proto %s not implemented!\n",
		     get_value_string(cbc_peer_proto_name, peer->proto));
		return -1;
	default:
		OSMO_ASSERT(0);
	}

	return 0;
}

/* receive a new CBC message from the user (REST). Allocates new memory,
 * a FSM, copies data from 'orig', routes to all peers and starts FSMs.
 * Once the operation is complete (success, error, timeout) we must
 * notify osmo_it_q of the completion */
int cbc_message_new(const struct cbc_message *orig, struct rest_it_op *op)
{
	struct cbc_message *cbcmsg = cbc_message_alloc(g_cbc, orig);
	struct cbc_peer *peer;

	if (!cbcmsg) {
		rest_it_op_set_http_result(op, 409, "Could not allocate");
		rest_it_op_complete(op);
		return -ENOMEM;
	}

	OSMO_ASSERT(llist_empty(&cbcmsg->peers));

	/* iterate over all peers */
	llist_for_each_entry(peer, &g_cbc->peers, list) {
		struct cbc_message_peer *mp;

		if (!is_peer_in_scope(peer, cbcmsg))
			continue;

		/* allocate new cbc_mesage_peer + related FSM */
		mp = smscb_peer_fsm_alloc(peer, cbcmsg);
		if (!mp) {
			LOGP(DCBSP, LOGL_ERROR, "Cannot allocate cbc_message_peer\n");
			continue;
		}
	}

	/* kick off the state machine[s] */
	if (osmo_fsm_inst_dispatch(cbcmsg->fi, SMSCB_E_CREATE, op) < 0) {
		rest_it_op_set_http_result(op, 500, "Illegal FSM event");
		rest_it_op_complete(op);
	}

	/* we continue in the FSM after the WRITE_ACK event was received */

	return 0;
}

void cbc_message_delete(struct cbc_message *cbcmsg, struct rest_it_op *op)
{
	if (osmo_fsm_inst_dispatch(cbcmsg->fi, SMSCB_E_DELETE, op) < 0) {
		rest_it_op_set_http_result(op, 500, "Illegal FSM event");
		rest_it_op_complete(op);
	}
	/* we continue in the FSM after the DELETE_ACK event was received */
}

struct cbc_message *cbc_message_by_id(uint16_t message_id)
{
	struct cbc_message *cbc_msg;
	llist_for_each_entry(cbc_msg, &g_cbc->messages, list) {
		if (cbc_msg->msg.message_id == message_id)
			return cbc_msg;
	}
	return NULL;
}

struct cbc_message *cbc_message_expired_by_id(uint16_t message_id)
{
	struct cbc_message *cbc_msg;
	llist_for_each_entry(cbc_msg, &g_cbc->expired_messages, list) {
		if (cbc_msg->msg.message_id == message_id)
			return cbc_msg;
	}
	return NULL;
}

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
