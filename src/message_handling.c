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


#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/cbsp.h>

#include "cbc_data.h"
#include "cbsp_server.h"
#include "internal.h"

/* convert cbc_message to osmo_cbsp_cell_list */
static int cbcmsg_to_cbsp_cell_list(const void *ctx, struct osmo_cbsp_cell_list *list,
				    const struct cbc_message *cbcmsg)
{
	struct osmo_cbsp_cell_ent *ent;

	switch (cbcmsg->scope) {
	case CBC_MSG_SCOPE_PLMN:
		list->id_discr = CELL_IDENT_BSS;
		ent = talloc_zero(ctx, struct osmo_cbsp_cell_ent);
		if (!ent)
			return -ENOMEM;
		//ent->cell_id = ?
		llist_add_tail(&ent->list, &list->list);
		return 0;
	default:
		OSMO_ASSERT(0);
	}
}

/* generate a CBSP WRITE-REPLACE from our internal representation */
struct osmo_cbsp_decoded *cbcmsg_to_cbsp(void *ctx, const struct cbc_message *cbcmsg)
{
	struct osmo_cbsp_write_replace *wrepl;
	const struct smscb_message *smscb = &cbcmsg->msg;
	struct osmo_cbsp_decoded *cbsp = osmo_cbsp_decoded_alloc(ctx, CBSP_MSGT_WRITE_REPLACE);
	unsigned int i;
	int rc;

	if (!cbsp)
		return NULL;
	wrepl = &cbsp->u.write_replace;

	wrepl->msg_id = smscb->message_id;
	wrepl->new_serial_nr = smscb->serial_nr;
	/* FIXME: old? */
	/* Cell list */
	rc = cbcmsg_to_cbsp_cell_list(smscb, &wrepl->cell_list, cbcmsg);
	if (rc < 0) {
		talloc_free(cbsp);
		return NULL;
	}
	if (!smscb->is_etws)
		wrepl->is_cbs = true;
	if (wrepl->is_cbs) {
		if (cbcmsg->extended_cbch)
			wrepl->u.cbs.channel_ind = CBSP_CHAN_IND_EXTENDED;
		else
			wrepl->u.cbs.channel_ind = CBSP_CHAN_IND_BASIC;
		wrepl->u.cbs.category = cbcmsg->priority;
		wrepl->u.cbs.rep_period = cbcmsg->rep_period;
		wrepl->u.cbs.num_bcast_req = cbcmsg->num_bcast;
		wrepl->u.cbs.dcs = smscb->cbs.dcs;
		for (i = 0; i < smscb->cbs.num_pages; i++) {
			struct osmo_cbsp_content *ce = talloc_zero(cbsp, struct osmo_cbsp_content);
			// FIXME: ce->user_len =
			memcpy(ce->data, smscb->cbs.data[i], SMSCB_RAW_PAGE_LEN);
			llist_add_tail(&ce->list, &wrepl->u.cbs.msg_content);
		}
	} else {
		/* FIXME */
		talloc_free(cbsp);
		return NULL;
	}
	return cbsp;
}

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

	switch (peer->proto) {
	case CBC_PEER_PROTO_CBSP:
		cbsp = cbcmsg_to_cbsp(peer, cbcmsg);
		cbsp_cbc_client_tx(peer->client.cbsp, cbsp);
		break;
	default:
		OSMO_ASSERT(0);
	}

	return 0;
}

/* receive a new CBC message from the user (REST). Allocates new memory,
 * a FSM, copies data from 'orig', routes to all peers and starts FSMs */
int cbc_message_new(const struct cbc_message *orig)
{
	struct cbc_message *cbcmsg = cbc_message_alloc(g_cbc, orig);
	struct cbc_peer *peer;

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
	osmo_fsm_inst_dispatch(cbcmsg->fi, SMSCB_E_CREATE, NULL);

	return 0;
}

void cbc_message_delete(struct cbc_message *cbcmsg)
{
	osmo_fsm_inst_dispatch(cbcmsg->fi, SMSCB_E_DELETE, NULL);
	/* TODO: how to handle completion */
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
