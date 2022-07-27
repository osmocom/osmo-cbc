/* SMSCB Peer FSM: Represents state of one SMSCB for one peer (BSC) */

/* This FSM exists per tuple of (message, [bsc/rnc/mme] peer) */

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

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/fsm.h>

#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/cbsp_link.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/sbcap_msg.h>
#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/smscb_peer_fsm.h>
#include <osmocom/cbc/smscb_message_fsm.h>

const struct value_string smscb_peer_fsm_event_names[] = {
	{ SMSCB_PEER_E_CREATE,			"CREATE" },
	{ SMSCB_PEER_E_REPLACE,			"REPLACE" },
	{ SMSCB_PEER_E_STATUS,			"STATUS" },
	{ SMSCB_PEER_E_DELETE,			"DELETE" },
	{ SMSCB_PEER_E_CBSP_WRITE_ACK,		"CBSP_WRITE_ACK" },
	{ SMSCB_PEER_E_CBSP_WRITE_NACK,		"CBSP_WRITE_NACK" },
	{ SMSCB_PEER_E_CBSP_REPLACE_ACK,	"CBSP_REPLACE_ACK" },
	{ SMSCB_PEER_E_CBSP_REPLACE_NACK,	"CBSP_REPLACE_NACK" },
	{ SMSCB_PEER_E_CBSP_DELETE_ACK,		"CBSP_DELETE_ACK" },
	{ SMSCB_PEER_E_CBSP_DELETE_NACK,	"CBSP_DELETE_NACK" },
	{ SMSCB_PEER_E_CBSP_STATUS_ACK,		"CBSP_STATUS_ACK" },
	{ SMSCB_PEER_E_CBSP_STATUS_NACK,	"CBSP_STATUS_NACK" },
	{ SMSCB_PEER_E_SBCAP_WRITE_ACK,		"SBcAP_WRITE_ACK" },
	{ SMSCB_PEER_E_SBCAP_WRITE_NACK,	"SBcAP_WRITE_NACK" },
	{ SMSCB_PEER_E_SBCAP_DELETE_ACK,	"SBcAP_DELETE_ACK" },
	{ SMSCB_PEER_E_SBCAP_DELETE_NACK,	"SBcAP_DELETE_NACK" },
	{ SMSCB_PEER_E_SBCAP_WRITE_IND,		"SBcAP_WRITE_IND" },
	{ 0, NULL }
};

struct cbc_message_peer *smscb_peer_fsm_alloc(struct cbc_peer *peer, struct cbc_message *cbcmsg)
{
	struct cbc_message_peer *mp;
	struct osmo_fsm_inst *fi;
	struct osmo_fsm *fsm_def;

	switch (peer->proto) {
	case CBC_PEER_PROTO_CBSP:
		fsm_def = &cbsp_smscb_peer_fsm;
		break;
	case CBC_PEER_PROTO_SBcAP:
		fsm_def = &sbcap_smscb_peer_fsm;
		break;
	case CBC_PEER_PROTO_SABP:
	default:
		osmo_panic("smscb_peer FSM not implemented for proto %u", peer->proto);
	}
	fi = osmo_fsm_inst_alloc_child(fsm_def, cbcmsg->fi, SMSCB_MSG_E_CHILD_DIED);
	if (!fi)
		return NULL;
	/* include the peer name in the ID of the child FSM */
	osmo_fsm_inst_update_id_f_sanitize(fi, '_', "%s-%s", cbcmsg->fi->id, peer->name);

	/* allocate and initialize message_peer */
	mp = talloc_zero(fi, struct cbc_message_peer);
	if (!mp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	mp->peer = peer;
	mp->cbcmsg = cbcmsg;
	INIT_LLIST_HEAD(&mp->cell_list);
	INIT_LLIST_HEAD(&mp->fail_list);
	INIT_LLIST_HEAD(&mp->num_compl_list);

	/* link message_peer with its FSM instance */
	fi->priv = mp;
	mp->fi = fi;

	/* link message_peer to message */
	llist_add_tail(&mp->list, &cbcmsg->peers);

	return mp;
}
