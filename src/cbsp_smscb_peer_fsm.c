/* SMSCB Peer FSM: Represents state of one SMSCB for one peer (BSC) */

/* This FSM exists per tuple of (message, bsc peer) */

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

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/cbsp.h>

#include <osmocom/sbcap/sbcap_common.h>

#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/cbsp_link.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/sbcap_msg.h>
#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/smscb_peer_fsm.h>
#include <osmocom/cbc/smscb_message_fsm.h>

#define S(x)	(1 << (x))

/***********************************************************************
 * Helper functions
 ***********************************************************************/

/* covert TS 08.08 Cell Identity value to CBC internal type */
static enum cbc_cell_id_type cci_discr_from_cell_id(enum CELL_IDENT id_discr)
{
	switch (id_discr) {
	case CELL_IDENT_NO_CELL:
		return CBC_CELL_ID_NONE;
	case CELL_IDENT_WHOLE_GLOBAL:
		return CBC_CELL_ID_CGI;
	case CELL_IDENT_LAC_AND_CI:
		return CBC_CELL_ID_LAC_CI;
	case CELL_IDENT_CI:
		return CBC_CELL_ID_CI;
	case CELL_IDENT_LAI:
		return CBC_CELL_ID_LAI;
	case CELL_IDENT_LAC:
		return CBC_CELL_ID_LAC;
	case CELL_IDENT_BSS:
		return CBC_CELL_ID_BSS;
	default:
		return -1;
	}
}

/* covert CBC internal type to TS 08.08 Cell Identity */
static enum CELL_IDENT cell_id_from_ccid_discr(enum cbc_cell_id_type in)
{
	switch (in) {
	case CBC_CELL_ID_NONE:
		return CELL_IDENT_NO_CELL;
	case CBC_CELL_ID_CGI:
		return CELL_IDENT_WHOLE_GLOBAL;
	case CBC_CELL_ID_LAC_CI:
		return CELL_IDENT_LAC_AND_CI;
	case CBC_CELL_ID_CI:
		return CELL_IDENT_CI;
	case CBC_CELL_ID_LAI:
		return CELL_IDENT_LAI;
	case CBC_CELL_ID_LAC:
		return CELL_IDENT_LAC;
	case CBC_CELL_ID_BSS:
		return CELL_IDENT_BSS;
	default:
		return -1;
	}
}

/* convert TS 08.08 Cell Identifier Union to CBC internal type */
static void cci_from_cbsp(struct cbc_cell_id *cci, enum CELL_IDENT id_discr,
			  const union gsm0808_cell_id_u *u)
{
	cci->id_discr = cci_discr_from_cell_id(id_discr);

	switch (id_discr) {
	case CELL_IDENT_NO_CELL:
		break;
	case CELL_IDENT_WHOLE_GLOBAL:
		cci->u.cgi = u->global;
		break;
	case CELL_IDENT_LAC_AND_CI:
		cci->u.lac_and_ci = u->lac_and_ci;
		break;
	case CELL_IDENT_CI:
		cci->u.ci = u->ci;
		break;
	case CELL_IDENT_LAI:
		cci->u.lai = u->lai_and_lac;
		break;
	case CELL_IDENT_LAC:
		cci->u.lac = u->lac;
		break;
	case CELL_IDENT_BSS:
		break;
	default:
		break;
	}
}

/* convert TS 08.08 Cell Identifier Union to CBC internal type */
static void cbsp_from_cci(union gsm0808_cell_id_u *u, const struct cbc_cell_id *cci)
{
	switch (cci->id_discr) {
	case CBC_CELL_ID_NONE:
		break;
	case CBC_CELL_ID_CGI:
		u->global = cci->u.cgi;
		printf("u->gobal: %s\n", osmo_hexdump((uint8_t *) &u->global, sizeof(u->global)));
		break;
	case CBC_CELL_ID_LAC_CI:
		u->lac_and_ci = cci->u.lac_and_ci;
		break;
	case CBC_CELL_ID_CI:
		u->ci = cci->u.ci;
		break;
	case CBC_CELL_ID_LAI:
		u->lai_and_lac = cci->u.lai;
		break;
	case CBC_CELL_ID_LAC:
		u->lac = cci->u.lac;
		break;
	case CBC_CELL_ID_BSS:
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* read a single osmo_cbsp_num_compl_ent and add it to cbc_message_peer */
static void cci_from_cbsp_compl_ent(struct cbc_message_peer *mp,
				    struct osmo_cbsp_num_compl_ent *ce, enum CELL_IDENT id_discr)
{
	struct cbc_cell_id *cci;

	cci = NULL; // FIXME: lookup
	if (!cci) {
		cci = talloc_zero(mp, struct cbc_cell_id);
		if (!cci)
			return;
		llist_add_tail(&cci->list, &mp->num_compl_list);
	}
	cci_from_cbsp(cci, id_discr, &ce->cell_id);
	cci->num_compl.num_compl += ce->num_compl;
	cci->num_compl.num_bcast_info += ce->num_bcast_info;
}
static void msg_peer_append_cbsp_compl(struct cbc_message_peer *mp,
					struct osmo_cbsp_num_compl_list *nclist)
{
	struct osmo_cbsp_num_compl_ent *ce;

	llist_for_each_entry(ce, &nclist->list, list)
		cci_from_cbsp_compl_ent(mp, ce, nclist->id_discr);
}

/* read a single osmo_cbsp_cell_ent and add it to cbc_message_peer */
static void cci_from_cbsp_cell_ent(struct cbc_message_peer *mp,
				   struct osmo_cbsp_cell_ent *ce, enum CELL_IDENT id_discr)
{
	struct cbc_cell_id *cci;

	cci = NULL; // FIXME: lookup
	if (!cci) {
		cci = talloc_zero(mp, struct cbc_cell_id);
		if (!cci)
			return;
		llist_add_tail(&cci->list, &mp->cell_list);
	}
	cci_from_cbsp(cci, id_discr, &ce->cell_id);
}
static void msg_peer_append_cbsp_cell(struct cbc_message_peer *mp,
					struct osmo_cbsp_cell_list *clist)
{
	struct osmo_cbsp_cell_ent *ce;

	llist_for_each_entry(ce, &clist->list, list)
		cci_from_cbsp_cell_ent(mp, ce, clist->id_discr);
}

/* read a single osmo_cbsp_fail_ent and add it to cbc_message_peer */
static void cci_from_cbsp_fail_ent(struct cbc_message_peer *mp,
				   struct osmo_cbsp_fail_ent *fe)
{
	struct cbc_cell_id *cci;
	cci = NULL; // lookup */
	if (!cci) {
		cci = talloc_zero(mp, struct cbc_cell_id);
		if (!cci)
			return;
		llist_add_tail(&cci->list, &mp->fail_list);
	}
	cci->id_discr = cci_discr_from_cell_id(fe->id_discr);
	cci->fail.cause = fe->cause;
}
static void msg_peer_append_cbsp_fail(struct cbc_message_peer *mp, struct llist_head *flist)
{
	struct osmo_cbsp_fail_ent *fe;

	llist_for_each_entry(fe, flist, list)
		cci_from_cbsp_fail_ent(mp, fe);
}

/* append all cells from cbc_message_peer to given CBSP cell_list */
static void cbsp_append_cell_list(struct osmo_cbsp_cell_list *out, void *ctx,
				  const struct cbc_message_peer *mp)
{
	struct cbc_cell_id *cci;
	enum cbc_cell_id_type id_discr = CBC_CELL_ID_NONE;

	llist_for_each_entry(cci, &mp->cell_list, list) {
		struct osmo_cbsp_cell_ent *ent;

		if (id_discr == CBC_CELL_ID_NONE)
			id_discr = cci->id_discr;
		else if (id_discr != cci->id_discr) {
			LOGPFSML(mp->fi, LOGL_ERROR, "Cannot encode CBSP cell_list as not all "
				 "entries are of same type (%u != %u)\n", id_discr, cci->id_discr);
			continue;
		}
		ent = talloc_zero(ctx, struct osmo_cbsp_cell_ent);
		OSMO_ASSERT(ent);
		cbsp_from_cci(&ent->cell_id, cci);
		llist_add_tail(&ent->list, &out->list);
	}
	out->id_discr = cell_id_from_ccid_discr(id_discr);
}

/***********************************************************************
 * actual FSM
 ***********************************************************************/

static void smscb_p_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	int rc;

	switch (event) {
	case SMSCB_PEER_E_CREATE:
		/* send it to peer */
		rc = peer_new_cbc_message(mp->peer, mp->cbcmsg);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_WRITE_ACK, 10, T_WAIT_WRITE_ACK);
		if (rc != 0) /* Immediately timeout the message */
			fi->fsm->timer_cb(fi);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_wait_write_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	struct osmo_cbsp_decoded *dec = NULL;

	switch (event) {
	case SMSCB_PEER_E_CBSP_WRITE_ACK:
		dec = data;
		msg_peer_append_cbsp_compl(mp, &dec->u.write_replace_compl.num_compl_list);
		msg_peer_append_cbsp_cell(mp, &dec->u.write_replace_compl.cell_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_WRITE_ACK, mp);
		break;
	case SMSCB_PEER_E_CBSP_WRITE_NACK:
		dec = data;
		msg_peer_append_cbsp_compl(mp, &dec->u.write_replace_fail.num_compl_list);
		msg_peer_append_cbsp_cell(mp, &dec->u.write_replace_fail.cell_list);
		msg_peer_append_cbsp_fail(mp, &dec->u.write_replace_fail.fail_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_WRITE_NACK, mp);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	struct osmo_cbsp_decoded *cbsp;
	int rc;

	switch (event) {
	case SMSCB_PEER_E_REPLACE: /* send WRITE-REPLACE to BSC */
		cbsp = osmo_cbsp_decoded_alloc(mp->peer, CBSP_MSGT_WRITE_REPLACE);
		OSMO_ASSERT(cbsp);
		cbsp->u.write_replace.msg_id = mp->cbcmsg->msg.message_id;
		cbsp->u.write_replace.old_serial_nr = &mp->cbcmsg->msg.serial_nr;
		//cbsp->u.write_replace.new_serial_nr
		/* TODO: we assume that the replace will always affect all original cells */
		cbsp_append_cell_list(&cbsp->u.write_replace.cell_list, cbsp, mp);
		// TODO: ALL OTHER DATA
		rc = cbc_cbsp_link_tx(mp->peer->link.cbsp, cbsp);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_REPLACE_ACK, 10, T_WAIT_REPLACE_ACK);
		if (rc != 0) /* Immediately timeout the message */
			fi->fsm->timer_cb(fi);
		break;
	case SMSCB_PEER_E_STATUS: /* send MSG-STATUS-QUERY to BSC */
		cbsp = osmo_cbsp_decoded_alloc(mp->peer, CBSP_MSGT_MSG_STATUS_QUERY);
		OSMO_ASSERT(cbsp);
		cbsp->u.msg_status_query.msg_id = mp->cbcmsg->msg.message_id;
		cbsp->u.msg_status_query.old_serial_nr = mp->cbcmsg->msg.serial_nr;
		cbsp_append_cell_list(&cbsp->u.msg_status_query.cell_list, cbsp, mp);
		cbsp->u.msg_status_query.channel_ind = CBSP_CHAN_IND_BASIC;
		rc = cbc_cbsp_link_tx(mp->peer->link.cbsp, cbsp);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_STATUS_ACK, 10, T_WAIT_STATUS_ACK);
		if (rc != 0) /* Immediately timeout the message */
			fi->fsm->timer_cb(fi);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_wait_status_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	struct osmo_cbsp_decoded *dec = NULL;

	switch (event) {
	case SMSCB_PEER_E_CBSP_STATUS_ACK:
		dec = data;
		msg_peer_append_cbsp_compl(mp, &dec->u.msg_status_query_compl.num_compl_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_STATUS_ACK, mp);
		break;
	case SMSCB_PEER_E_CBSP_STATUS_NACK:
		dec = data;
		msg_peer_append_cbsp_compl(mp, &dec->u.msg_status_query_fail.num_compl_list);
		msg_peer_append_cbsp_fail(mp, &dec->u.msg_status_query_fail.fail_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_STATUS_NACK, mp);
		break;
	default:
		OSMO_ASSERT(0);
	}
}


static void smscb_p_fsm_wait_replace_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	struct osmo_cbsp_decoded *dec = NULL;

	switch (event) {
	case SMSCB_PEER_E_CBSP_REPLACE_ACK:
		dec = data;
		msg_peer_append_cbsp_compl(mp, &dec->u.write_replace_compl.num_compl_list);
		msg_peer_append_cbsp_cell(mp, &dec->u.write_replace_compl.cell_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_REPLACE_ACK, mp);
		break;
	case SMSCB_PEER_E_CBSP_REPLACE_NACK:
		dec = data;
		msg_peer_append_cbsp_compl(mp, &dec->u.write_replace_fail.num_compl_list);
		msg_peer_append_cbsp_cell(mp, &dec->u.write_replace_fail.cell_list);
		msg_peer_append_cbsp_fail(mp, &dec->u.write_replace_fail.fail_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_REPLACE_NACK, mp);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_wait_delete_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	struct osmo_cbsp_decoded *dec = NULL;

	switch (event) {
	case SMSCB_PEER_E_CBSP_DELETE_ACK:
		dec = data;
		/* append results */
		msg_peer_append_cbsp_compl(mp, &dec->u.kill_compl.num_compl_list);
		msg_peer_append_cbsp_cell(mp, &dec->u.kill_compl.cell_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_DELETED, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_DELETE_ACK, mp);
		break;
	case SMSCB_PEER_E_CBSP_DELETE_NACK:
		dec = data;
		/* append results */
		msg_peer_append_cbsp_compl(mp, &dec->u.kill_fail.num_compl_list);
		msg_peer_append_cbsp_cell(mp, &dec->u.kill_fail.cell_list);
		msg_peer_append_cbsp_fail(mp, &dec->u.kill_fail.fail_list);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_DELETED, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_DELETE_NACK, mp);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int smscb_p_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	case T_WAIT_WRITE_ACK:
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_PEER_E_CBSP_WRITE_NACK, NULL);
		break;
	case T_WAIT_REPLACE_ACK:
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_REPLACE_NACK, NULL);
		break;
	case T_WAIT_STATUS_ACK:
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_STATUS_NACK, NULL);
		break;
	case T_WAIT_DELETE_ACK:
		osmo_fsm_inst_state_chg(fi, SMSCB_S_DELETED, 0, 0);
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_PEER_E_CBSP_DELETE_NACK, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static void smscb_p_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	struct osmo_cbsp_decoded *cbsp;
	int rc;

	switch (event) {
	case SMSCB_PEER_E_DELETE: /* send KILL to BSC */
		switch (fi->state) {
		case SMSCB_S_DELETED:
		case SMSCB_S_INIT:
			LOGPFSML(fi, LOGL_ERROR, "Event %s not permitted\n",
				 osmo_fsm_event_name(fi->fsm, event));
			return;
		default:
			break;
		}
		cbsp = osmo_cbsp_decoded_alloc(mp->peer, CBSP_MSGT_KILL);
		OSMO_ASSERT(cbsp);
		cbsp->u.kill.msg_id = mp->cbcmsg->msg.message_id;
		cbsp->u.kill.old_serial_nr = mp->cbcmsg->msg.serial_nr;
		/* TODO: we assume that the delete will always affect all original cells */
		cbsp_append_cell_list(&cbsp->u.kill.cell_list, cbsp, mp);
		if (!mp->cbcmsg->msg.is_etws) {
			/* Channel Indication IE is only present in CBS, not in ETWS! */
			cbsp->u.kill.channel_ind = talloc_zero(cbsp, enum cbsp_channel_ind);
			OSMO_ASSERT(cbsp->u.kill.channel_ind);
			*(cbsp->u.kill.channel_ind) = CBSP_CHAN_IND_BASIC;
		}
		rc = cbc_cbsp_link_tx(mp->peer->link.cbsp, cbsp);
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_DELETE_ACK, 10, T_WAIT_DELETE_ACK);
		if (rc != 0) /* Immediately timeout the message */
			fi->fsm->timer_cb(fi);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	llist_del(&mp->list);
	/* memory of mp is child of fi and hence automatically free'd */
}

static const struct osmo_fsm_state smscb_p_fsm_states[] = {
	[SMSCB_S_INIT] = {
		.name = "INIT",
		.in_event_mask = S(SMSCB_PEER_E_CREATE),
		.out_state_mask = S(SMSCB_S_WAIT_WRITE_ACK) |
				  S(SMSCB_S_ACTIVE),
		.action = smscb_p_fsm_init,
	},
	[SMSCB_S_WAIT_WRITE_ACK] = {
		.name = "WAIT_WRITE_ACK",
		.in_event_mask = S(SMSCB_PEER_E_CBSP_WRITE_ACK) |
				 S(SMSCB_PEER_E_CBSP_WRITE_NACK),
		.out_state_mask = S(SMSCB_S_ACTIVE) |
				  S(SMSCB_S_WAIT_DELETE_ACK),
		.action = smscb_p_fsm_wait_write_ack,
	},
	[SMSCB_S_ACTIVE] = {
		.name = "ACTIVE",
		.in_event_mask = S(SMSCB_PEER_E_REPLACE) |
				 S(SMSCB_PEER_E_STATUS),
		.out_state_mask = S(SMSCB_S_WAIT_REPLACE_ACK) |
				  S(SMSCB_S_WAIT_STATUS_ACK) |
				  S(SMSCB_S_WAIT_DELETE_ACK),
		.action = smscb_p_fsm_active,
	},
	[SMSCB_S_WAIT_STATUS_ACK] = {
		.name = "WAIT_STATUS_ACK",
		.in_event_mask = S(SMSCB_PEER_E_CBSP_STATUS_ACK) |
				 S(SMSCB_PEER_E_CBSP_STATUS_NACK),
		.out_state_mask = S(SMSCB_S_ACTIVE) |
				 S(SMSCB_S_WAIT_DELETE_ACK),
		.action = smscb_p_fsm_wait_status_ack,
	},
	[SMSCB_S_WAIT_REPLACE_ACK] = {
		.name = "WAIT_REPLACE_ACK",
		.in_event_mask = S(SMSCB_PEER_E_CBSP_REPLACE_ACK) |
				 S(SMSCB_PEER_E_CBSP_REPLACE_NACK),
		.out_state_mask = S(SMSCB_S_ACTIVE) |
				  S(SMSCB_S_WAIT_DELETE_ACK),
		.action = smscb_p_fsm_wait_replace_ack,
	},
	[SMSCB_S_WAIT_DELETE_ACK] = {
		.name = "WAIT_DELETE_ACK",
		.in_event_mask = S(SMSCB_PEER_E_CBSP_DELETE_ACK) |
				 S(SMSCB_PEER_E_CBSP_DELETE_NACK),
		.out_state_mask = S(SMSCB_S_DELETED),
		.action = smscb_p_fsm_wait_delete_ack,
	},
	[SMSCB_S_DELETED] = {
		.name = "DELETED",
	},
};

struct osmo_fsm cbsp_smscb_peer_fsm = {
	.name = "SMSCB-PEER-CBSP",
	.states = smscb_p_fsm_states,
	.num_states = ARRAY_SIZE(smscb_p_fsm_states),
	.allstate_event_mask = S(SMSCB_PEER_E_DELETE),
	.allstate_action = smscb_p_fsm_allstate,
	.timer_cb = smscb_p_fsm_timer_cb,
	.log_subsys = DCBSP,
	.event_names = smscb_peer_fsm_event_names,
	.cleanup = smscb_p_fsm_cleanup,
};

static __attribute__((constructor)) void on_dso_load_smscb_p_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&cbsp_smscb_peer_fsm) == 0);
}
