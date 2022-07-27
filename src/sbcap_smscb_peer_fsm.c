/* SMSCB Peer FSM: Represents state of one SMSCB for one peer (MME) */

/* This FSM exists per tuple of (message, mme peer) */

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

#include <osmocom/sbcap/sbcap_common.h>

#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/sbcap_msg.h>
#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/smscb_peer_fsm.h>
#include <osmocom/cbc/smscb_message_fsm.h>

#define S(x)	(1 << (x))

/***********************************************************************
 * Helper functions
 ***********************************************************************/

/* append SBcAP cells to msg_peer compl list */
void msg_peer_append_compl_sbcap_bcast_area_list(struct cbc_message_peer *mp,
						 const SBcAP_Broadcast_Scheduled_Area_List_t *bcast)
{
	SBcAP_CellId_Broadcast_List_t *cell_id_bscat = bcast->cellId_Broadcast_List;
	A_SEQUENCE_OF(struct SBcAP_CellId_Broadcast_List_Item) *as_cell_id_bcast;
	SBcAP_CellId_Broadcast_List_Item_t *it;
	unsigned int i;

	if (!cell_id_bscat)
		return;

	as_cell_id_bcast = (void *) &cell_id_bscat->list;
	for (i = 0; i < as_cell_id_bcast->count; i++) {
		it = (SBcAP_CellId_Broadcast_List_Item_t *)(as_cell_id_bcast->array[i]);
		OSMO_ASSERT(it);
		struct cbc_cell_id *cci = NULL; // FIXME: lookup
		if (!cci) {
			cci = talloc_zero(mp, struct cbc_cell_id);
			if (!cci)
				return;
			llist_add_tail(&cci->list, &mp->num_compl_list);
		}
		cci_from_sbcap_bcast_cell_id(cci, it);
		LOGPFSML(mp->fi, LOGL_DEBUG, "Appending CellId %s to Broadcast Completed list\n",
			 cbc_cell_id2str(cci));
		cci->num_compl.num_compl += 1;
		cci->num_compl.num_bcast_info += 1;
	}
}

/* append SBcAP cells to msg_peer fail list */
void msg_peer_append_fail_sbcap_tai_list(struct cbc_message_peer *mp,
					 const SBcAP_List_of_TAIs_t *tais)
{
	A_SEQUENCE_OF(List_of_TAIs__Member) *as_tais = (void *)&tais->list;
	List_of_TAIs__Member *it;
	unsigned int i;

	for (i = 0; i < as_tais->count; i++) {
		it = (List_of_TAIs__Member *)(as_tais->array[i]);
		OSMO_ASSERT(it);
		struct cbc_cell_id *cci = NULL; // FIXME: lookup
		if (!cci) {
			cci = talloc_zero(mp, struct cbc_cell_id);
			if (!cci)
				return;
			llist_add_tail(&cci->list, &mp->fail_list);
		}
		cci_from_sbcap_tai(cci, &it->tai);
		cci->fail.cause = SBcAP_Cause_tracking_area_not_valid;
		LOGPFSML(mp->fi, LOGL_DEBUG, "Appending CellId %s (cause: %s) to Failed list\n",
			 cbc_cell_id2str(cci), sbcap_cause_str(cci->fail.cause));
	}
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
		if (rc == 0) {
			/* wait for peers' response */
			osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_WRITE_ACK, 10,
						T_WAIT_WRITE_ACK);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_wait_write_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	SBcAP_SBC_AP_PDU_t *sbcap = NULL;
	A_SEQUENCE_OF(void) *as_pdu;
	SBcAP_Write_Replace_Warning_Response_IEs_t *ie;

	switch (event) {
	case SMSCB_PEER_E_SBCAP_WRITE_ACK:
		sbcap = data;
		OSMO_ASSERT(sbcap->present == SBcAP_SBC_AP_PDU_PR_successfulOutcome);
		OSMO_ASSERT(sbcap->choice.successfulOutcome.procedureCode == SBcAP_ProcedureId_Write_Replace_Warning);
		as_pdu = (void *)&sbcap->choice.successfulOutcome.value.choice.Write_Replace_Warning_Response.protocolIEs.list;
		/* static const long asn_VAL_21_SBcAP_id_Unknown_Tracking_Area_List = 22; */
		ie = sbcap_as_find_ie(as_pdu, 22);
		if (ie) { /* IE is optional */
			OSMO_ASSERT(ie->value.present == SBcAP_Write_Replace_Warning_Response_IEs__value_PR_List_of_TAIs);
			msg_peer_append_fail_sbcap_tai_list(mp, &ie->value.choice.List_of_TAIs);
		}
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_WRITE_ACK, mp);
		break;
	case SMSCB_PEER_E_SBCAP_WRITE_NACK:
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
	//struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;

	switch (event) {
	case SMSCB_PEER_E_REPLACE: /* send WRITE-REPLACE to MME */
		/* NOT IMPLEMENETED */
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_REPLACE_ACK, 10, T_WAIT_REPLACE_ACK);
		break;
	case SMSCB_PEER_E_STATUS:
		/* NOT IMPLEMENETED */
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_STATUS_ACK, 10, T_WAIT_STATUS_ACK);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_wait_status_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;

	switch (event) {
	/* NOT IMPLEMENETED */
	default:
		OSMO_ASSERT(0);
	}
}


static void smscb_p_fsm_wait_replace_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;

	switch (event) {
	/* NOT IMPLEMENETED */
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_p_fsm_wait_delete_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;

	switch (event) {
	case SMSCB_PEER_E_SBCAP_DELETE_ACK:
		//pdu = data;
		osmo_fsm_inst_state_chg(fi, SMSCB_S_DELETED, 0, 0);
		/* Signal parent fsm about completion */
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_DELETE_ACK, mp);
		break;
	case SMSCB_PEER_E_SBCAP_DELETE_NACK:
		//pdu = data;
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
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_WRITE_NACK, NULL);
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
		osmo_fsm_inst_dispatch(fi->proc.parent, SMSCB_MSG_E_DELETE_NACK, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static void smscb_p_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message_peer *mp = (struct cbc_message_peer *) fi->priv;
	SBcAP_SBC_AP_PDU_t *sbcap;
	A_SEQUENCE_OF(void) *as_pdu;
	SBcAP_Write_Replace_Warning_Indication_IEs_t *ie;

	switch (event) {
	case SMSCB_PEER_E_DELETE: /* send Stop-Warning to MME */
		switch (fi->state) {
		case SMSCB_S_DELETED:
		case SMSCB_S_INIT:
			LOGPFSML(fi, LOGL_ERROR, "Event %s not permitted\n",
				 osmo_fsm_event_name(fi->fsm, event));
			return;
		default:
			break;
		}
		if ((sbcap = sbcap_gen_stop_warning_req(mp->peer, mp->cbcmsg))) {
			cbc_sbcap_link_tx(mp->peer->link.sbcap, sbcap);
		} else {
			LOGP(DSBcAP, LOGL_ERROR,
			     "[%s] Tx SBc-AP Stop-Warning-Request: msg gen failed\n",
			     mp->peer->name);
		}
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_DELETE_ACK, 10, T_WAIT_DELETE_ACK);
		break;
	case SMSCB_PEER_E_SBCAP_WRITE_IND:
		sbcap = (SBcAP_SBC_AP_PDU_t *)data;
		OSMO_ASSERT(sbcap->present == SBcAP_SBC_AP_PDU_PR_initiatingMessage);
		OSMO_ASSERT(sbcap->choice.initiatingMessage.procedureCode == SBcAP_ProcedureId_Write_Replace_Warning_Indication);
		as_pdu = (void *)&sbcap->choice.initiatingMessage.value.choice.Write_Replace_Warning_Indication.protocolIEs.list;
		/* static const long asn_VAL_36_SBcAP_id_Broadcast_Scheduled_Area_List = 23; */
		ie = sbcap_as_find_ie(as_pdu, 23);
		if (!ie)
			return; /* IE is optional */
		OSMO_ASSERT(ie->value.present == SBcAP_Write_Replace_Warning_Indication_IEs__value_PR_Broadcast_Scheduled_Area_List);
		msg_peer_append_compl_sbcap_bcast_area_list(mp, &ie->value.choice.Broadcast_Scheduled_Area_List);
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
		.out_state_mask = S(SMSCB_S_WAIT_WRITE_ACK),
		.action = smscb_p_fsm_init,
	},
	[SMSCB_S_WAIT_WRITE_ACK] = {
		.name = "WAIT_WRITE_ACK",
		.in_event_mask = S(SMSCB_PEER_E_SBCAP_WRITE_ACK) |
				 S(SMSCB_PEER_E_SBCAP_WRITE_NACK),
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
		.in_event_mask = 0 /* NOT IMPLEMENTED */,
		.out_state_mask = S(SMSCB_S_ACTIVE) |
				 S(SMSCB_S_WAIT_DELETE_ACK),
		.action = smscb_p_fsm_wait_status_ack,
	},
	[SMSCB_S_WAIT_REPLACE_ACK] = {
		.name = "WAIT_REPLACE_ACK",
		.in_event_mask = 0 /* NOT IMPLEMENTED */,
		.out_state_mask = S(SMSCB_S_ACTIVE) |
				  S(SMSCB_S_WAIT_DELETE_ACK),
		.action = smscb_p_fsm_wait_replace_ack,
	},
	[SMSCB_S_WAIT_DELETE_ACK] = {
		.name = "WAIT_DELETE_ACK",
		.in_event_mask = S(SMSCB_PEER_E_SBCAP_DELETE_ACK) |
				 S(SMSCB_PEER_E_SBCAP_DELETE_NACK),
		.out_state_mask = S(SMSCB_S_DELETED),
		.action = smscb_p_fsm_wait_delete_ack,
	},
	[SMSCB_S_DELETED] = {
		.name = "DELETED",
	},
};

struct osmo_fsm sbcap_smscb_peer_fsm = {
	.name = "SMSCB-PEER-SBcAP",
	.states = smscb_p_fsm_states,
	.num_states = ARRAY_SIZE(smscb_p_fsm_states),
	.allstate_event_mask = S(SMSCB_PEER_E_DELETE) |
			       S(SMSCB_PEER_E_SBCAP_WRITE_IND),
	.allstate_action = smscb_p_fsm_allstate,
	.timer_cb = smscb_p_fsm_timer_cb,
	.log_subsys = DSBcAP,
	.event_names = smscb_peer_fsm_event_names,
	.cleanup = smscb_p_fsm_cleanup,
};

static __attribute__((constructor)) void on_dso_load_smscb_p_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&sbcap_smscb_peer_fsm) == 0);
}
