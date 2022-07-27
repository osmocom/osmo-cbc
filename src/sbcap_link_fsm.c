/* (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <osmocom/core/fsm.h>

#include <osmocom/sbcap/sbcap_common.h>

#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/sbcap_link_fsm.h>
#include <osmocom/cbc/sbcap_msg.h>
#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/smscb_message_fsm.h>

#define S(x)	(1 << (x))

enum sbcap_link_state {
	/* initial state after link SCTP connection established */
	SBcAP_LINK_S_INIT,
	/* normal operation (idle) */
	SBcAP_LINK_S_IDLE,
};

static const struct value_string sbcap_link_event_names[] = {
	{ SBcAP_LINK_E_RX_RESTART, "Rx Restart" },
	{ SBcAP_LINK_E_CMD_RESET, "RESET.cmd" },
	{ SBcAP_LINK_E_CMD_CLOSE, "CLOSE.cmd" },
	{ 0, NULL }
};

static void sbcap_link_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SBcAP_LINK_E_CMD_RESET:
		osmo_fsm_inst_state_chg(fi, SBcAP_LINK_S_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void sbcap_link_s_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	default:
		OSMO_ASSERT(0);
	}
}

static void sbcap_link_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_sbcap_link *link = (struct cbc_sbcap_link *) fi->priv;
	//SBcAP_SBC_AP_PDU_t *pdu;

	switch (event) {
	case SBcAP_LINK_E_CMD_CLOSE:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);
		break;
	case SBcAP_LINK_E_RX_RESTART:
		//pdu = data;
		/* TODO: delete any CBS state we have for this peer */
		/* TODO: re-send messages we have matching the scope of the peer */
		LOGPSBCAPC(link, LOGL_NOTICE, "Rx PWS Restart Indication not implemented yet\n");
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void sbcap_link_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct cbc_sbcap_link *link = (struct cbc_sbcap_link *) fi->priv;

	cbc_sbcap_link_close(link);

	/* reparent the fsm_inst to the cbc as we're about to free() it's talloc
	 * parent 'link' */
	link->fi = NULL;
	talloc_steal(g_cbc, fi);

	cbc_sbcap_link_free(link);
}

static const struct osmo_fsm_state sbcap_link_fsm_states[] = {
	[SBcAP_LINK_S_INIT] = {
		.name = "INIT",
		.in_event_mask = S(SBcAP_LINK_E_CMD_RESET),
		.out_state_mask = S(SBcAP_LINK_S_IDLE),
		.action = sbcap_link_s_init,
	},
	[SBcAP_LINK_S_IDLE] = {
		.name = "IDLE",
		.in_event_mask = 0,
		.out_state_mask = 0,
		.action = sbcap_link_s_idle,
	},
};

struct osmo_fsm sbcap_link_fsm = {
	.name = "SBcAP-Link",
	.states = sbcap_link_fsm_states,
	.num_states = ARRAY_SIZE(sbcap_link_fsm_states),
	.allstate_event_mask = S(SBcAP_LINK_E_CMD_CLOSE) |
			       S(SBcAP_LINK_E_RX_RESTART),
	.allstate_action = sbcap_link_fsm_allstate,
	.log_subsys = DSBcAP,
	.event_names = sbcap_link_event_names,
	.cleanup = sbcap_link_fsm_cleanup,
};

static SBcAP_Message_Identifier_t *get_msg_id_ie(struct cbc_sbcap_link *link,
						 const SBcAP_SBC_AP_PDU_t *pdu)
{
	A_SEQUENCE_OF(void) *as_pdu = NULL;
	/* static const long asn_VAL_1_SBcAP_id_Message_Identifier = 5; */
	const SBcAP_ProtocolIE_ID_t msg_id_ie = 5;
	void *ie;

	switch (pdu->present) {
	case SBcAP_SBC_AP_PDU_PR_initiatingMessage:
		switch (pdu->choice.initiatingMessage.procedureCode) {
		case SBcAP_ProcedureId_Write_Replace_Warning_Indication:
			as_pdu = (void *)&pdu->choice.initiatingMessage.value.choice.Write_Replace_Warning_Indication.protocolIEs.list;
			if (!(ie = sbcap_as_find_ie(as_pdu, msg_id_ie)))
				return NULL;
			return &((SBcAP_Write_Replace_Warning_Indication_IEs_t *)ie)->value.choice.Message_Identifier;
		case SBcAP_ProcedureId_Stop_Warning_Indication:
			as_pdu = (void *)&pdu->choice.initiatingMessage.value.choice.Stop_Warning_Indication.protocolIEs.list;
			if (!(ie = sbcap_as_find_ie(as_pdu, msg_id_ie)))
				return NULL;
			return &((SBcAP_Stop_Warning_Indication_IEs_t *)ie)->value.choice.Message_Identifier;
		default:
			LOGPSBCAPC(link, LOGL_ERROR, "get_msg_id initiatingMessage procedure=%ld not implemented\n",
			       pdu->choice.unsuccessfulOutcome.procedureCode);
			return NULL;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_successfulOutcome:
		switch (pdu->choice.successfulOutcome.procedureCode) {
		case SBcAP_ProcedureId_Write_Replace_Warning:
			as_pdu = (void *)&pdu->choice.successfulOutcome.value.choice.Write_Replace_Warning_Response.protocolIEs.list;
			if (!(ie = sbcap_as_find_ie(as_pdu, msg_id_ie)))
				return NULL;
			return &((SBcAP_Write_Replace_Warning_Response_IEs_t *)ie)->value.choice.Message_Identifier;
		case SBcAP_ProcedureId_Stop_Warning:
			as_pdu = (void *)&pdu->choice.successfulOutcome.value.choice.Stop_Warning_Response.protocolIEs.list;
			if (!(ie = sbcap_as_find_ie(as_pdu, msg_id_ie)))
				return NULL;
			return &((SBcAP_Stop_Warning_Response_IEs_t *)ie)->value.choice.Message_Identifier;
		default:
			LOGPSBCAPC(link, LOGL_ERROR, "get_msg_id successfulOutcome procedure=%ld not implemented\n",
			       pdu->choice.unsuccessfulOutcome.procedureCode);
			return NULL;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_unsuccessfulOutcome:
		switch (pdu->choice.unsuccessfulOutcome.procedureCode) {
		default:
			LOGPSBCAPC(link, LOGL_ERROR, "get_msg_id unsuccessfulOutcome procedure=%ld not implemented\n",
			       pdu->choice.unsuccessfulOutcome.procedureCode);
			return NULL;
		}
		break;
	default:
		return NULL;
	}
}

static int get_msg_id(struct cbc_sbcap_link *link, const SBcAP_SBC_AP_PDU_t *pdu)
{
	SBcAP_Message_Identifier_t *ie = get_msg_id_ie(link, pdu);
	if (!ie)
		return -1;
	if (ie->size != 2) {
		LOGPSBCAPC(link, LOGL_ERROR, "get_msg_id(%s) wrong size %zu\n",
			   sbcap_pdu_get_name(pdu), ie->size);
		return -1;
	}
	return osmo_load16be(ie->buf);
}

/* Rx Error Indication from peer */
static int cbc_sbcap_link_rx_error_ind(struct cbc_sbcap_link *link, SBcAP_SBC_AP_PDU_t *pdu)
{
	A_SEQUENCE_OF(void) *as_pdu = NULL;
	SBcAP_ErrorIndicationIEs_t *ie;
	SBcAP_Criticality_Diagnostics_t *ie_diag = NULL;
	long cause = -1;
	long proc_code = -1;
	long trigger_msg = -1;
	long criticality = -1;
	int i;

	as_pdu = (void *)&pdu->choice.initiatingMessage.value.choice.Error_Indication.protocolIEs.list;
	OSMO_ASSERT(as_pdu);

	for (i = 0; i < as_pdu->count; i++) {
		ie = (SBcAP_ErrorIndicationIEs_t *)(as_pdu->array[i]);
		OSMO_ASSERT(ie);
		switch (ie->id) {
		case SBcAP_ErrorIndicationIEs__value_PR_Cause:
			cause = ie->value.choice.Cause;
			break;
		case SBcAP_ErrorIndicationIEs__value_PR_Criticality_Diagnostics:
			ie_diag = &ie->value.choice.Criticality_Diagnostics;
			if (ie_diag->procedureCode)
				proc_code = *ie_diag->procedureCode;
			if (ie_diag->triggeringMessage)
				trigger_msg = *ie_diag->triggeringMessage;
			if (ie_diag->procedureCriticality)
				criticality = *ie_diag->procedureCriticality;
			break;
		default:
			continue;
		}
	}

	LOGPSBCAPC(link, LOGL_ERROR, "Rx %s (cause=%ld, diagnostics=%d [proc_code=%ld, trigger_msg=%ld criticality=%ld])\n",
		  sbcap_pdu_get_name(pdu), cause, !!ie_diag, proc_code, trigger_msg, criticality);
	return 0;
}

/* message was received from remote SBc-AP peer (MME) */
int cbc_sbcap_link_rx_cb(struct cbc_sbcap_link *link, SBcAP_SBC_AP_PDU_t *pdu)
{
	struct cbc_message *smscb;
	struct cbc_message_peer *mp;
	SBcAP_SBC_AP_PDU_t *err_ind_pdu;
	int msg_id;

	/* messages without reference to a specific SMSCB message */
	switch (pdu->present) {
	case SBcAP_SBC_AP_PDU_PR_initiatingMessage:
		switch (pdu->choice.initiatingMessage.procedureCode) {
		case SBcAP_ProcedureId_Write_Replace_Warning:
		case SBcAP_ProcedureId_Stop_Warning:
			LOGPSBCAPC(link, LOGL_ERROR,
				   "SBcAP %s MME->CBC not expected\n",
				   sbcap_pdu_get_name(pdu));
			return -EINVAL;
		case SBcAP_ProcedureId_PWS_Restart_Indication:
			return osmo_fsm_inst_dispatch(link->fi, SBcAP_LINK_E_RX_RESTART, pdu);
		case SBcAP_ProcedureId_Error_Indication:
			return cbc_sbcap_link_rx_error_ind(link, pdu);
		case SBcAP_ProcedureId_PWS_Failure_Indication:
			LOGPSBCAPC(link, LOGL_NOTICE, "Rx %s not implemented yet\n",
				   sbcap_pdu_get_name(pdu));
			return 0;
		case SBcAP_ProcedureId_Stop_Warning_Indication:
		case SBcAP_ProcedureId_Write_Replace_Warning_Indication:
			break; /* Handle msg id below */
		default:
			LOGPSBCAPC(link, LOGL_ERROR, "SBcAP initiatingMessage procedure=%ld not implemented?\n",
				   pdu->choice.initiatingMessage.procedureCode);
			err_ind_pdu = sbcap_gen_error_ind(link, SBcAP_Cause_valid_message_not_identified, pdu);
			if (err_ind_pdu)
				cbc_sbcap_link_tx(link, err_ind_pdu);
			else
				LOGPSBCAPC(link, LOGL_ERROR,
					   "Tx SBc-AP %s: msg gen failed\n",
					   sbcap_pdu_get_name(err_ind_pdu));
			return 0;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_successfulOutcome:
		switch (pdu->choice.successfulOutcome.procedureCode) {
		default:
			LOGPSBCAPC(link, LOGL_INFO, "SBcAP SuccessfulOutcome procedure=%ld\n",
			       pdu->choice.successfulOutcome.procedureCode);
			break;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_unsuccessfulOutcome:
		switch (pdu->choice.unsuccessfulOutcome.procedureCode) {
		default:
			LOGPSBCAPC(link, LOGL_ERROR, "SBcAP UnsuccessfulOutcome procedure=%ld\n",
			       pdu->choice.unsuccessfulOutcome.procedureCode);
			break;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_NOTHING:
	default:
		LOGPSBCAPC(link, LOGL_ERROR, "Rx SBc-AP unexpected message type %d\n",
		       pdu->present);
		return 0;
	}


	/* messages with reference to a specific SMSCB message handled below*/
	msg_id = get_msg_id(link, pdu);
	OSMO_ASSERT(msg_id >= 0);

	/* look-up smscb_message */
	smscb = cbc_message_by_id(msg_id);
	if (!smscb) {
		LOGPSBCAPC(link, LOGL_ERROR, "Rx SBc-AP %s for unknown message-id 0x%04x\n",
			   sbcap_pdu_get_name(pdu), msg_id);
		/* TODO: inform peer? */
		return 0;
	}

	/* look-up smscb_message_peer */
	mp = cbc_message_peer_get(smscb, link->peer);
	if (!mp) {
		LOGPSBCAPC(link, LOGL_ERROR, "Rx SBc-AP %s for message-id 0x%04x without peer %s\n",
			   sbcap_pdu_get_name(pdu), msg_id, link->peer->name);
		/* TODO: inform peer? */
		return 0;
	}

	/* dispatch event to smscp_p_fms instance */
	switch (pdu->present) {
	case SBcAP_SBC_AP_PDU_PR_initiatingMessage:
		switch (pdu->choice.initiatingMessage.procedureCode) {
		default:
			break;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_successfulOutcome:
		switch (pdu->choice.successfulOutcome.procedureCode) {
		case SBcAP_ProcedureId_Write_Replace_Warning:
			//if (dec->u.write_replace_compl.old_serial_nr)
			//	return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_SBcAP_REPLACE_ACK, dec);
			//else
				return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_SBCAP_WRITE_ACK, pdu);
		case SBcAP_ProcedureId_Stop_Warning:
			return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_SBCAP_DELETE_ACK, pdu);
		default:
			break;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_unsuccessfulOutcome:
		switch (pdu->choice.unsuccessfulOutcome.procedureCode) {
		case SBcAP_ProcedureId_Stop_Warning:
			return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_SBCAP_DELETE_NACK, pdu);
		default:
			break;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_NOTHING:
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static __attribute__((constructor)) void on_dso_load_sbcap_srv_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&sbcap_link_fsm) == 0);
}
