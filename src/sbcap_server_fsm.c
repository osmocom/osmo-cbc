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
#include <osmocom/cbc/sbcap_server.h>
#include <osmocom/cbc/sbcap_server_fsm.h>
#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/smscb_message_fsm.h>

#define S(x)	(1 << (x))

enum sbcap_server_state {
	/* initial state after client SCTP connection established */
	SBcAP_SRV_S_INIT,
	/* normal operation (idle) */
	SBcAP_SRV_S_IDLE,
};

static const struct value_string sbcap_server_event_names[] = {
	{ SBcAP_SRV_E_RX_RST_COMPL, "Rx Reset Complete" },
	{ SBcAP_SRV_E_RX_RST_FAIL, "Rx Reset Failure" },
	{ SBcAP_SRV_E_RX_KA_COMPL, "Rx Keep-Alive Complete" },
	{ SBcAP_SRV_E_RX_RESTART, "Rx Restart" },
	{ SBcAP_SRV_E_CMD_RESET, "RESET.cmd" },
	{ SBcAP_SRV_E_CMD_CLOSE, "CLOSE.cmd" },
	{ 0, NULL }
};

static void sbcap_server_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SBcAP_SRV_E_CMD_RESET:
		osmo_fsm_inst_state_chg(fi, SBcAP_SRV_S_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void sbcap_server_s_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	default:
		OSMO_ASSERT(0);
	}
}

static void sbcap_server_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_sbcap_cbc_client *client = (struct osmo_sbcap_cbc_client *) fi->priv;
	//SBcAP_SBC_AP_PDU_t *pdu;

	switch (event) {
	case SBcAP_SRV_E_CMD_CLOSE:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REQUEST, NULL);
		break;
	case SBcAP_SRV_E_RX_RESTART:
		//pdu = data;
		/* TODO: delete any CBS state we have for this peer */
		/* TODO: re-send messages we have matching the scope of the peer */
		LOGPSBCAPC(client, LOGL_NOTICE, "RESTART  but re-sending not implemented yet\n");
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void sbcap_server_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct osmo_sbcap_cbc_client *client = (struct osmo_sbcap_cbc_client *) fi->priv;

	if (client->conn)
		osmo_stream_srv_destroy(client->conn);
	llist_del(&client->list);
	client->fi = NULL;

	/* reparent the fsm_inst to the cbc as we're about to free() it's talloc
	 * parent 'client' */
	talloc_steal(g_cbc, fi);
	talloc_free(client);
}

static const struct osmo_fsm_state sbcap_server_fsm_states[] = {
	[SBcAP_SRV_S_INIT] = {
		.name = "INIT",
		.in_event_mask = S(SBcAP_SRV_E_CMD_RESET),
		.out_state_mask = S(SBcAP_SRV_S_IDLE),
		.action = sbcap_server_s_init,
	},
	[SBcAP_SRV_S_IDLE] = {
		.name = "IDLE",
		.in_event_mask = 0,
		.out_state_mask = 0,
		.action = sbcap_server_s_idle,
	},
};

struct osmo_fsm sbcap_server_fsm = {
	.name = "SBcAP-SERVER",
	.states = sbcap_server_fsm_states,
	.num_states = ARRAY_SIZE(sbcap_server_fsm_states),
	.allstate_event_mask = S(SBcAP_SRV_E_CMD_CLOSE) |
			       S(SBcAP_SRV_E_RX_RESTART),
	.allstate_action = sbcap_server_fsm_allstate,
	.log_subsys = DSBcAP,
	.event_names = sbcap_server_event_names,
	.cleanup = sbcap_server_fsm_cleanup,
};

static void *sbcap_as_find_ie(void *void_list, SBcAP_ProtocolIE_ID_t ie_id)
{
	A_SEQUENCE_OF(SBcAP_ProtocolIE_ID_t) *li = (void *)void_list;
	int i;
	for (i = 0; i < li->count; i++) {
		/* "SBcAP_ProtocolIE_ID_t id" is first element in all *_IEs struct */
		SBcAP_ProtocolIE_ID_t *cur_ie_id = li->array[i];
		if (*cur_ie_id == ie_id) {
			return cur_ie_id;
		}
	}
	return NULL;
}

static SBcAP_Message_Identifier_t *get_msg_id_ie(struct osmo_sbcap_cbc_client *client,
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
			LOGPSBCAPC(client, LOGL_ERROR, "get_msg_id initiatingMessage procedure=%ld not implemented\n",
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
			LOGPSBCAPC(client, LOGL_ERROR, "get_msg_id successfulOutcome procedure=%ld not implemented\n",
			       pdu->choice.unsuccessfulOutcome.procedureCode);
			return NULL;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_unsuccessfulOutcome:
		switch (pdu->choice.unsuccessfulOutcome.procedureCode) {
		default:
			LOGPSBCAPC(client, LOGL_ERROR, "get_msg_id unsuccessfulOutcome procedure=%ld not implemented\n",
			       pdu->choice.unsuccessfulOutcome.procedureCode);
			return NULL;
		}
		break;
	default:
		return NULL;
	}
}

static int get_msg_id(struct osmo_sbcap_cbc_client *client, const SBcAP_SBC_AP_PDU_t *pdu)
{
	SBcAP_Message_Identifier_t *ie = get_msg_id_ie(client, pdu);
	if (!ie)
		return -1;
	if (ie->size != 2) {
		LOGPSBCAPC(client, LOGL_ERROR, "get_msg_id wrong size %zu\n", ie->size);
		return -1;
	}
	return osmo_load16be(ie->buf);
}

/* message was received from remote SBcAP peer (BSC) */
int sbcap_cbc_client_rx_cb(struct osmo_sbcap_cbc_client *client, SBcAP_SBC_AP_PDU_t *pdu)
{
	struct cbc_message *smscb;
	struct cbc_message_peer *mp;
	int msg_id;

	/* messages without reference to a specific SMSCB message */
	switch (pdu->present) {
	case SBcAP_SBC_AP_PDU_PR_initiatingMessage:
		switch (pdu->choice.initiatingMessage.procedureCode) {
		case SBcAP_ProcedureId_Write_Replace_Warning:
		case SBcAP_ProcedureId_Stop_Warning:
			LOGPSBCAPC(client, LOGL_ERROR,
				   "SBcAP initiatingMessage procedure=%ld MME->CBC not expected\n",
				   pdu->choice.initiatingMessage.procedureCode);
			return -EINVAL;
		case SBcAP_ProcedureId_PWS_Restart_Indication:
			return osmo_fsm_inst_dispatch(client->fi, SBcAP_SRV_E_RX_RESTART, pdu);
		case SBcAP_ProcedureId_Stop_Warning_Indication:
		case SBcAP_ProcedureId_Write_Replace_Warning_Indication:
			break; /* Handle msg id below */
		case SBcAP_ProcedureId_Error_Indication:
		case SBcAP_ProcedureId_PWS_Failure_Indication:
		default:
			LOGPSBCAPC(client, LOGL_ERROR, "SBcAP initiatingMessage procedure=%ld not implemented?\n",
			       pdu->choice.initiatingMessage.procedureCode);
			return 0;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_successfulOutcome:
		switch (pdu->choice.successfulOutcome.procedureCode) {
		default:
			LOGPSBCAPC(client, LOGL_INFO, "SBcAP SuccessfulOutcome procedure=%ld\n",
			       pdu->choice.successfulOutcome.procedureCode);
			break;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_unsuccessfulOutcome:
		switch (pdu->choice.unsuccessfulOutcome.procedureCode) {
		default:
			LOGPSBCAPC(client, LOGL_ERROR, "SBcAP UnsuccessfulOutcome procedure=%ld\n",
			       pdu->choice.unsuccessfulOutcome.procedureCode);
			break;
		}
		break;
	case SBcAP_SBC_AP_PDU_PR_NOTHING:
	default:
		LOGPSBCAPC(client, LOGL_ERROR, "Rx SBc-AP unexpected message type %d\n",
		       pdu->present);
		return 0;
	}


	/* messages with reference to a specific SMSCB message handled below*/
	msg_id = get_msg_id(client, pdu);
	OSMO_ASSERT(msg_id >= 0);

	/* look-up smscb_message */
	smscb = cbc_message_by_id(msg_id);
	if (!smscb) {
		LOGPSBCAPC(client, LOGL_ERROR, "Rx SBc-AP msg for unknown message-id 0x%04x\n",
			   msg_id);
		/* TODO: inform peer? */
		return 0;
	}

	/* look-up smscb_message_peer */
	mp = cbc_message_peer_get(smscb, client->peer);
	if (!mp) {
		LOGPSBCAPC(client, LOGL_ERROR, "Rx SBc-AP msg for message-id 0x%04x without peer %s\n",
			   msg_id, client->peer->name);
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
	OSMO_ASSERT(osmo_fsm_register(&sbcap_server_fsm) == 0);
}
