/* Osmocom CBC (Cell Broacast Centre) */

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


#include <string.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/sbcap/sbcap_common.h>

#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/debug.h>

/* 3GPP TS 36.413 9.2.1.53, 3GPP TS 23.041 9.3.35 */
#define SBCAP_WARN_MSG_CONTENTS_IE_MAX_LEN 9600

#if 0
/* Warning Area List
 * 3GPP TS 36.413 9.2.1.46, 3GPP TS 23.041 9.3.30
 */
static void msgb_put_sbcap_cell_list(const struct cbc_message *cbcmsg, void *void_li)
{
	static uint8_t ie_plm_id0[] = {0x05, 0xf5, 0x32};
	static uint8_t ie_cell_id0[] = {0xa0, 0x00, 0x00, 0x10};
	static uint8_t ie_cell_id1[] = {0xa0, 0x00, 0x00, 0x20};
	SBcAP_EUTRAN_CGI_t *ecgi;
	A_SEQUENCE_OF(void) *li = void_li;

	ecgi = CALLOC(1, sizeof(*ecgi));
	*ecgi = (SBcAP_EUTRAN_CGI_t) {
		.pLMNidentity = {
			.buf = ie_plm_id0,
			.size = sizeof(ie_plm_id0),
		},
		.cell_ID = { /* SBcAP_CellIdentity_t*/
			.buf = ie_cell_id0,
			.size = sizeof(ie_cell_id0),
			.bits_unused = 4,
		}
	};
	ASN_SEQUENCE_ADD(li, ecgi);

	ecgi = CALLOC(1, sizeof(*ecgi));
	*ecgi = (SBcAP_EUTRAN_CGI_t) {
		.pLMNidentity = {
			.buf = ie_plm_id0,
			.size = sizeof(ie_plm_id0),
		},
		.cell_ID = { /* SBcAP_CellIdentity_t*/
			.buf = ie_cell_id1,
			.size = sizeof(ie_cell_id1),
			.bits_unused = 4,
		}
	};
	ASN_SEQUENCE_ADD(li, ecgi);

}
#endif

/* generate a SBc-AP WRITE-REPLACE WARNING REQUEST from our internal representation.
 * 3GPP TS 36.413 9.1.13.1
 */
SBcAP_SBC_AP_PDU_t *sbcap_gen_write_replace_warning_req(void *ctx, const struct cbc_message *cbcmsg)
{
	const struct smscb_message *smscb = &cbcmsg->msg;
	SBcAP_SBC_AP_PDU_t *pdu;
	SBcAP_Write_Replace_Warning_Request_IEs_t *ie;
	unsigned int i;
	uint8_t *ptr;
#if 0
	A_SEQUENCE_OF(void) *as_warn_area_ecgi = NULL;
#endif

	pdu = sbcap_pdu_alloc();
	if (!pdu)
		return NULL;
	pdu->present = SBcAP_SBC_AP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage.procedureCode = SBcAP_ProcedureId_Write_Replace_Warning;
	pdu->choice.initiatingMessage.criticality = SBcAP_Criticality_reject;
	pdu->choice.initiatingMessage.value.present = SBcAP_InitiatingMessage__value_PR_Write_Replace_Warning_Request;

	A_SEQUENCE_OF(void) *as_pdu = (void *)&pdu->choice.initiatingMessage.value.choice.Write_Replace_Warning_Request.protocolIEs.list;

	/* Message Identifier:
	 * 3GPP TS 36.413 9.2.1.44, 3GPP TS 23.041 9.4.1.3.6
	 * static const long asn_VAL_1_SBcAP_id_Message_Identifier = 5; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(5, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Message_Identifier);
	ie->value.choice.Message_Identifier.buf = MALLOC(sizeof(uint16_t));
	ie->value.choice.Message_Identifier.size = sizeof(uint16_t);
	ie->value.choice.Message_Identifier.bits_unused = 0;
	osmo_store16be(smscb->message_id, ie->value.choice.Message_Identifier.buf);
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* Serial Number
	 * 3GPP TS 36.413 9.2.1.45, 3GPP TS 23.041 9.4.1.2.1
	 * static const long asn_VAL_2_SBcAP_id_Serial_Number = 11; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(11, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Serial_Number);
	ie->value.choice.Serial_Number.buf = MALLOC(sizeof(uint16_t));
	ie->value.choice.Serial_Number.size = sizeof(uint16_t);
	ie->value.choice.Serial_Number.bits_unused = 0;
	osmo_store16be(smscb->serial_nr, ie->value.choice.Serial_Number.buf);
	ASN_SEQUENCE_ADD(as_pdu, ie);

	switch (cbcmsg->scope) {
	case CBC_MSG_SCOPE_PLMN:
		break; /* Nothing to be done :*/
#if 0
	case CBC_MSG_SCOPE_EUTRAN_CGI:
		/* Warning Area List
		 * 3GPP TS 36.413 9.2.1.46, 3GPP TS 23.041 9.3.30
		 * static const long asn_VAL_25_SBcAP_id_Warning_Area_List = 15; */
		ie = sbcap_alloc_Write_Replace_Warning_Request_IE(15, SBcAP_Criticality_ignore,
			SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Area_List);
		ASN_SEQUENCE_ADD(as_pdu, ie);
		as_warn_area_ecgi = (void *)ie->value.choice.Warning_Area_List.choice.cell_ID_List.list;
		msgb_put_sbcap_cell_list(cbcmsg, as_warn_area_ecgi);
		break;
#endif
	default:
		OSMO_ASSERT(0);
	}

	/* Repetition Period
	 * 3GPP TS 36.413 9.2.1.48, 3GPP TS 23.041 9.3.8
	 * static const long asn_VAL_5_SBcAP_id_Repetition_Period = 10; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(10, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Repetition_Period);
	ie->value.choice.Repetition_Period = cbcmsg->rep_period; /*seconds */
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* Number of Broadcasts Requested
	 * 3GPP TS 36.413 9.2.1.49, 3GPP TS 23.041 9.3.9
	 * static const long asn_VAL_7_SBcAP_id_Number_of_Broadcasts_Requested = 7; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(7, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Number_of_Broadcasts_Requested);
	ie->value.choice.Number_of_Broadcasts_Requested = cbcmsg->num_bcast;
	ASN_SEQUENCE_ADD(as_pdu, ie);

	if (smscb->is_etws) {
		/* Warning Type
		 * 3GPP TS 36.413 sec 9.2.1.50, 3GPP TS 23.041 9.3.24
		 * static const long asn_VAL_8_SBcAP_id_Warning_Type = 18; */
		ie = sbcap_alloc_Write_Replace_Warning_Request_IE(18, SBcAP_Criticality_ignore,
			SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Type);
		ie->value.choice.Warning_Type.buf = MALLOC(2);
		ie->value.choice.Warning_Type.size = 2;
		ie->value.choice.Warning_Type.buf[0] = ((smscb->etws.warning_type & 0x7f) << 1);
		if (smscb->etws.user_alert)
			ie->value.choice.Warning_Type.buf[0] |= 0x01;
		ie->value.choice.Warning_Type.buf[1] = (smscb->etws.popup_on_display) ? 0x80 : 0x0;
		ASN_SEQUENCE_ADD(as_pdu, ie);

		/* Warning Security Information
		 * 3GPP TS 36.413 sec 9.2.1.51, 3GPP TS 23.041 9.3.25
		 * static const long asn_VAL_9_SBcAP_id_Warning_Security_Information = 17 */
		ie = sbcap_alloc_Write_Replace_Warning_Request_IE(17, SBcAP_Criticality_ignore,
			SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Security_Information);
		ie->value.choice.Warning_Security_Information.buf = MALLOC(sizeof(smscb->etws.warning_sec_info));
		ie->value.choice.Warning_Security_Information.size = sizeof(smscb->etws.warning_sec_info);
		memcpy(ie->value.choice.Warning_Security_Information.buf,
		       smscb->etws.warning_sec_info, sizeof(smscb->etws.warning_sec_info));
		ASN_SEQUENCE_ADD(as_pdu, ie);

	} else {
		/* Data Coding Scheme
		 * 3GPP TS 36.413 9.2.1.52, 3GPP TS 23.041 9.4.1.2.3
		 * static const long asn_VAL_10_SBcAP_id_Data_Coding_Scheme = 3; */
		ie = sbcap_alloc_Write_Replace_Warning_Request_IE(3, SBcAP_Criticality_ignore,
			SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Data_Coding_Scheme);
		ie->value.choice.Data_Coding_Scheme.buf = MALLOC(1);
		ie->value.choice.Data_Coding_Scheme.size = 1;
		ie->value.choice.Data_Coding_Scheme.bits_unused = 0;
		*ie->value.choice.Data_Coding_Scheme.buf = smscb->cbs.dcs;
		ASN_SEQUENCE_ADD(as_pdu, ie);

		/* Warning Message Contents
		 * 3GPP TS 36.413 9.2.1.53, 3GPP TS 23.041 9.3.35
		 * static const long asn_VAL_11_SBcAP_id_Warning_Message_Content = 16; */
		ie = sbcap_alloc_Write_Replace_Warning_Request_IE(16, SBcAP_Criticality_ignore,
			SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Message_Content);
		ie->value.choice.Warning_Message_Content.buf = MALLOC(1 + smscb->cbs.num_pages * (SMSCB_RAW_PAGE_LEN+1));
		ie->value.choice.Warning_Message_Content.size = 1 + smscb->cbs.num_pages * (SMSCB_RAW_PAGE_LEN+1);
		ptr = &ie->value.choice.Warning_Message_Content.buf[0];
		*ptr = (uint8_t)smscb->cbs.num_pages;
		ptr++;
		for (i = 0; i < smscb->cbs.num_pages; i++) {
			unsigned len = 0;
			if (i == smscb->cbs.num_pages - 1)
				len = smscb->cbs.data_user_len - (i * SMSCB_RAW_PAGE_LEN);
			else
				len = SMSCB_RAW_PAGE_LEN;
			if (len > 0) {
				memcpy(ptr, smscb->cbs.data[i], SMSCB_RAW_PAGE_LEN);
				ptr += SMSCB_RAW_PAGE_LEN;
			}
			*ptr = (uint8_t)len;
			ptr++;
		}
		ASN_SEQUENCE_ADD(as_pdu, ie);
	}

	/* Send Write-Replace-Warning-Indication
	 * 3GPP TS 36.413 4.3.4.3.5, 3GPP TS 23.041 9.3.39
	 * static const long asn_VAL_14_SBcAP_id_Send_Write_Replace_Warning_Indication = 24; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(24, SBcAP_Criticality_ignore,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Send_Write_Replace_Warning_Indication);
	ie->value.choice.Send_Write_Replace_Warning_Indication = SBcAP_Send_Write_Replace_Warning_Indication_true;
	ASN_SEQUENCE_ADD(as_pdu, ie);

	return pdu;
}

/* generate a SBc-AP WRITE-REPLACE WARNING REQUEST from our internal representation */
SBcAP_SBC_AP_PDU_t *sbcap_gen_stop_warning_req(void *ctx, const struct cbc_message *cbcmsg)
{
	const struct smscb_message *smscb = &cbcmsg->msg;
	SBcAP_SBC_AP_PDU_t *pdu;
	SBcAP_Stop_Warning_Request_IEs_t *ie;
#if 0
	A_SEQUENCE_OF(void) *as_warn_area_ecgi = NULL;
#endif

	pdu = sbcap_pdu_alloc();
	if (!pdu)
		return NULL;
	pdu->present = SBcAP_SBC_AP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage.procedureCode = SBcAP_ProcedureId_Stop_Warning;
	pdu->choice.initiatingMessage.criticality = SBcAP_Criticality_reject;
	pdu->choice.initiatingMessage.value.present = SBcAP_InitiatingMessage__value_PR_Stop_Warning_Request;

	A_SEQUENCE_OF(void) *as_pdu = (void *)&pdu->choice.initiatingMessage.value.choice.Stop_Warning_Request.protocolIEs.list;

	/* Message Identifier:
	 * 3GPP TS 36.413 9.2.1.44, 3GPP TS 23.041 9.4.1.3.6
	 * static const long asn_VAL_1_SBcAP_id_Message_Identifier = 5; */
	ie = sbcap_alloc_Stop_Warning_Request_IE(5, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Message_Identifier);
	ie->value.choice.Message_Identifier.buf = MALLOC(sizeof(uint16_t));
	ie->value.choice.Message_Identifier.size = sizeof(uint16_t);
	ie->value.choice.Message_Identifier.bits_unused = 0;
	osmo_store16be(smscb->message_id, ie->value.choice.Message_Identifier.buf);
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* Serial Number
	 * 3GPP TS 36.413 9.2.1.45, 3GPP TS 23.041 9.4.1.2.1
	 * static const long asn_VAL_2_SBcAP_id_Serial_Number = 11; */
	ie = sbcap_alloc_Stop_Warning_Request_IE(11, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Serial_Number);
	ie->value.choice.Serial_Number.buf = MALLOC(sizeof(uint16_t));
	ie->value.choice.Serial_Number.size = sizeof(uint16_t);
	ie->value.choice.Serial_Number.bits_unused = 0;
	osmo_store16be(smscb->serial_nr, ie->value.choice.Serial_Number.buf);
	ASN_SEQUENCE_ADD(as_pdu, ie);

	switch (cbcmsg->scope) {
	case CBC_MSG_SCOPE_PLMN:
		break; /* Nothing to be done :*/
#if 0
	case CBC_MSG_SCOPE_EUTRAN_CGI:
		/* Warning Area List
		 * 3GPP TS 36.413 9.2.1.46, 3GPP TS 23.041 9.3.30
		 * static const long asn_VAL_25_SBcAP_id_Warning_Area_List = 15; */
		ie = sbcap_alloc_Stop_Warning_Request_IE(15, SBcAP_Criticality_ignore,
			SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Area_List);
		ASN_SEQUENCE_ADD(as_pdu, ie);
		as_warn_area_ecgi = (void *)ie->value.choice.Warning_Area_List.choice.cell_ID_List.list;
		msgb_put_sbcap_cell_list(cbcmsg, as_warn_area_ecgi);
		break;
#endif
	default:
		OSMO_ASSERT(0);
	}

	return pdu;
}

/* generate a SBc-AP ERROR INDICATION, 3GPP TS 29.168 4.3.4.2A.1.
 * rx_pdu can be NULL.
 */
SBcAP_SBC_AP_PDU_t *sbcap_gen_error_ind(void *ctx, SBcAP_Cause_t cause, SBcAP_SBC_AP_PDU_t *rx_pdu)
{
	SBcAP_SBC_AP_PDU_t *pdu;
	SBcAP_ErrorIndicationIEs_t *ie;

	pdu = sbcap_pdu_alloc();
	if (!pdu)
		return NULL;
	pdu->present = SBcAP_SBC_AP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage.procedureCode = SBcAP_ProcedureId_Error_Indication;
	pdu->choice.initiatingMessage.criticality = SBcAP_Criticality_ignore;
	pdu->choice.initiatingMessage.value.present = SBcAP_InitiatingMessage__value_PR_Error_Indication;

	A_SEQUENCE_OF(void) *as_pdu = (void *)&pdu->choice.initiatingMessage.value.choice.Error_Indication.protocolIEs.list;

	/* Cause, Optional:
	 * 3GPP TS 36.413 4.3.4.3.2
	 * static const long asn_VAL_19_SBcAP_id_Cause = 1; */
	ie = sbcap_alloc_Error_Indication_IE(1, SBcAP_Criticality_ignore,
		SBcAP_ErrorIndicationIEs__value_PR_Cause);
	ie->value.choice.Cause = cause;
	ASN_SEQUENCE_ADD(as_pdu, ie);

	if (rx_pdu) {
		SBcAP_Criticality_Diagnostics_t *diag_ie;
		/* Criticality Diagnostics, Optional:
		 * 3GPP TS 36.413 4.3.4.3.3
		 * static const long asn_VAL_20_SBcAP_id_Criticality_Diagnostics = 2; */
		ie = sbcap_alloc_Error_Indication_IE(1, SBcAP_Criticality_ignore,
			SBcAP_ErrorIndicationIEs__value_PR_Criticality_Diagnostics);
		diag_ie = &ie->value.choice.Criticality_Diagnostics;
		diag_ie->procedureCode = MALLOC(sizeof(*diag_ie->procedureCode));
		*diag_ie->procedureCode = sbcap_pdu_get_procedure_code(rx_pdu);
		diag_ie->triggeringMessage = MALLOC(sizeof(*diag_ie->triggeringMessage));
		*diag_ie->triggeringMessage = rx_pdu->present;
		diag_ie->procedureCriticality = MALLOC(sizeof(*diag_ie->procedureCriticality));
		*diag_ie->procedureCriticality = sbcap_pdu_get_criticality(rx_pdu);
		ASN_SEQUENCE_ADD(as_pdu, ie);
	}
	return pdu;
}
static void cci_from_sbcap_ecgi(struct cbc_cell_id *cci, const SBcAP_EUTRAN_CGI_t *eCGI)
{
	cci->id_discr = CBC_CELL_ID_ECGI;
	cci->u.ecgi.eci = (osmo_load32be(&eCGI->cell_ID.buf[0]) >> 4);
	osmo_plmn_from_bcd(eCGI->pLMNidentity.buf, &cci->u.ecgi.plmn);
}

/* Fill a cbc_cell_id from a SBcAP_CellId_Broadcast_List_Item */
void cci_from_sbcap_bcast_cell_id(struct cbc_cell_id *cci, const SBcAP_CellId_Broadcast_List_Item_t *it)
{
	cci_from_sbcap_ecgi(cci, &it->eCGI);
}

/* Fill a cbc_cell_id from a SBcAP_TAI_t */
void cci_from_sbcap_tai(struct cbc_cell_id *cci, const SBcAP_TAI_t *tai)
{
	cci->id_discr = CBC_CELL_ID_TAI;
	cci->u.tai.tac = osmo_load16be(tai->tAC.buf);
	osmo_plmn_from_bcd(tai->pLMNidentity.buf, &cci->u.tai.plmn);
}
