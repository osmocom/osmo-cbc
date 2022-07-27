/* common SBC-AP Code */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
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


#include <stdint.h>

#include <osmocom/core/msgb.h>

#include <osmocom/sbcap/sbcap_common.h>

extern int asn1_xer_print;

int _sbcap_DSBCAP = 0;
int _sbcap_DASN1C = 0;
#define DSBCAP _sbcap_DSBCAP
#define DASN1C _sbcap_DASN1C

static const struct value_string sbcap_procedure_code_vals[] = {
	{ SBcAP_ProcedureId_Write_Replace_Warning,		"Write-Replace-Warning" },
	{ SBcAP_ProcedureId_Stop_Warning,			"Stop-Warning" },
	{ SBcAP_ProcedureId_Error_Indication,			"Error-Indication" },
	{ SBcAP_ProcedureId_Write_Replace_Warning_Indication,	"Write-Replace-Warning-Indication" },
	{ SBcAP_ProcedureId_Stop_Warning_Indication,		"Stop-Warning-Indication" },
	{ SBcAP_ProcedureId_PWS_Restart_Indication,		"PWS-Restart-Indication" },
	{ SBcAP_ProcedureId_PWS_Failure_Indication,		"PWS-Failure-Indication" },
	{ 0, NULL }
};

const char *sbcap_procedure_code_str(SBcAP_ProcedureCode_t pc)
{
	return get_value_string(sbcap_procedure_code_vals, pc);
}

static const struct value_string sbcap_cause_vals[] = {
	{ SBcAP_Cause_message_accepted,				"message accepted" },
	{ SBcAP_Cause_parameter_not_recognised,			"parameter not recognised" },
	{ SBcAP_Cause_parameter_value_invalid,			"parameter value invalid" },
	{ SBcAP_Cause_valid_message_not_identified,		"valid message not identified" },
	{ SBcAP_Cause_tracking_area_not_valid,			"Tracking Area not valid" },
	{ SBcAP_Cause_unrecognised_message,			"unrecognised message" },
	{ SBcAP_Cause_missing_mandatory_element,		"missing mandatory element" },
	{ SBcAP_Cause_mME_capacity_exceeded,			"MME capacity exceeded" },
	{ SBcAP_Cause_mME_memory_exceeded,			"MME memory exceeded" },
	{ SBcAP_Cause_warning_broadcast_not_supported,		"warning broadcast not supported" },
	{ SBcAP_Cause_warning_broadcast_not_operational,	"warning broadcast not operational" },
	{ SBcAP_Cause_message_reference_already_used,		"message reference already used" },
	{ SBcAP_Cause_unspecifed_error,				"unspecified error" },
	{ SBcAP_Cause_transfer_syntax_error,			"transfer syntax error" },
	{ SBcAP_Cause_semantic_error,				"semantic error" },
	{ SBcAP_Cause_message_not_compatible_with_receiver_state,	"message not compatible with receiver state" },
	{ SBcAP_Cause_abstract_syntax_error_reject,			"abstract syntax error reject" },
	{ SBcAP_Cause_abstract_syntax_error_ignore_and_notify,		"abstract syntax error ignore and notify" },
	{ SBcAP_Cause_abstract_syntax_error_falsely_constructed_message,	"abstract syntax error falsely constructed message" },
	{ 0, NULL }
};

const char *sbcap_cause_str(SBcAP_Cause_t cause)
{
	return get_value_string_or_null(sbcap_cause_vals, cause);
}


static struct msgb *sbcap_msgb_alloc(void)
{
	return msgb_alloc(1024, "SBC_AP Tx");
}

struct msgb *sbcap_encode(SBcAP_SBC_AP_PDU_t *pdu)
{
	struct msgb *msg = sbcap_msgb_alloc();
	asn_enc_rval_t rval;

	if (!msg)
		return NULL;

	rval = aper_encode_to_buffer(&asn_DEF_SBcAP_SBC_AP_PDU, NULL, pdu,
				     msgb_data(msg), msgb_tailroom(msg));
	if (rval.encoded < 0) {
		LOGP(DSBCAP, LOGL_ERROR, "%s: Error encoding type: %s\n",
		     sbcap_pdu_get_name(pdu),
		     rval.failed_type->name);
		msgb_free(msg);
		return NULL;
	}

	msgb_put(msg, rval.encoded/8);

	return msg;
}

SBcAP_SBC_AP_PDU_t *sbcap_decode(const struct msgb *msg)
{
	asn_dec_rval_t rval;
	SBcAP_SBC_AP_PDU_t *pdu = sbcap_pdu_alloc();
	rval = aper_decode_complete(NULL, &asn_DEF_SBcAP_SBC_AP_PDU, (void **)&pdu,
				    msgb_data(msg), msgb_length(msg));
	if (rval.code != RC_OK) {
		LOGP(DSBCAP, LOGL_ERROR, "Error decoding code=%d\n", rval.code);
		return NULL;
	}
	LOGP(DSBCAP, LOGL_DEBUG, "Decoded %s\n", sbcap_pdu_get_name(pdu));
	return pdu;
}

SBcAP_SBC_AP_PDU_t *sbcap_pdu_alloc(void)
{
	SBcAP_SBC_AP_PDU_t *pdu;
	pdu = CALLOC(1, sizeof(*pdu));
	return pdu;
}

void sbcap_pdu_free(SBcAP_SBC_AP_PDU_t *pdu)
{
	ASN_STRUCT_FREE(asn_DEF_SBcAP_SBC_AP_PDU, pdu);
}

SBcAP_ProcedureCode_t sbcap_pdu_get_procedure_code(const SBcAP_SBC_AP_PDU_t *pdu)
{
	switch (pdu->present) {
	case SBcAP_SBC_AP_PDU_PR_initiatingMessage:
		return pdu->choice.initiatingMessage.procedureCode;
	case SBcAP_SBC_AP_PDU_PR_successfulOutcome:
		return pdu->choice.successfulOutcome.procedureCode;
	case SBcAP_SBC_AP_PDU_PR_unsuccessfulOutcome:
		return pdu->choice.unsuccessfulOutcome.procedureCode;
	case SBcAP_SBC_AP_PDU_PR_NOTHING:
	default:
		return -1;
	}
}

SBcAP_Criticality_t sbcap_pdu_get_criticality(const SBcAP_SBC_AP_PDU_t *pdu)
{
	switch (pdu->present) {
	case SBcAP_SBC_AP_PDU_PR_initiatingMessage:
		return pdu->choice.initiatingMessage.criticality;
	case SBcAP_SBC_AP_PDU_PR_successfulOutcome:
		return pdu->choice.successfulOutcome.criticality;
	case SBcAP_SBC_AP_PDU_PR_unsuccessfulOutcome:
		return pdu->choice.unsuccessfulOutcome.criticality;
	case SBcAP_SBC_AP_PDU_PR_NOTHING:
	default:
		return -1;
	}
}

const char *sbcap_pdu_get_name(const SBcAP_SBC_AP_PDU_t *pdu)
{
	static char pdu_name[256] = "<unknown>";
	struct osmo_strbuf sb = { .buf = pdu_name, .len = sizeof(pdu_name) };
	SBcAP_ProcedureCode_t pc = sbcap_pdu_get_procedure_code(pdu);

	OSMO_STRBUF_PRINTF(sb, "%s", sbcap_procedure_code_str(pc));

	switch (pc) {
	case SBcAP_ProcedureId_Write_Replace_Warning:
	case SBcAP_ProcedureId_Stop_Warning:
		OSMO_STRBUF_PRINTF(sb, "%s",
				   pdu->present == SBcAP_SBC_AP_PDU_PR_initiatingMessage
				   ? "-Request" : "-Response");
		break;
	default:
		break;
	}
	return pdu_name;
}

void *sbcap_as_find_ie(void *void_list, SBcAP_ProtocolIE_ID_t ie_id)
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

void sbcap_set_log_area(int log_area_sbcap, int log_area_asn1c)
{
	_sbcap_DSBCAP = log_area_sbcap;
	_sbcap_DASN1C = log_area_asn1c;
}

SBcAP_Write_Replace_Warning_Request_IEs_t *sbcap_alloc_Write_Replace_Warning_Request_IE(
	long id, SBcAP_Criticality_t criticality, SBcAP_Write_Replace_Warning_Request_IEs__value_PR present)
{
	SBcAP_Write_Replace_Warning_Request_IEs_t *ie = CALLOC(1, sizeof(*ie));
	ie->id = id;
	ie->criticality = criticality;
	ie->value.present = present;
	return ie;
}

SBcAP_Stop_Warning_Request_IEs_t *sbcap_alloc_Stop_Warning_Request_IE(
	long id, SBcAP_Criticality_t criticality, SBcAP_Stop_Warning_Request_IEs__value_PR present)
{
	SBcAP_Stop_Warning_Request_IEs_t *ie = CALLOC(1, sizeof(*ie));
	ie->id = id;
	ie->criticality = criticality;
	ie->value.present = present;
	return ie;
}

SBcAP_ErrorIndicationIEs_t *sbcap_alloc_Error_Indication_IE(
	long id, SBcAP_Criticality_t criticality, SBcAP_Stop_Warning_Request_IEs__value_PR present)
{
	SBcAP_ErrorIndicationIEs_t *ie = CALLOC(1, sizeof(*ie));
	ie->id = id;
	ie->criticality = criticality;
	ie->value.present = present;
	return ie;
}
