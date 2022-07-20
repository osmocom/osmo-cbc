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
#define DSBCAP _sbcap_DSBCAP

static const struct value_string sbcap_cause_vals[] = {
	{ SBcAP_Cause_message_accepted,				"message accepted" },
	{ SBcAP_Cause_parameter_not_recognised,			"parameter not recognised" },
	{ SBcAP_Cause_parameter_value_invalid,			"parameter value invalid" },
	{ SBcAP_Cause_valid_message_not_identified,		"valid message not identified" },
	{ SBcAP_Cause_tracking_area_not_valid,			"Tracking Area not valid" },
	{ SBcAP_Cause_unrecognised_message,			"unrecoznied message" },
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
		LOGP(DSBCAP, LOGL_ERROR, "Error encoding type: %s\n",
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

void sbcap_set_log_area(int log_area)
{
	_sbcap_DSBCAP = log_area;
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