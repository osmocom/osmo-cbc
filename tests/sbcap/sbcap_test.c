#include <osmocom/core/application.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/sbcap/sbcap_common.h>

/* 3GPP TS 36.413 9.2.1.53 */
#define SBCAP_WARN_MSG_CONTENTS_IE_MAX_LEN 9600

void test_asn1c_enc(void)
{
	struct msgb *msg;
	SBcAP_SBC_AP_PDU_t *pdu;
	SBcAP_Write_Replace_Warning_Request_IEs_t *ie;
	uint8_t ie_warning_type[2] = {(0x01 << 1) | 0x01, 0x80};
	uint8_t ie_dcs = 2;
	uint8_t ie_warning_sec_info[50] = {0x30, 0x40, 0x12, 0x23, 0x45};
	uint8_t ie_warning_msg_content[SBCAP_WARN_MSG_CONTENTS_IE_MAX_LEN] = {0x30, 0x40, 0x12, 0x23, 0x45};

	static uint8_t ie_message_identifier[] = {0xab, 0x01};
	static uint8_t ie_serial_number[] = {0xab, 0xcd};

	printf("==== %s ====\n", __func__);

	pdu = sbcap_pdu_alloc();
	pdu->present = SBcAP_SBC_AP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage.procedureCode = SBcAP_ProcedureId_Write_Replace_Warning;
	pdu->choice.initiatingMessage.criticality = SBcAP_Criticality_reject;
	pdu->choice.initiatingMessage.value.present = SBcAP_InitiatingMessage__value_PR_Write_Replace_Warning_Request;

	A_SEQUENCE_OF(void) *as_pdu = (void *)&pdu->choice.initiatingMessage.value.choice.Write_Replace_Warning_Request.protocolIEs.list;

	/* static const long asn_VAL_1_SBcAP_id_Message_Identifier = 5; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(5, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Message_Identifier);
	ie->value.choice.Message_Identifier.buf = MALLOC(sizeof(ie_message_identifier));
	ie->value.choice.Message_Identifier.size = sizeof(ie_message_identifier);
	ie->value.choice.Message_Identifier.bits_unused = 0;
	memcpy(ie->value.choice.Message_Identifier.buf, ie_message_identifier, sizeof(ie_message_identifier));
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* static const long asn_VAL_2_SBcAP_id_Serial_Number = 11; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(11, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Serial_Number);
	ie->value.choice.Serial_Number.buf = MALLOC(sizeof(ie_serial_number));
	ie->value.choice.Serial_Number.size = sizeof(ie_serial_number);
	ie->value.choice.Serial_Number.bits_unused = 0;
	memcpy(ie->value.choice.Serial_Number.buf, ie_serial_number, sizeof(ie_serial_number));
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* static const long asn_VAL_5_SBcAP_id_Repetition_Period = 10; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(10, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Repetition_Period);
	ie->value.choice.Repetition_Period = 30; /*seconds */
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* static const long asn_VAL_7_SBcAP_id_Number_of_Broadcasts_Requested = 7; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(7, SBcAP_Criticality_reject,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Number_of_Broadcasts_Requested);
	ie->value.choice.Number_of_Broadcasts_Requested = 89;
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* Warning Type, 3GPP TS 36.413 sec 9.2.1.50: */
	/* static const long asn_VAL_8_SBcAP_id_Warning_Type = 18; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(18, SBcAP_Criticality_ignore,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Type);
	ie->value.choice.Warning_Type.buf = MALLOC(sizeof(ie_warning_type));
	ie->value.choice.Warning_Type.size = sizeof(ie_warning_type);
	memcpy(ie->value.choice.Warning_Type.buf, &ie_warning_type, sizeof(ie_warning_type));
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* Warning Security Information, 3GPP TS 36.413 sec 9.2.1.51: */
	/*static const long asn_VAL_9_SBcAP_id_Warning_Security_Information = 17 */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(17, SBcAP_Criticality_ignore,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Security_Information);
	ie->value.choice.Warning_Security_Information.buf = MALLOC(sizeof(ie_warning_sec_info));
	ie->value.choice.Warning_Security_Information.size = sizeof(ie_warning_sec_info);
	memcpy(ie->value.choice.Warning_Security_Information.buf, ie_warning_sec_info, sizeof(ie_warning_sec_info));
	ASN_SEQUENCE_ADD(as_pdu, ie);


	/* static const long asn_VAL_10_SBcAP_id_Data_Coding_Scheme = 3; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(3, SBcAP_Criticality_ignore,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Data_Coding_Scheme);
	ie->value.choice.Data_Coding_Scheme.buf = MALLOC(sizeof(ie_dcs));
	ie->value.choice.Data_Coding_Scheme.size = sizeof(ie_dcs);
	ie->value.choice.Data_Coding_Scheme.bits_unused = 0;
	memcpy(ie->value.choice.Data_Coding_Scheme.buf, &ie_dcs, sizeof(ie_dcs));
	ASN_SEQUENCE_ADD(as_pdu, ie);

	/* 3GPP TS 36.413 9.2.1.53 Warning Message Contents */
	/* static const long asn_VAL_11_SBcAP_id_Warning_Message_Content = 16; */
	ie = sbcap_alloc_Write_Replace_Warning_Request_IE(16, SBcAP_Criticality_ignore,
		SBcAP_Write_Replace_Warning_Request_IEs__value_PR_Warning_Message_Content);
	ie->value.choice.Warning_Message_Content.buf = MALLOC(sizeof(ie_warning_msg_content));
	ie->value.choice.Warning_Message_Content.size = 20;
	memcpy(ie->value.choice.Warning_Message_Content.buf, ie_warning_msg_content, sizeof(ie_warning_msg_content));
	ASN_SEQUENCE_ADD(as_pdu, ie);

	msg = sbcap_encode(pdu);
	ASN_STRUCT_FREE(asn_DEF_SBcAP_SBC_AP_PDU, pdu);
	OSMO_ASSERT(msg);

	printf("Encoded message: %s\n", msgb_hexdump(msg));

	msgb_free(msg);
}

static void test_asn1c_dec(void)
{
	asn_dec_rval_t rval;
	SBcAP_SBC_AP_PDU_t *pdu = sbcap_pdu_alloc();
	SBcAP_Write_Replace_Warning_Response_IEs_t *ie;
	SBcAP_Message_Identifier_t *msg_id_ie;
	SBcAP_Serial_Number_t *serial_nr_ie;

	printf("==== %s ====\n", __func__);
/*
SBc Application Part
 SBC-AP-PDU: successfulOutcome (1)
  successfulOutcome
   procedureCode: id-Write-Replace-Warning (0)
   criticality: reject (0)
   value
    Write-Replace-Warning-Response
  protocolIEs: 3 items
   Item 0: id-Message-Identifier
    ProtocolIE-Field
  id: id-Message-Identifier (5)
  criticality: reject (0)
     value
   Message-Identifier: Unknown (43)
   Item 1: id-Serial-Number
    ProtocolIE-Field
  id: id-Serial-Number (11)
  criticality: reject (0)
  value
   Serial-Number: 4170 [bit length 16, 0100 0001  0111 0000 decimal value 16752]
    01.. .... .... .... = Geographical Scope: Display mode normal, PLMN wide (1)
    ..00 0001 0111 .... = Message Code: 23
    .... .... .... 0000 = Update Number: 0
   Item 2: id-Cause
    ProtocolIE-Field
  id: id-Cause (1)
  criticality: reject (0)
     value
      Cause: message-accepted (0)
*/
	uint8_t write_replace_warning_resp[] = {
		0x20, 0x00, 0x00, 0x14, 0x00, 0x00, 0x03, 0x00, 0x05, 0x00, 0x02, 0x00,
		0x2b, 0x00, 0x0b, 0x00, 0x02, 0x41, 0x70, 0x00, 0x01, 0x00, 0x01, 0x00
	};
	printf("Decoding message: %s\n",
		osmo_hexdump(write_replace_warning_resp, sizeof(write_replace_warning_resp)));
	rval = aper_decode_complete(NULL, &asn_DEF_SBcAP_SBC_AP_PDU,
			(void **)&pdu, write_replace_warning_resp, sizeof(write_replace_warning_resp));
	OSMO_ASSERT(rval.code == RC_OK);
	OSMO_ASSERT(pdu);

	OSMO_ASSERT(pdu->present == SBcAP_SBC_AP_PDU_PR_successfulOutcome);
	OSMO_ASSERT(pdu->choice.successfulOutcome.procedureCode == SBcAP_ProcedureId_Write_Replace_Warning);
	OSMO_ASSERT(pdu->choice.successfulOutcome.criticality == SBcAP_Criticality_reject);

	A_SEQUENCE_OF(void) *as_pdu = NULL;
	as_pdu = (void *)&pdu->choice.successfulOutcome.value.choice.Write_Replace_Warning_Response.protocolIEs.list;
	OSMO_ASSERT(as_pdu);
	OSMO_ASSERT(as_pdu->count == 3);

	/* Message-Identifier: */
	ie = ((SBcAP_Write_Replace_Warning_Response_IEs_t *)(as_pdu->array[0]));
	OSMO_ASSERT(ie);
	OSMO_ASSERT(ie->id == 5);
	OSMO_ASSERT(ie->criticality == 0);
	OSMO_ASSERT(ie->value.present == SBcAP_Write_Replace_Warning_Response_IEs__value_PR_Message_Identifier);
	msg_id_ie = &ie->value.choice.Message_Identifier;
	OSMO_ASSERT(msg_id_ie->size == 2);
	OSMO_ASSERT(osmo_load16be(msg_id_ie->buf) == 43);

	/* Serial-Number: */
	ie = ((SBcAP_Write_Replace_Warning_Response_IEs_t *)(as_pdu->array[1]));
	OSMO_ASSERT(ie);
	OSMO_ASSERT(ie->id == 11);
	OSMO_ASSERT(ie->criticality == 0);
	OSMO_ASSERT(ie->value.present == SBcAP_Write_Replace_Warning_Response_IEs__value_PR_Serial_Number);
	serial_nr_ie = &ie->value.choice.Serial_Number;
	OSMO_ASSERT(serial_nr_ie->size == 2);
	OSMO_ASSERT(serial_nr_ie->buf[0] == 0x41 && serial_nr_ie->buf[1] == 0x70);

	/* Cause: */
	ie = ((SBcAP_Write_Replace_Warning_Response_IEs_t *)(as_pdu->array[2]));
	OSMO_ASSERT(ie);
	OSMO_ASSERT(ie->id == 1);
	OSMO_ASSERT(ie->criticality == 0);
	OSMO_ASSERT(ie->value.present == SBcAP_Write_Replace_Warning_Response_IEs__value_PR_Cause);
	OSMO_ASSERT(ie->value.choice.Cause == 0);

	sbcap_pdu_free(pdu);
	printf("Decoded message successfully\n");
}

static const struct log_info_cat log_categories[] = {
	[0] = {
		.name = "DMAIN",
		.description = "main category",
		.color = "\033[1;32m",
		.enabled = 1,
		.loglevel = LOGL_DEBUG,
	},
};

const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "mgcp_test");
	void *msgb_ctx = msgb_talloc_ctx_init(ctx, 0);
	osmo_init_logging2(ctx, &log_info);
	sbcap_set_log_area(0, 0);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_use_color(osmo_stderr_target, 0);

	test_asn1c_enc();
	test_asn1c_dec();

	OSMO_ASSERT(talloc_total_size(msgb_ctx) == 0);
	OSMO_ASSERT(talloc_total_blocks(msgb_ctx) == 1);
	talloc_free(msgb_ctx);
	printf("Done\n");
	return EXIT_SUCCESS;
}
