#pragma once

#include <asn_application.h>

#include <osmocom/sbcap/SBcAP_Broadcast-Cancelled-Area-List-5GS.h>
#include <osmocom/sbcap/SBcAP_Broadcast-Cancelled-Area-List.h>
#include <osmocom/sbcap/SBcAP_Broadcast-Empty-Area-List-5GS.h>
#include <osmocom/sbcap/SBcAP_Broadcast-Empty-Area-List.h>
#include <osmocom/sbcap/SBcAP_Broadcast-Scheduled-Area-List-5GS.h>
#include <osmocom/sbcap/SBcAP_Broadcast-Scheduled-Area-List.h>
#include <osmocom/sbcap/SBcAP_CancelledCellinEAI.h>
#include <osmocom/sbcap/SBcAP_CancelledCellinEAI-Item.h>
#include <osmocom/sbcap/SBcAP_CancelledCellinTAI-5GS.h>
#include <osmocom/sbcap/SBcAP_CancelledCellinTAI.h>
#include <osmocom/sbcap/SBcAP_CancelledCellinTAI-Item.h>
#include <osmocom/sbcap/SBcAP_Cause.h>
#include <osmocom/sbcap/SBcAP_CellId-Broadcast-List-5GS.h>
#include <osmocom/sbcap/SBcAP_CellId-Broadcast-List.h>
#include <osmocom/sbcap/SBcAP_CellId-Broadcast-List-Item.h>
#include <osmocom/sbcap/SBcAP_CellID-Cancelled-Item.h>
#include <osmocom/sbcap/SBcAP_CellID-Cancelled-List-5GS.h>
#include <osmocom/sbcap/SBcAP_CellID-Cancelled-List.h>
#include <osmocom/sbcap/SBcAP_CellIdentity.h>
#include <osmocom/sbcap/SBcAP_Concurrent-Warning-Message-Indicator.h>
#include <osmocom/sbcap/SBcAP_Criticality-Diagnostics.h>
#include <osmocom/sbcap/SBcAP_CriticalityDiagnostics-IE-List.h>
#include <osmocom/sbcap/SBcAP_Criticality.h>
#include <osmocom/sbcap/SBcAP_Data-Coding-Scheme.h>
#include <osmocom/sbcap/SBcAP_ECGIList.h>
#include <osmocom/sbcap/SBcAP_EmergencyAreaID-Broadcast-List.h>
#include <osmocom/sbcap/SBcAP_EmergencyAreaID-Broadcast-List-Item.h>
#include <osmocom/sbcap/SBcAP_EmergencyAreaID-Cancelled-Item.h>
#include <osmocom/sbcap/SBcAP_EmergencyAreaID-Cancelled-List.h>
#include <osmocom/sbcap/SBcAP_Emergency-Area-ID.h>
#include <osmocom/sbcap/SBcAP_Emergency-Area-ID-List.h>
#include <osmocom/sbcap/SBcAP_ENB-ID.h>
#include <osmocom/sbcap/SBcAP_Error-Indication.h>
#include <osmocom/sbcap/SBcAP_EUTRAN-CGI.h>
#include <osmocom/sbcap/SBcAP_Extended-Repetition-Period.h>
#include <osmocom/sbcap/SBcAP_Failed-Cell-List.h>
#include <osmocom/sbcap/SBcAP_Failed-Cell-List-NR.h>
#include <osmocom/sbcap/SBcAP_Global-ENB-ID.h>
#include <osmocom/sbcap/SBcAP_Global-GNB-ID.h>
#include <osmocom/sbcap/SBcAP_Global-NgENB-ID.h>
#include <osmocom/sbcap/SBcAP_Global-RAN-Node-ID.h>
#include <osmocom/sbcap/SBcAP_GNB-ID.h>
#include <osmocom/sbcap/SBcAP_InitiatingMessage.h>
#include <osmocom/sbcap/SBcAP_List-of-5GS-Cells-for-Failure.h>
#include <osmocom/sbcap/SBcAP_List-of-5GS-TAI-for-Restart.h>
#include <osmocom/sbcap/SBcAP_List-of-5GS-TAIs.h>
#include <osmocom/sbcap/SBcAP_List-of-EAIs-Restart.h>
#include <osmocom/sbcap/SBcAP_List-of-TAIs.h>
#include <osmocom/sbcap/SBcAP_List-of-TAIs-Restart.h>
#include <osmocom/sbcap/SBcAP_Message-Identifier.h>
#include <osmocom/sbcap/SBcAP_NgENB-ID.h>
#include <osmocom/sbcap/SBcAP_NRCellIdentity.h>
#include <osmocom/sbcap/SBcAP_NR-CGI.h>
#include <osmocom/sbcap/SBcAP_NR-CGIList.h>
#include <osmocom/sbcap/SBcAP_NumberOfBroadcasts.h>
#include <osmocom/sbcap/SBcAP_Number-of-Broadcasts-Requested.h>
#include <osmocom/sbcap/SBcAP_Omc-Id.h>
#include <osmocom/sbcap/SBcAP_PLMNidentity.h>
#include <osmocom/sbcap/SBcAP_Presence.h>
#include <osmocom/sbcap/SBcAP_ProcedureCode.h>
#include <osmocom/sbcap/SBcAP_ProtocolExtensionContainer.h>
#include <osmocom/sbcap/SBcAP_ProtocolExtensionField.h>
#include <osmocom/sbcap/SBcAP_ProtocolExtensionID.h>
#include <osmocom/sbcap/SBcAP_ProtocolIE-Container.h>
#include <osmocom/sbcap/SBcAP_ProtocolIE-ContainerList.h>
#include <osmocom/sbcap/SBcAP_ProtocolIE-Field.h>
#include <osmocom/sbcap/SBcAP_ProtocolIE-ID.h>
#include <osmocom/sbcap/SBcAP_PWS-Failure-Indication.h>
#include <osmocom/sbcap/SBcAP_PWS-Restart-Indication.h>
#include <osmocom/sbcap/SBcAP_RAT-Selector-5GS.h>
#include <osmocom/sbcap/SBcAP_Repetition-Period.h>
#include <osmocom/sbcap/SBcAP_Restarted-Cell-List.h>
#include <osmocom/sbcap/SBcAP_Restarted-Cell-List-NR.h>
#include <osmocom/sbcap/SBcAP_SBC-AP-PDU.h>
#include <osmocom/sbcap/SBcAP_ScheduledCellinEAI.h>
#include <osmocom/sbcap/SBcAP_ScheduledCellinEAI-Item.h>
#include <osmocom/sbcap/SBcAP_ScheduledCellinTAI-5GS.h>
#include <osmocom/sbcap/SBcAP_ScheduledCellinTAI.h>
#include <osmocom/sbcap/SBcAP_ScheduledCellinTAI-Item.h>
#include <osmocom/sbcap/SBcAP_Send-Stop-Warning-Indication.h>
#include <osmocom/sbcap/SBcAP_Send-Write-Replace-Warning-Indication.h>
#include <osmocom/sbcap/SBcAP_Serial-Number.h>
#include <osmocom/sbcap/SBcAP_Stop-All-Indicator.h>
#include <osmocom/sbcap/SBcAP_Stop-Warning-Indication.h>
#include <osmocom/sbcap/SBcAP_Stop-Warning-Request.h>
#include <osmocom/sbcap/SBcAP_Stop-Warning-Response.h>
#include <osmocom/sbcap/SBcAP_SuccessfulOutcome.h>
#include <osmocom/sbcap/SBcAP_TAC-5GS.h>
#include <osmocom/sbcap/SBcAP_TAC.h>
#include <osmocom/sbcap/SBcAP_TAI-5GS.h>
#include <osmocom/sbcap/SBcAP_TAI-Broadcast-List-5GS.h>
#include <osmocom/sbcap/SBcAP_TAI-Broadcast-List.h>
#include <osmocom/sbcap/SBcAP_TAI-Broadcast-List-Item.h>
#include <osmocom/sbcap/SBcAP_TAI-Cancelled-List-5GS.h>
#include <osmocom/sbcap/SBcAP_TAI-Cancelled-List.h>
#include <osmocom/sbcap/SBcAP_TAI-Cancelled-List-Item.h>
#include <osmocom/sbcap/SBcAP_TAI.h>
#include <osmocom/sbcap/SBcAP_TAI-List-for-Warning.h>
#include <osmocom/sbcap/SBcAP_TBCD-STRING.h>
#include <osmocom/sbcap/SBcAP_TriggeringMessage.h>
#include <osmocom/sbcap/SBcAP_TypeOfError.h>
#include <osmocom/sbcap/SBcAP_Unknown-5GS-Tracking-Area-List.h>
#include <osmocom/sbcap/SBcAP_Unknown-Tracking-Area-List.h>
#include <osmocom/sbcap/SBcAP_UnsuccessfulOutcome.h>
#include <osmocom/sbcap/SBcAP_Warning-Area-Coordinates.h>
#include <osmocom/sbcap/SBcAP_Warning-Area-List-5GS.h>
#include <osmocom/sbcap/SBcAP_Warning-Area-List.h>
#include <osmocom/sbcap/SBcAP_Warning-Message-Content.h>
#include <osmocom/sbcap/SBcAP_Warning-Security-Information.h>
#include <osmocom/sbcap/SBcAP_Warning-Type.h>
#include <osmocom/sbcap/SBcAP_Write-Replace-Warning-Indication.h>
#include <osmocom/sbcap/SBcAP_Write-Replace-Warning-Request.h>
#include <osmocom/sbcap/SBcAP_Write-Replace-Warning-Response.h>

#include <osmocom/core/logging.h>

extern int _sbcap_DASN1C;
#define SBC_AP_DEBUG(x, args ...) DEBUGP(_sbcap_DASN1C, x, ## args)

extern int asn1_xer_print;

/* SBcAP_ProcedureCode_t codes */
#define SBcAP_ProcedureId_Write_Replace_Warning 0
#define SBcAP_ProcedureId_Stop_Warning 1
#define SBcAP_ProcedureId_Error_Indication 2
#define SBcAP_ProcedureId_Write_Replace_Warning_Indication 3
#define SBcAP_ProcedureId_Stop_Warning_Indication 4
#define SBcAP_ProcedureId_PWS_Restart_Indication 5
#define SBcAP_ProcedureId_PWS_Failure_Indication 6

SBcAP_SBC_AP_PDU_t *sbcap_pdu_alloc(void);
void sbcap_pdu_free(SBcAP_SBC_AP_PDU_t *pdu);
struct msgb *sbcap_encode(SBcAP_SBC_AP_PDU_t *pdu);
SBcAP_SBC_AP_PDU_t *sbcap_decode(const struct msgb *msg);

const char *sbcap_procedure_code_str(SBcAP_ProcedureCode_t pc);
const char *sbcap_cause_str(SBcAP_Cause_t cause);

void sbcap_set_log_area(int log_area_sbcap, int log_area_asn1c);

SBcAP_ProcedureCode_t sbcap_pdu_get_procedure_code(const SBcAP_SBC_AP_PDU_t *pdu);
SBcAP_Criticality_t sbcap_pdu_get_criticality(const SBcAP_SBC_AP_PDU_t *pdu);
const char *sbcap_pdu_get_name(const SBcAP_SBC_AP_PDU_t *pdu);

void *sbcap_as_find_ie(void *void_list, SBcAP_ProtocolIE_ID_t ie_id);

SBcAP_Write_Replace_Warning_Request_IEs_t *sbcap_alloc_Write_Replace_Warning_Request_IE(
	long id, SBcAP_Criticality_t criticality, SBcAP_Write_Replace_Warning_Request_IEs__value_PR present);

SBcAP_Stop_Warning_Request_IEs_t *sbcap_alloc_Stop_Warning_Request_IE(
	long id, SBcAP_Criticality_t criticality, SBcAP_Stop_Warning_Request_IEs__value_PR present);

SBcAP_ErrorIndicationIEs_t *sbcap_alloc_Error_Indication_IE(
	long id, SBcAP_Criticality_t criticality, SBcAP_Stop_Warning_Request_IEs__value_PR present);
