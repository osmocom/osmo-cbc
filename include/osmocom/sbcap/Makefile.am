version.h: version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

EXTRA_DIST = \
	version.h.tpl \
	$(NULL)

sbcap_HEADERS = \
	sbcap_common.h \
	sbcap_internal.h \
	SBcAP_Broadcast-Cancelled-Area-List-5GS.h \
	SBcAP_Broadcast-Cancelled-Area-List.h \
	SBcAP_Broadcast-Empty-Area-List-5GS.h \
	SBcAP_Broadcast-Empty-Area-List.h \
	SBcAP_Broadcast-Scheduled-Area-List-5GS.h \
	SBcAP_Broadcast-Scheduled-Area-List.h \
	SBcAP_CancelledCellinEAI.h \
	SBcAP_CancelledCellinEAI-Item.h \
	SBcAP_CancelledCellinTAI-5GS.h \
	SBcAP_CancelledCellinTAI.h \
	SBcAP_CancelledCellinTAI-Item.h \
	SBcAP_Cause.h \
	SBcAP_CellId-Broadcast-List-5GS.h \
	SBcAP_CellId-Broadcast-List.h \
	SBcAP_CellId-Broadcast-List-Item.h \
	SBcAP_CellID-Cancelled-Item.h \
	SBcAP_CellID-Cancelled-List-5GS.h \
	SBcAP_CellID-Cancelled-List.h \
	SBcAP_CellIdentity.h \
	SBcAP_Concurrent-Warning-Message-Indicator.h \
	SBcAP_Criticality-Diagnostics.h \
	SBcAP_CriticalityDiagnostics-IE-List.h \
	SBcAP_Criticality.h \
	SBcAP_Data-Coding-Scheme.h \
	SBcAP_ECGIList.h \
	SBcAP_EmergencyAreaID-Broadcast-List.h \
	SBcAP_EmergencyAreaID-Broadcast-List-Item.h \
	SBcAP_EmergencyAreaID-Cancelled-Item.h \
	SBcAP_EmergencyAreaID-Cancelled-List.h \
	SBcAP_Emergency-Area-ID.h \
	SBcAP_Emergency-Area-ID-List.h \
	SBcAP_ENB-ID.h \
	SBcAP_Error-Indication.h \
	SBcAP_EUTRAN-CGI.h \
	SBcAP_Extended-Repetition-Period.h \
	SBcAP_EXTERNAL.h \
	SBcAP_Failed-Cell-List.h \
	SBcAP_Failed-Cell-List-NR.h \
	SBcAP_Global-ENB-ID.h \
	SBcAP_Global-GNB-ID.h \
	SBcAP_Global-NgENB-ID.h \
	SBcAP_Global-RAN-Node-ID.h \
	SBcAP_GNB-ID.h \
	SBcAP_InitiatingMessage.h \
	SBcAP_List-of-5GS-Cells-for-Failure.h \
	SBcAP_List-of-5GS-TAI-for-Restart.h \
	SBcAP_List-of-5GS-TAIs.h \
	SBcAP_List-of-EAIs-Restart.h \
	SBcAP_List-of-TAIs.h \
	SBcAP_List-of-TAIs-Restart.h \
	SBcAP_Message-Identifier.h \
	SBcAP_NgENB-ID.h \
	SBcAP_NRCellIdentity.h \
	SBcAP_NR-CGI.h \
	SBcAP_NR-CGIList.h \
	SBcAP_NumberOfBroadcasts.h \
	SBcAP_Number-of-Broadcasts-Requested.h \
	SBcAP_Omc-Id.h \
	SBcAP_PLMNidentity.h \
	SBcAP_Presence.h \
	SBcAP_ProcedureCode.h \
	SBcAP_ProtocolExtensionContainer.h \
	SBcAP_ProtocolExtensionField.h \
	SBcAP_ProtocolExtensionID.h \
	SBcAP_ProtocolIE-Container.h \
	SBcAP_ProtocolIE-ContainerList.h \
	SBcAP_ProtocolIE-Field.h \
	SBcAP_ProtocolIE-ID.h \
	SBcAP_PWS-Failure-Indication.h \
	SBcAP_PWS-Restart-Indication.h \
	SBcAP_RAT-Selector-5GS.h \
	SBcAP_Repetition-Period.h \
	SBcAP_Restarted-Cell-List.h \
	SBcAP_Restarted-Cell-List-NR.h \
	SBcAP_SBC-AP-PDU.h \
	SBcAP_ScheduledCellinEAI.h \
	SBcAP_ScheduledCellinEAI-Item.h \
	SBcAP_ScheduledCellinTAI-5GS.h \
	SBcAP_ScheduledCellinTAI.h \
	SBcAP_ScheduledCellinTAI-Item.h \
	SBcAP_Send-Stop-Warning-Indication.h \
	SBcAP_Send-Write-Replace-Warning-Indication.h \
	SBcAP_Serial-Number.h \
	SBcAP_Stop-All-Indicator.h \
	SBcAP_Stop-Warning-Indication.h \
	SBcAP_Stop-Warning-Request.h \
	SBcAP_Stop-Warning-Response.h \
	SBcAP_SuccessfulOutcome.h \
	SBcAP_TAC-5GS.h \
	SBcAP_TAC.h \
	SBcAP_TAI-5GS.h \
	SBcAP_TAI-Broadcast-List-5GS.h \
	SBcAP_TAI-Broadcast-List.h \
	SBcAP_TAI-Broadcast-List-Item.h \
	SBcAP_TAI-Cancelled-List-5GS.h \
	SBcAP_TAI-Cancelled-List.h \
	SBcAP_TAI-Cancelled-List-Item.h \
	SBcAP_TAI.h \
	SBcAP_TAI-List-for-Warning.h \
	SBcAP_TBCD-STRING.h \
	SBcAP_TriggeringMessage.h \
	SBcAP_TypeOfError.h \
	SBcAP_Unknown-5GS-Tracking-Area-List.h \
	SBcAP_Unknown-Tracking-Area-List.h \
	SBcAP_UnsuccessfulOutcome.h \
	SBcAP_Warning-Area-Coordinates.h \
	SBcAP_Warning-Area-List-5GS.h \
	SBcAP_Warning-Area-List.h \
	SBcAP_Warning-Message-Content.h \
	SBcAP_Warning-Security-Information.h \
	SBcAP_Warning-Type.h \
	SBcAP_Write-Replace-Warning-Indication.h \
	SBcAP_Write-Replace-Warning-Request.h \
	SBcAP_Write-Replace-Warning-Response.h \
	version.h \
	$(NULL)

sbcapdir = $(includedir)/osmocom/sbcap
