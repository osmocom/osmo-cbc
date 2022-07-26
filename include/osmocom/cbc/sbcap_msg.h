#pragma once
#include <osmocom/core/linuxlist.h>
#include <osmocom/netif/stream.h>
#include <osmocom/sbcap/sbcap_common.h>

#include "cbc_data.h"

struct cbc_message;
typedef struct SBcAP_SBC_AP_PDU SBcAP_SBC_AP_PDU_t;

SBcAP_SBC_AP_PDU_t *sbcap_gen_write_replace_warning_req(void *ctx, const struct cbc_message *cbcmsg);
SBcAP_SBC_AP_PDU_t *sbcap_gen_stop_warning_req(void *ctx, const struct cbc_message *cbcmsg);
SBcAP_SBC_AP_PDU_t *sbcap_gen_error_ind(void *ctx, SBcAP_Cause_t cause, SBcAP_SBC_AP_PDU_t *rx_pdu);
