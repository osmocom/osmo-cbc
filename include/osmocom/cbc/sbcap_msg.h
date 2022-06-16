#pragma once
#include <osmocom/core/linuxlist.h>
#include <osmocom/netif/stream.h>

#include "cbc_data.h"

struct cbc_message;
typedef struct SBcAP_SBC_AP_PDU SBcAP_SBC_AP_PDU_t;

SBcAP_SBC_AP_PDU_t *cbcmsg_to_sbcap(void *ctx, const struct cbc_message *cbcmsg);
SBcAP_SBC_AP_PDU_t *sbcap_gen_stop_warning_req(void *ctx, const struct cbc_message *cbcmsg);
