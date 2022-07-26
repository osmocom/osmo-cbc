#pragma once
#include <osmocom/gsm/cbsp.h>

struct cbc_message;
struct osmo_cbsp_decoded *cbcmsg_to_cbsp(void *ctx, const struct cbc_message *cbcmsg);
