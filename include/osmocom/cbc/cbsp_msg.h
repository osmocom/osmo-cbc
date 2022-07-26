#pragma once
#include <osmocom/gsm/cbsp.h>

struct cbc_message;
struct osmo_cbsp_decoded *cbsp_gen_write_replace_req(void *ctx, const struct cbc_message *cbcmsg);
