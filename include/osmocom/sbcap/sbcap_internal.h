#pragma once

#include <osmocom/core/logging.h>

extern int _sbcap_DASN1C;
#define SBC_AP_ASN_DEBUG(x, args ...) DEBUGP(_sbcap_DASN1C, x "\n", ## args)

#define	ASN_DEBUG	SBC_AP_ASN_DEBUG
