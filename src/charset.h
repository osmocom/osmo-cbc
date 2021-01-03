#pragma once
#include <stdint.h>

int charset_utf8_to_gsm7(uint8_t *out, size_t out_len, const char *in, size_t in_len);
int charset_gsm7_to_utf8(char *out, size_t out_len, const uint8_t *in, size_t in_len);

int charset_utf8_to_ucs2(uint8_t *out, size_t out_len, const char *in, size_t in_len);
int charset_ucs2_to_utf8(char *out, size_t out_len, const uint8_t *in, size_t in_len);
