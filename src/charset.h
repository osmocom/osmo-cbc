#pragma once

int charset_utf8_to_gsm7(char *out, size_t out_len, const char *in, size_t in_len);
int charset_gsm7_to_utf8(char *out, size_t out_len, const char *in, size_t in_len);

int charset_utf8_to_ucs2(char *out, size_t out_len, const char *in, size_t in_len);
int charset_ucs2_to_utf8(char *out, size_t out_len, const char *in, size_t in_len);
