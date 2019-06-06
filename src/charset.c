#include <iconv.h>
#include <osmocom/core/utils.h>

#include "charset.h"

int charset_utf8_to_gsm7(char *out, size_t out_len, const char *in, size_t in_len)
{
	/* FIXME: implement this */
	osmo_strlcpy(out, in, out_len);
	return 0;
}

int charset_gsm7_to_utf8(char *out, size_t out_len, const char *in, size_t in_len)
{
	/* FIXME: implement this */
	osmo_strlcpy(out, in, out_len);
	return 0;
}


static struct {
	iconv_t utf8_to_ucs2;
	iconv_t ucs2_to_utf8;
} g_iconv_state;

int charset_utf8_to_ucs2(char *out, size_t out_len, const char *in, size_t in_len)
{
	iconv_t ic = g_iconv_state.utf8_to_ucs2;
	int rc;

	/* reset the conversion state */
	rc = iconv(ic, NULL, NULL, NULL, NULL);
	if (rc < 0)
		return rc;

	return iconv(ic, (char **) &in, &in_len, &out, &out_len);
}

int charset_ucs2_to_utf8(char *out, size_t out_len, const char *in, size_t in_len)
{
	iconv_t ic = g_iconv_state.ucs2_to_utf8;
	int rc;

	/* reset the conversion state */
	rc = iconv(ic, NULL, NULL, NULL, NULL);
	if (rc < 0)
		return rc;

	return iconv(ic, (char **) &in, &in_len, &out, &out_len);
}

static void __attribute__ ((constructor)) charset_init(void)
{
	g_iconv_state.utf8_to_ucs2 = iconv_open("UCS2", "utf8");
	OSMO_ASSERT(g_iconv_state.utf8_to_ucs2 != (iconv_t) -1);

	g_iconv_state.ucs2_to_utf8 = iconv_open("utf8", "UCS2");
	OSMO_ASSERT(g_iconv_state.utf8_to_ucs2 != (iconv_t) -1);
}
