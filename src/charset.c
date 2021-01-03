/* Osmocom CBC (Cell Broacast Centre) */

/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <iconv.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/utils.h>

#include "charset.h"

/* return number of output bytes written */
int charset_utf8_to_gsm7(uint8_t *out, size_t out_len, const char *in, size_t in_len)
{
	int octets;
	/* FIXME: implement this for 'escape' characters outside 7bit alphabet */
	gsm_7bit_encode_n_ussd(out, out_len, in, &octets);
	return octets;
}

/* return number of output bytes written */
int charset_gsm7_to_utf8(char *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	/* FIXME: implement this for 'escape' characters outside 7bit alphabet */
	return gsm_7bit_decode_n_ussd(out, out_len, in, in_len);
}


static struct {
	iconv_t utf8_to_ucs2;
	iconv_t ucs2_to_utf8;
} g_iconv_state;

int charset_utf8_to_ucs2(uint8_t *out, size_t out_len, const char *in, size_t in_len)
{
	iconv_t ic = g_iconv_state.utf8_to_ucs2;
	int rc;

	/* reset the conversion state */
	rc = iconv(ic, NULL, NULL, NULL, NULL);
	if (rc < 0)
		return rc;

	return iconv(ic, (char **) &in, &in_len, (char **) &out, &out_len);
}

int charset_ucs2_to_utf8(char *out, size_t out_len, const uint8_t *in, size_t in_len)
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
