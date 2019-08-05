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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include <jansson.h>
#include <ulfius.h>
#include <orcania.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/gsm/protocol/gsm_48_049.h>

#define PREFIX  "/api/ecbe/v1"

#include "internal.h"
#include "charset.h"
#include "cbc_data.h"

/* get an integer value for field "key" in object "parent" */
static int json_get_integer(int *out, json_t *parent, const char *key)
{
	json_t *jtmp;

	if (!parent || !json_is_object(parent))
		return -ENODEV;
	jtmp = json_object_get(parent, key);
	if (!jtmp)
		return -ENOENT;
	if (!json_is_integer(jtmp))
		return -EINVAL;
	*out = json_integer_value(jtmp);
	return 0;
}

static int json_get_integer_range(int *out, json_t *parent, const char *key, int min, int max)
{
	int rc, tmp;
	rc = json_get_integer(&tmp, parent, key);
	if (rc < 0)
		return rc;
	if (tmp < min || tmp > max)
		return -ERANGE;
	*out = tmp;
	return 0;
}

/* get a string value for field "key" in object "parent" */
static const char *json_get_string(json_t *parent, const char *key)
{
	json_t *jtmp;

	if (!parent || !json_is_object(parent))
		return NULL;
	jtmp = json_object_get(parent, key);
	if (!jtmp)
		return NULL;
	if (!json_is_string(jtmp))
		return NULL;
	return json_string_value(jtmp);
}

/* geographc scope (part of message_id) as per 3GPP TS 23.041 Section 9.4.1.2 "GS Code" */
static const struct value_string geo_scope_vals[] = {
	{ 0, "cell_wide_immediate" },
	{ 1, "plmn_wide" },
	{ 2, "lac_sac_tac_wide" },
	{ 3, "cell_wide" },
	{ 0, NULL }
};

/* mapping of CBS DCS values for languages in 7bit GSM alphabet to ISO639-1 language codes,
 * as per 3GPP TS 23.038 Section 5 */
static const struct value_string iso639_1_cbs_dcs_vals[] = {
	{ 0x00, "de" },
	{ 0x01, "en" },
	{ 0x02, "it" },
	{ 0x03, "fr" },
	{ 0x04, "es" },
	{ 0x05, "nl" },
	{ 0x06, "sv" },
	{ 0x07, "da" },
	{ 0x08, "pt" },
	{ 0x09, "fi" },
	{ 0x0a, "no" },
	{ 0x0b, "el" },
	{ 0x0c, "tr" },
	{ 0x0d, "hu" },
	{ 0x0e, "pl" },
	{ 0x20, "cs" },
	{ 0x21, "he" },
	{ 0x22, "ar" },
	{ 0x23, "ru" },
	{ 0x24, "is" },
	{ 0, NULL }
};
/* values not expressed in the table above must use "language indication" at the start of the message */

/* 3GPP TS 23.041 Section 9.3.24 */
static const struct value_string ts23041_warning_type_vals[] = {
	{ 0,	"earthquake" },
	{ 1,	"tsunami" },
	{ 2,	"earthquake_and_tsuname" },
	{ 3,	"test" },
	{ 4,	"other" },
	{ 0, NULL }
};

/* parse a smscb.schema.json/warning_type (either encoded or decoded) */
static int parse_warning_type(uint16_t *out, json_t *in)
{
	json_t *jtmp;
	int i, rc;

	if (!in || !json_is_object(in))
		return -EINVAL;
	rc = json_get_integer_range(&i, in, "warning_type_encoded", 0, 255);
	if (rc == 0) {
		*out = i;
	} else if (rc == -ENOENT && (jtmp = json_object_get(in, "warning_type_decoded"))) {
		const char *tstr = json_string_value(jtmp);
		if (!tstr)
			return -EINVAL;
		i = get_string_value(ts23041_warning_type_vals, tstr);
		if (i < 0)
			return -EINVAL;
		*out = i;
	} else
		return -EINVAL;

	return 0;
}

/* parse a smscb.schema.json/serial_nr type (either encoded or decoded) */
static int json2serial_nr(uint16_t *out, json_t *jser_nr)
{
	json_t *jtmp;
	int tmp, rc;

	if (!jser_nr || !json_is_object(jser_nr))
		return -EINVAL;
	rc = json_get_integer_range(&tmp, jser_nr, "serial_nr_encoded", 0, UINT16_MAX);
	if (rc == 0) {
		*out = tmp;
	} else if (rc == -ENOENT && (jtmp = json_object_get(jser_nr, "serial_nr_decoded"))) {
		const char *geo_scope_str;
		int msg_code, upd_nr, geo_scope;
		geo_scope_str = json_get_string(jtmp, "geo_scope");
		if (!geo_scope_str)
			return -EINVAL;
		geo_scope = get_string_value(geo_scope_vals, geo_scope_str);
		if (geo_scope < 0)
			return -EINVAL;
		rc = json_get_integer_range(&msg_code, jtmp, "msg_code", 0, 1024);
		if (rc < 0)
			return rc;
		rc = json_get_integer_range(&upd_nr, jtmp, "update_nr", 0, 15);
		if (rc < 0)
			return rc;
		*out = ((geo_scope & 3) << 14) | ((msg_code & 0x3ff) << 4) | (upd_nr & 0xf);
		return 0;
	} else
		return -EINVAL;

	return 0;
}

/* parse a smscb.schema.json/payload_decoded type */
static int parse_payload_decoded(struct smscb_message *out, json_t *jtmp)
{
	const char *cset_str, *lang_str, *data_utf8_str;
	int rc, dcs_class = 0;

	/* character set */
	cset_str = json_get_string(jtmp, "character_set");
	if (!cset_str) {
		/* TODO: dynamically decide? */
		return -EINVAL;
	}

	/* language */
	lang_str = json_get_string(jtmp, "language");
	if (lang_str && strlen(lang_str) > 2)
		return -EINVAL;

	/* DCS class: if not present, default (0) above will prevail */
	rc = json_get_integer_range(&dcs_class, jtmp, "dcs_class", 0, 3);
	if (rc < 0 && rc != -EINVAL)
		return rc;

	data_utf8_str = json_get_string(jtmp, "data_utf8");
	if (!data_utf8_str)
		return -EINVAL;

	/* encode according to character set */
	if (!strcmp(cset_str, "gsm")) {
		if (lang_str) {
			rc = get_string_value(iso639_1_cbs_dcs_vals, lang_str);
			if (rc >= 0)
				out->cbs.dcs = rc;
			else {
				/* TODO: we must encode it in the first 3 characters */
			}
		} else {
			if (json_object_get(jtmp, "dcs_class")) {
				/* user has not specified language but class,
				 * express class in DCS */
				out->cbs.dcs = 0xF0 | (dcs_class & 3);
			} else {
				/* user has specified neither language nor class,
				 * use general "7 bit alphabet / language unspacified" */
				out->cbs.dcs = 0x0F;
			}
		}
		/* convert from UTF-8 input to GSM 7bit output */
		rc = charset_utf8_to_gsm7((char *)out->cbs.data, sizeof(out->cbs.data),
					  data_utf8_str, strlen(data_utf8_str));
	} else if (!strcmp(cset_str, "8bit")) {
		/* Determine DCS based on UDH + message class */
		out->cbs.dcs = 0xF4 | (dcs_class & 3);
		/* copy 8bit data over (hex -> binary conversion) */
		rc = osmo_hexparse(data_utf8_str, (uint8_t *)out->cbs.data, sizeof(out->cbs.data));
	} else if (!strcmp(cset_str, "ucs2")) {
		if (lang_str) {
			/* TODO: we must encode it in the first two octets */
		}
		/* convert from UTF-8 input to UCS2 output */
		rc = charset_utf8_to_ucs2((char *) out->cbs.data, sizeof(out->cbs.data),
					  data_utf8_str, strlen(data_utf8_str));
	} else
		return -EINVAL;
	return 0;
}

/* parse a smscb.schema.json/payload type */
static int json2payload(struct smscb_message *out, json_t *in)
{
	json_t *jtmp;
	int rc;

	if (!in || !json_is_object(in))
		return -EINVAL;

	if ((jtmp = json_object_get(in, "payload_encoded"))) {
		json_t *jpage_arr, *jpage;
		int i, dcs, num_pages;

		out->is_etws = false;
		/* Data Coding Scheme */
		rc = json_get_integer_range(&dcs, jtmp, "dcs", 0, 255);
		if (rc < 0)
			return rc;
		out->cbs.dcs = dcs;

		/* Array of Pages as hex-strings */
		jpage_arr = json_object_get(jtmp, "pages");
		if (!jpage_arr || !json_is_array(jpage_arr))
			return -EINVAL;
		num_pages = json_array_size(jpage_arr);
		if (num_pages < 1 || num_pages > 15)
			return -EINVAL;
		out->cbs.num_pages = num_pages;
		json_array_foreach(jpage_arr, i, jpage) {
			const char *hexstr;
			if (!json_is_string(jpage))
				return -EINVAL;
			hexstr = json_string_value(jpage);
			if (strlen(hexstr) > 88 * 2)
				return -EINVAL;
			if (osmo_hexparse(hexstr, out->cbs.data[i], sizeof(out->cbs.data[i])) < 0)
				return -EINVAL;
		}
		return 0;
	} else if ((jtmp = json_object_get(in, "payload_decoded"))) {
		out->is_etws = false;
		return parse_payload_decoded(out, jtmp);
	} else if ((jtmp = json_object_get(in, "payload_etws"))) {
		json_t *jwtype;
		const char *wsecinfo_str;
		out->is_etws = true;
		/* Warning Type */
		jwtype = json_object_get(jtmp, "warning_type");
		if (!jwtype)
			return -EINVAL;
		if (parse_warning_type(&out->etws.warning_type, jwtype) < 0)
			return -EINVAL;
		/* Warning Security Info */
		wsecinfo_str = json_get_string(jtmp, "warning_sec_info");
		if (wsecinfo_str) {
			if (osmo_hexparse(wsecinfo_str, out->etws.warning_sec_info,
					  sizeof(out->etws.warning_sec_info)) < 0)
				return -EINVAL;
		}
		return 0;
	} else
		return -EINVAL;

}

static int json2smscb_message(struct smscb_message *out, json_t *in)
{
	json_t *jser_nr, *jtmp;
	int msg_id, rc;

	if (!json_is_object(in))
		return -EINVAL;

	jser_nr = json_object_get(in, "serial_nr");
	if (!jser_nr)
		return -EINVAL;
	if (json2serial_nr(&out->serial_nr, jser_nr) < 0)
		return -EINVAL;

	rc = json_get_integer_range(&msg_id, in, "message_id", 0, UINT16_MAX);
	if (rc < 0)
		return -EINVAL;
	out->message_id = msg_id;

	jtmp = json_object_get(in, "payload");
	if (json2payload(out, jtmp) < 0)
		return -EINVAL;
	return 0;
}

static int api_cb_message_post(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	struct smscb_message message;
	json_error_t json_err;
	json_t *json_req;
	int rc;

	json_req = ulfius_get_json_body_request(req, &json_err);
	if (!json_req) {
		LOGP(DREST, LOGL_ERROR, "REST: No JSON Body\n");
		goto err;
	}

	rc = json2smscb_message(&message, json_req);
	if (rc < 0)
		goto err;

	ulfius_set_empty_body_response(resp, 200);
	return U_CALLBACK_COMPLETE;
err:
	ulfius_set_empty_body_response(resp, 400);
	return U_CALLBACK_COMPLETE;
}

static const struct _u_endpoint api_endpoints[] = {
	/* create/update a message */
	{ "POST", PREFIX, "/message", 0, &api_cb_message_post, NULL },
};

static struct _u_instance g_instance;
static void *g_tall_rest;
static pthread_mutex_t g_tall_rest_lock = PTHREAD_MUTEX_INITIALIZER;

static void *my_o_malloc(size_t sz)
{
	void *obj;
	pthread_mutex_lock(&g_tall_rest_lock);
	obj = talloc_size(g_tall_rest, sz);
	pthread_mutex_unlock(&g_tall_rest_lock);
	return obj;
}

static void *my_o_realloc(void *obj, size_t sz)
{
	void *ret;
	pthread_mutex_lock(&g_tall_rest_lock);
	ret = talloc_realloc_size(g_tall_rest, obj, sz);
	pthread_mutex_unlock(&g_tall_rest_lock);
	return ret;
}

static void my_o_free(void *obj)
{
	pthread_mutex_lock(&g_tall_rest_lock);
	talloc_free(obj);
	pthread_mutex_unlock(&g_tall_rest_lock);
}

int rest_api_init(void *ctx, uint16_t port)
{
	int i;

	g_tall_rest = ctx;
	o_set_alloc_funcs(my_o_malloc, my_o_realloc, my_o_free);

	if (ulfius_init_instance(&g_instance, port, NULL, NULL) != U_OK)
		return -1;
	g_instance.mhd_response_copy_data = 1;

	for (i = 0; i < ARRAY_SIZE(api_endpoints); i++)
		ulfius_add_endpoint(&g_instance, &api_endpoints[i]);

	if (ulfius_start_framework(&g_instance) != U_OK) {
		LOGP(DREST, LOGL_FATAL, "Cannot start REST API on port %u\n", port);
		return -1;
	}
	LOGP(DREST, LOGL_NOTICE, "Started REST API on port %u\n", port);
	return 0;
}

void rest_api_fin(void)
{
	ulfius_stop_framework(&g_instance);
	ulfius_clean_instance(&g_instance);
}
