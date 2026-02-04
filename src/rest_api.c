/* Osmocom CBC (Cell Broadcast Centre) */

/* (C) 2019-2021 by Harald Welte <laforge@gnumonks.org>
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
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/gsm/protocol/gsm_48_049.h>

#define PREFIX  "/api/ecbe/v1"

#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/charset.h>
#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/rest_it_op.h>

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

/* geographic scope (part of message_id) as per 3GPP TS 23.041 Section 9.4.1.2 "GS Code" */
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
static int parse_warning_type(json_t *in, const char **errstr)
{
	json_t *jtmp;
	int i, rc, val;

	if (!in || !json_is_object(in)) {
		*errstr = "'warning_type' must be object";
		return -EINVAL;
	}
	rc = json_get_integer_range(&i, in, "warning_type_encoded", 0, 255);
	if (rc == 0) {
		val = i;
	} else if (rc == -ENOENT && (jtmp = json_object_get(in, "warning_type_decoded"))) {
		const char *tstr = json_string_value(jtmp);
		if (!tstr) {
			*errstr = "'warning_type_decoded' is not a string";
			return -EINVAL;
		}
		i = get_string_value(ts23041_warning_type_vals, tstr);
		if (i < 0) {
			*errstr = "'warning_type_decoded' is invalid";
			return -EINVAL;
		}
		val = i;
	} else {
		*errstr = "either 'warning_type_encoded' or 'warning_type_decoded' must be present";
		return -EINVAL;
	}

	return val;
}

/* parse a smscb.schema.json/serial_nr type (either encoded or decoded) */
static int json2serial_nr(uint16_t *out, json_t *jser_nr, const char **errstr)
{
	json_t *jtmp;
	int tmp, rc;

	if (!jser_nr || !json_is_object(jser_nr)) {
		*errstr = "'serial_nr' must be present and an object";
		return -EINVAL;
	}
	rc = json_get_integer_range(&tmp, jser_nr, "serial_nr_encoded", 0, UINT16_MAX);
	if (rc == 0) {
		*out = tmp;
	} else if (rc == -ENOENT && (jtmp = json_object_get(jser_nr, "serial_nr_decoded"))) {
		const char *geo_scope_str;
		int msg_code, upd_nr, geo_scope;
		geo_scope_str = json_get_string(jtmp, "geo_scope");
		if (!geo_scope_str) {
			*errstr = "'geo_scope' is mandatory";
			return -EINVAL;
		}
		geo_scope = get_string_value(geo_scope_vals, geo_scope_str);
		if (geo_scope < 0) {
			*errstr = "'geo_scope' is invalid";
			return -EINVAL;
		}
		rc = json_get_integer_range(&msg_code, jtmp, "msg_code", 0, 1024);
		if (rc < 0) {
			*errstr = "'msg_code' is out of range";
			return rc;
		}
		rc = json_get_integer_range(&upd_nr, jtmp, "update_nr", 0, 15);
		if (rc < 0) {
			*errstr = "'update_nr' is out of range";
			return rc;
		}
		*out = ((geo_scope & 3) << 14) | ((msg_code & 0x3ff) << 4) | (upd_nr & 0xf);
		return 0;
	} else {
		*errstr = "Either 'serial_nr_encoded' or 'serial_nr_decoded' are mandatory";
		return -EINVAL;
	}

	return 0;
}

/* compute the number of pages needed for number of octets */
static unsigned int pages_from_octets(int n_octets)
{
	unsigned int n_pages = n_octets / SMSCB_RAW_PAGE_LEN;
	if (n_octets % SMSCB_RAW_PAGE_LEN)
		n_pages++;
	return n_pages;
}

/* parse a smscb.schema.json/payload_decoded type */
static int parse_payload_decoded(struct smscb_message *out, json_t *jtmp, const char **errstr)
{
	const char *cset_str, *lang_str, *data_utf8_str;
	int rc, dcs_class = 0;

	/* character set */
	cset_str = json_get_string(jtmp, "character_set");
	if (!cset_str) {
		*errstr = "Currently 'character_set' is mandatory";
		/* TODO: dynamically decide? */
		return -EINVAL;
	}

	/* language */
	lang_str = json_get_string(jtmp, "language");
	if (lang_str && strlen(lang_str) > 2) {
		*errstr = "Only two-digit 'language' code is supported";
		return -EINVAL;
	}

	/* DCS class: if not present, default (0) above will prevail */
	rc = json_get_integer_range(&dcs_class, jtmp, "dcs_class", 0, 3);
	if (rc < 0 && rc != -ENOENT) {
		*errstr = "'dcs_class' out of range";
		return rc;
	}

	data_utf8_str = json_get_string(jtmp, "data_utf8");
	if (!data_utf8_str) {
		*errstr = "'data_utf8' is mandatory";
		return -EINVAL;
	}

	/* encode according to character set */
	if (!strcmp(cset_str, "gsm")) {
		if (lang_str) {
			rc = get_string_value(iso639_1_cbs_dcs_vals, lang_str);
			if (rc >= 0)
				out->cbs.dcs = rc;
			else {
				/* TODO: we must encode it in the first 3 characters */
				out->cbs.dcs = 0x0f;
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
		rc = charset_utf8_to_gsm7((uint8_t *) out->cbs.data, sizeof(out->cbs.data),
					  data_utf8_str, strlen(data_utf8_str));
		if (rc > 0) {
			out->cbs.data_user_len = rc;
			out->cbs.num_pages = pages_from_octets(rc);
		}
	} else if (!strcmp(cset_str, "8bit")) {
		/* Determine DCS based on UDH + message class */
		out->cbs.dcs = 0xF4 | (dcs_class & 3);
		/* copy 8bit data over (hex -> binary conversion) */
		rc = osmo_hexparse(data_utf8_str, (uint8_t *)out->cbs.data, sizeof(out->cbs.data));
		if (rc > 0)
			out->cbs.num_pages = pages_from_octets(rc);
	} else if (!strcmp(cset_str, "ucs2")) {
		if (lang_str) {
			/* TODO: we must encode it in the first two octets */
		}
		/* convert from UTF-8 input to UCS2 output */
		rc = charset_utf8_to_ucs2((uint8_t *) out->cbs.data, sizeof(out->cbs.data),
					  data_utf8_str, strlen(data_utf8_str));
		if (rc > 0)
			out->cbs.num_pages = pages_from_octets(rc);
	} else {
		*errstr = "Invalid 'character_set'";
		return -EINVAL;
	}
	return 0;
}

/* parse a smscb.schema.json/payload type */
static int json2payload(struct smscb_message *out, json_t *in, const char **errstr)
{
	json_t *jtmp;
	int rc;

	if (!in || !json_is_object(in)) {
		*errstr = "'payload' must be JSON object";
		return -EINVAL;
	}

	if ((jtmp = json_object_get(in, "payload_encoded"))) {
		json_t *jpage_arr, *jpage;
		int i, dcs, num_pages, len;

		out->is_etws = false;
		/* Data Coding Scheme */
		rc = json_get_integer_range(&dcs, jtmp, "dcs", 0, 255);
		if (rc < 0) {
			*errstr = "'dcs' out of range";
			return rc;
		}
		out->cbs.dcs = dcs;

		/* Array of Pages as hex-strings */
		jpage_arr = json_object_get(jtmp, "pages");
		if (!jpage_arr || !json_is_array(jpage_arr)) {
			*errstr = "'pages' absent or not an array";
			return -EINVAL;
		}
		num_pages = json_array_size(jpage_arr);
		if (num_pages < 1 || num_pages > 15) {
			*errstr = "'pages' array size out of range";
			return -EINVAL;
		}
		out->cbs.num_pages = num_pages;
		out->cbs.data_user_len = 0;
		json_array_foreach(jpage_arr, i, jpage) {
			const char *hexstr;
			if (!json_is_string(jpage)) {
				*errstr = "'pages' array must contain strings";
				return -EINVAL;
			}
			hexstr = json_string_value(jpage);
			/* The total page length is 88, but the header is 6 bytes length */
			if (strlen(hexstr) > sizeof(out->cbs.data[i]) * 2) {
				*errstr = "'pages' actual data array must contain strings up to 82 hex nibbles";
				return -EINVAL;
			}
			len = osmo_hexparse(hexstr, out->cbs.data[i], sizeof(out->cbs.data[i]));
			if (len < 0) {
				*errstr = "'pages' array must contain hex strings";
				return -EINVAL;
			}
			out->cbs.data_user_len += len;
		}
		return 0;
	} else if ((jtmp = json_object_get(in, "payload_decoded"))) {
		out->is_etws = false;
		return parse_payload_decoded(out, jtmp, errstr);
	} else if ((jtmp = json_object_get(in, "payload_etws"))) {
		json_t *jwtype, *jtmp2;
		const char *wsecinfo_str;

		out->is_etws = true;

		/* Warning Type (value) */
		jwtype = json_object_get(jtmp, "warning_type");
		if (!jwtype) {
			*errstr = "'warning_type' must be object";
			return -EINVAL;
		}
		rc = parse_warning_type(jwtype, errstr);
		if (rc < 0)
			return -EINVAL;
		out->etws.warning_type = rc;

		/* Emergency User Alert */
		jtmp2 = json_object_get(jtmp, "emergency_user_alert");
		if (jtmp && json_is_true(jtmp2))
			out->etws.user_alert = true;
		else
			out->etws.user_alert = false;

		/* Popup */
		jtmp2 = json_object_get(jtmp, "popup_on_display");
		if (jtmp && json_is_true(jtmp2))
			out->etws.popup_on_display = true;
		else
			out->etws.popup_on_display = false;

		/* Warning Security Info */
		wsecinfo_str = json_get_string(jtmp, "warning_sec_info");
		if (wsecinfo_str) {
			if (osmo_hexparse(wsecinfo_str, out->etws.warning_sec_info,
					  sizeof(out->etws.warning_sec_info)) < 0) {
				*errstr = "'warnin_sec_info' must be hex string";
				return -EINVAL;
			}
		}
		return 0;
	} else {
		*errstr = "'payload_type_encoded', 'payload_type_decoded' or 'payload_etws' must be present";
		return -EINVAL;
	}
}

/* decode a "smscb.schema.json#definitions/smscb_message" */
static int json2smscb_message(struct smscb_message *out, json_t *in, const char **errstr)
{
	json_t *jser_nr, *jtmp;
	int msg_id, rc;

	if (!json_is_object(in)) {
		*errstr = "not a JSON object";
		return -EINVAL;
	}

	jser_nr = json_object_get(in, "serial_nr");
	if (!jser_nr) {
		*errstr = "serial_nr is mandatory";
		return -EINVAL;
	}
	if (json2serial_nr(&out->serial_nr, jser_nr, errstr) < 0)
		return -EINVAL;

	rc = json_get_integer_range(&msg_id, in, "message_id", 0, UINT16_MAX);
	if (rc < 0) {
		*errstr = "message_id out of range";
		return -EINVAL;
	}
	out->message_id = msg_id;

	jtmp = json_object_get(in, "payload");
	if (json2payload(out, jtmp, errstr) < 0)
		return -EINVAL;

	return 0;
}

static const struct value_string category_str_vals[] = {
	{ CBSP_CATEG_NORMAL,		"normal" },
	{ CBSP_CATEG_HIGH_PRIO,		"high_priority" },
	{ CBSP_CATEG_BACKGROUND,	"background" },
	{ 0, NULL }
};

/* decode a "cbc.schema.json#definitions/cbc_message" */
static int json2cbc_message(struct cbc_message *out, void *ctx, json_t *in, const char **errstr)
{
	const char *category_str, *cbe_str;
	json_t *jtmp;
	int rc, tmp;

	if (!json_is_object(in)) {
		*errstr = "CBCMSG must be JSON object";
		return -EINVAL;
	}

	/* CBE name (M) */
	cbe_str = json_get_string(in, "cbe_name");
	if (!cbe_str) {
		*errstr = "CBCMSG 'cbe_name' is mandatory";
		return -EINVAL;
	}
	out->cbe_name = talloc_strdup(ctx, cbe_str);

	/* Category (O) */
	category_str = json_get_string(in, "category");
	if (!category_str)
		out->priority = CBSP_CATEG_NORMAL;
	else {
		rc = get_string_value(category_str_vals, category_str);
		if (rc < 0) {
			*errstr = "CBCMSG 'category' unknown";
			return -EINVAL;
		}
		out->priority = rc;
	}

	/* Repetition Period (O) */
	rc = json_get_integer_range(&tmp, in, "repetition_period", 0, 4095);
	if (rc == 0)
		out->rep_period = tmp;
	else if (rc == -ENOENT){
		*errstr = "CBCMSG 'repetiton_period' is mandatory";
		return rc;
	} else {
		*errstr = "CBCMSG 'repetiton_period' out of range";
		return rc;
	}

	/* Number of Broadcasts (O) */
	rc = json_get_integer_range(&tmp, in, "num_of_bcast", 0, 65535);
	if (rc == 0)
		out->num_bcast = tmp;
	else if (rc == -ENOENT)
		out->num_bcast = 0; /* unlimited */
	else {
		*errstr = "CBCMSG 'num_of_bcast' out of range";
		return rc;
	}

	/* Warning Period in seconds (O) */
	rc = json_get_integer_range(&tmp, in, "warning_period_sec", 0, 65535);
	if (rc == 0)
		out->warning_period_sec = tmp;
	else if (rc == -ENOENT)
		out->warning_period_sec = 0xffffffff; /* infinite */
	else {
		*errstr = "CBCMSG 'warning_period_sec' out of range";
		return rc;
	}

	/* [Geographic] Scope (M) */
	jtmp = json_object_get(in, "scope");
	if (!jtmp) {
		*errstr = "CBCMSG 'scope' is mandatory";
		return -EINVAL;
	}

	if ((jtmp = json_object_get(jtmp, "scope_plmn"))) {
		out->scope = CBC_MSG_SCOPE_PLMN;
	} else {
		*errstr = "CBCMSG only 'scope_plmn' supported";
		return -EINVAL;
	}

	/* SMSCB message itself */
	jtmp = json_object_get(in, "smscb_message");
	if (!jtmp) {
		*errstr = "CBCMSG 'smscb_message' is mandatory";
		return -EINVAL;
	}
	rc = json2smscb_message(&out->msg, jtmp, errstr);
	if (rc < 0)
		return rc;

	return 0;
}

static int api_cb_message_post(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	struct rest_it_op *riop = talloc_zero(g_cbc, struct rest_it_op);
	const char *errstr = "Unknown";
	json_error_t json_err;
	json_t *json_req = NULL;
	char *jsonstr;
	int rc;

	if (!riop) {
		LOGP(DREST, LOGL_ERROR, "Out of memory\n");
		ulfius_set_string_body_response(resp, 500, "Out of memory");
		return U_CALLBACK_COMPLETE;
	}

	riop->operation = REST_IT_OP_MSG_CREATE;

	json_req = ulfius_get_json_body_request(req, &json_err);
	if (!json_req) {
		errstr = "REST: No JSON Body";
		goto err;
	}

	char *jsontxt = json_dumps(json_req, 0);
	LOGP(DREST, LOGL_DEBUG, "/message POST: %s\n", jsontxt);
	free(jsontxt);

	rc = json2cbc_message(&riop->u.create.cbc_msg, riop, json_req, &errstr);
	if (rc < 0)
		goto err;

	LOGP(DREST, LOGL_DEBUG, "sending as inter-thread op\n");
	/* request message to be added by main thread */
	rc = rest_it_op_send_and_wait(riop);
	if (rc < 0) {
		LOGP(DREST, LOGL_ERROR, "Error %d in inter-thread op\n", rc);
		errstr = "Error in it_queue";
		goto err;
	}

	json_decref(json_req);
	LOGP(DREST, LOGL_DEBUG, "/message POST -> %u (%s)\n",
		riop->http_result.response_code, riop->http_result.message);
	ulfius_set_string_body_response(resp, riop->http_result.response_code, riop->http_result.message);
	talloc_free(riop);
	return U_CALLBACK_COMPLETE;
err:
	jsonstr = json_dumps(json_req, 0);
	LOGP(DREST, LOGL_ERROR, "ERROR: %s (%s)\n", errstr, jsonstr);
	free(jsonstr);
	json_decref(json_req);
	talloc_free(riop);
	LOGP(DREST, LOGL_DEBUG, "/message POST -> 400\n");
	ulfius_set_string_body_response(resp, 400, errstr);
	return U_CALLBACK_COMPLETE;
}

static int api_cb_message_del(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	const char *message_id_str = u_map_get(req->map_url, "message_id");
	struct rest_it_op *riop = talloc_zero(g_cbc, struct rest_it_op);
	int message_id;
	int status = 404;
	int rc;

	if (!message_id_str) {
		status = 400;
		goto err;
	}
	message_id = atoi(message_id_str);
	if (message_id < 0 || message_id > 65535) {
		status = 400;
		goto err;
	}

	if (!riop) {
		status = 500;
		goto err;
	}

	riop->operation = REST_IT_OP_MSG_DELETE;
	riop->u.del.msg_id = message_id;

	/* request message to be deleted by main thread */
	rc = rest_it_op_send_and_wait(riop);
	if (rc < 0)
		goto err;

	LOGP(DREST, LOGL_DEBUG, "/message DELETE(%u) -> %u (%s)\n", message_id,
		riop->http_result.response_code, riop->http_result.message);
	ulfius_set_string_body_response(resp, riop->http_result.response_code, riop->http_result.message);
	talloc_free(riop);
	return U_CALLBACK_COMPLETE;
err:
	talloc_free(riop);
	ulfius_set_empty_body_response(resp, status);
	return U_CALLBACK_COMPLETE;
}


static const struct _u_endpoint api_endpoints[] = {
	/* create/update a message */
	{ "POST", PREFIX, "/message", 0, &api_cb_message_post, NULL },
	{ "DELETE", PREFIX, "/message/:message_id", 0, &api_cb_message_del, NULL },
};

static struct _u_instance g_instance;
#ifdef ULFIUS_MALLOC_NOT_BROKEN
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
#endif

int rest_api_init(void *ctx, const char *bind_addr, uint16_t port)
{
	struct osmo_sockaddr_str sastr;
	int i;

	LOGP(DREST, LOGL_INFO, "Main thread tid: %lu\n", pthread_self());

#ifdef ULFIUS_MALLOC_NOT_BROKEN
	/* See https://github.com/babelouest/ulfius/issues/63 */
	g_tall_rest = ctx;
	o_set_alloc_funcs(my_o_malloc, my_o_realloc, my_o_free);
#endif

	OSMO_STRLCPY_ARRAY(sastr.ip, bind_addr);
	sastr.port = port;

	if (strchr(bind_addr, ':')) {
#if (ULFIUS_VERSION_MAJOR > 2) || (ULFIUS_VERSION_MAJOR == 2) && (ULFIUS_VERSION_MINOR >= 6)
		struct sockaddr_in6 sin6;
		sastr.af = AF_INET6;
		osmo_sockaddr_str_to_sockaddr_in6(&sastr, &sin6);
		if (ulfius_init_instance_ipv6(&g_instance, port, &sin6, U_USE_IPV6, NULL) != U_OK)
			return -1;
#else
		LOGP(DREST, LOGL_FATAL, "IPv6 requires ulfius version >= 2.6\n");
		return -2;
#endif
	} else {
		struct sockaddr_in sin;
		sastr.af = AF_INET;
		osmo_sockaddr_str_to_sockaddr_in(&sastr, &sin);
		if (ulfius_init_instance(&g_instance, port, &sin, NULL) != U_OK)
			return -1;
	}
	g_instance.mhd_response_copy_data = 1;

	for (i = 0; i < ARRAY_SIZE(api_endpoints); i++)
		ulfius_add_endpoint(&g_instance, &api_endpoints[i]);

	if (ulfius_start_framework(&g_instance) != U_OK) {
		LOGP(DREST, LOGL_FATAL, "Cannot start ECBE REST API at %s:%u\n", bind_addr, port);
		return -1;
	}
	LOGP(DREST, LOGL_NOTICE, "Started ECBE REST API at %s:%u\n", bind_addr, port);
	return 0;
}

void rest_api_fin(void)
{
	ulfius_stop_framework(&g_instance);
	ulfius_clean_instance(&g_instance);
}
