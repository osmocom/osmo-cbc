/* Osmocom CBC (Cell Broacast Centre) */

/* (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/cbsp_link.h>
#include <osmocom/cbc/sbcap_link.h>
#include <osmocom/cbc/rest_it_op.h>
#include <osmocom/cbc/debug.h>

const char *cbc_cell_id2str(const struct cbc_cell_id *cid)
{
	static char buf[256];

	switch (cid->id_discr) {
	case CBC_CELL_ID_NONE:
		snprintf(buf, sizeof(buf), "NONE");
		break;
	case CBC_CELL_ID_BSS:
		snprintf(buf, sizeof(buf), "BSS");
		break;
	case CBC_CELL_ID_CGI:
		snprintf(buf, sizeof(buf), "CGI %s", osmo_cgi_name(&cid->u.cgi));
		break;
	case CBC_CELL_ID_LAC_CI:
		snprintf(buf, sizeof(buf), "LAC %u CI %u", cid->u.lac_and_ci.lac, cid->u.lac_and_ci.ci);
		break;
	case CBC_CELL_ID_LAI:
		snprintf(buf, sizeof(buf), "LAI %s", osmo_lai_name(&cid->u.lai));
		break;
	case CBC_CELL_ID_LAC:
		snprintf(buf, sizeof(buf), "LAC %u", cid->u.lac);
		break;
	case CBC_CELL_ID_CI:
		snprintf(buf, sizeof(buf), "CI %u", cid->u.ci);
		break;
	case CBC_CELL_ID_ECGI:
		snprintf(buf, sizeof(buf), "ECGI %s-%05X-%02X", osmo_plmn_name(&cid->u.ecgi.plmn),
			 cid->u.ecgi.eci >> 8, cid->u.ecgi.eci & 0xff);
		break;
	case CBC_CELL_ID_TAI:
		snprintf(buf, sizeof(buf), "TAI %s-%u", osmo_plmn_name(&cid->u.tai.plmn), cid->u.tai.tac);
		break;
	default:
		snprintf(buf, sizeof(buf), "<invalid>");
		break;
	}
	return buf;
}

struct cbc *cbc_alloc(void *ctx)
{
	struct cbc *cbc;

	cbc = talloc_zero(ctx, struct cbc);
	INIT_LLIST_HEAD(&cbc->peers);
	INIT_LLIST_HEAD(&cbc->messages);
	INIT_LLIST_HEAD(&cbc->expired_messages);
	cbc->config.cbsp.local_host = talloc_strdup(cbc, "127.0.0.1");
	cbc->config.cbsp.local_port = CBSP_TCP_PORT;
	/* cbc->config.sbcap local_host set up during VTY (and vty_go_parent) */
	cbc->config.sbcap.local_port = SBcAP_SCTP_PORT;
	cbc->config.ecbe.local_host = talloc_strdup(cbc, "127.0.0.1");
	cbc->config.ecbe.local_port = 12345;

	cbc->it_q.rest2main = osmo_it_q_alloc(cbc, "rest2main", 10, rest2main_read_cb, NULL);
	OSMO_ASSERT(cbc->it_q.rest2main);
	osmo_fd_register(&cbc->it_q.rest2main->event_ofd);

	cbc->cbsp.mgr = cbc_cbsp_mgr_alloc(cbc);
	OSMO_ASSERT(cbc->cbsp.mgr);

	cbc->sbcap.mgr = cbc_sbcap_mgr_alloc(cbc);
	OSMO_ASSERT(cbc->sbcap.mgr);

	return cbc;
}

int cbc_start(struct cbc *cbc)
{
	void *tall_rest_ctx;
	int rc;

	tall_rest_ctx = talloc_named_const(cbc, 0, "REST");

	if ((rc = cbc_cbsp_mgr_open_srv(cbc->cbsp.mgr)) < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error binding CBSP port\n");
		return rc;
	}

	if ((rc = cbc_sbcap_mgr_open_srv(cbc->sbcap.mgr)) < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error binding SBc-AP port\n");
		return rc;
	}

	rc = rest_api_init(tall_rest_ctx, cbc->config.ecbe.local_host, cbc->config.ecbe.local_port);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error binding ECBE port\n");
		return -EIO;
	}
	return 0;
}
