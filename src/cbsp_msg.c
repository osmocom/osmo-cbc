/* Osmocom CBC (Cell Broadcast Centre) */

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


#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/cbsp.h>
#include <osmocom/cbc/cbsp_msg.h>
#include <osmocom/cbc/cbc_message.h>

/* convert cbc_message to osmo_cbsp_cell_list */
static int cbcmsg_to_cbsp_cell_list(const void *ctx, struct osmo_cbsp_cell_list *list,
				    const struct cbc_message *cbcmsg)
{
	struct osmo_cbsp_cell_ent *ent;

	switch (cbcmsg->scope) {
	case CBC_MSG_SCOPE_PLMN:
		list->id_discr = CELL_IDENT_BSS;
		ent = talloc_zero(ctx, struct osmo_cbsp_cell_ent);
		if (!ent)
			return -ENOMEM;
		//ent->cell_id = ?
		llist_add_tail(&ent->list, &list->list);
		return 0;
	default:
		OSMO_ASSERT(0);
	}
}

/* generate a CBSP WRITE-REPLACE from our internal representation */
struct osmo_cbsp_decoded *cbsp_gen_write_replace_req(void *ctx, const struct cbc_message *cbcmsg)
{
	struct osmo_cbsp_write_replace *wrepl;
	const struct smscb_message *smscb = &cbcmsg->msg;
	struct osmo_cbsp_decoded *cbsp = osmo_cbsp_decoded_alloc(ctx, CBSP_MSGT_WRITE_REPLACE);
	unsigned int i;
	int rc;

	if (!cbsp)
		return NULL;
	wrepl = &cbsp->u.write_replace;

	wrepl->msg_id = smscb->message_id;
	wrepl->new_serial_nr = smscb->serial_nr;
	/* FIXME: old? */
	/* Cell list */
	rc = cbcmsg_to_cbsp_cell_list(cbcmsg, &wrepl->cell_list, cbcmsg);
	if (rc < 0) {
		talloc_free(cbsp);
		return NULL;
	}
	if (!smscb->is_etws)
		wrepl->is_cbs = true;
	if (wrepl->is_cbs) {
		if (cbcmsg->extended_cbch)
			wrepl->u.cbs.channel_ind = CBSP_CHAN_IND_EXTENDED;
		else
			wrepl->u.cbs.channel_ind = CBSP_CHAN_IND_BASIC;
		wrepl->u.cbs.category = cbcmsg->priority;
		wrepl->u.cbs.rep_period = cbcmsg->rep_period;
		wrepl->u.cbs.num_bcast_req = cbcmsg->num_bcast;
		wrepl->u.cbs.dcs = smscb->cbs.dcs;
		INIT_LLIST_HEAD(&wrepl->u.cbs.msg_content);
		for (i = 0; i < smscb->cbs.num_pages; i++) {
			struct osmo_cbsp_content *ce = talloc_zero(cbsp, struct osmo_cbsp_content);
			if (i == smscb->cbs.num_pages - 1)
				ce->user_len = smscb->cbs.data_user_len - (i * SMSCB_RAW_PAGE_LEN);
			else
				ce->user_len = SMSCB_RAW_PAGE_LEN;
			memcpy(ce->data, smscb->cbs.data[i], SMSCB_RAW_PAGE_LEN);
			llist_add_tail(&ce->list, &wrepl->u.cbs.msg_content);
		}
	} else {
		wrepl->u.emergency.indicator = 1;
		wrepl->u.emergency.warning_type = (smscb->etws.warning_type & 0x7f) << 9;
		if (smscb->etws.user_alert)
			wrepl->u.emergency.warning_type |= 0x0100;
		if (smscb->etws.popup_on_display)
			wrepl->u.emergency.warning_type |= 0x0080;
		memcpy(wrepl->u.emergency.warning_sec_info, smscb->etws.warning_sec_info,
			sizeof(wrepl->u.emergency.warning_sec_info));
		if (cbcmsg->warning_period_sec == 0xffffffff)
			wrepl->u.emergency.warning_period = 0;
		else
			wrepl->u.emergency.warning_period = cbcmsg->warning_period_sec;
	}
	return cbsp;
}
