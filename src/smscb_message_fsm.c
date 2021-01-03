/* SMSCB FSM: Represent master state about one SMSCB message. Parent of smscb_peer_fsm */

/* (C) 2019-2020 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/fsm.h>

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/cbsp.h>

#include "cbc_data.h"
#include "cbsp_server.h"
#include "internal.h"
#include "rest_it_op.h"

#define S(x)    (1 << (x))

static void smscb_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message *cbcmsg = fi->priv;

	switch (event) {
	case SMSCB_E_CREATE:
		OSMO_ASSERT(!cbcmsg->it_op);
		cbcmsg->it_op = data;
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_WRITE_ACK, 15, T_WAIT_WRITE_ACK);
		/* forward this event to all child FSMs (i.e. all smscb_message_peer) */
		osmo_fsm_inst_broadcast_children(fi, SMSCB_E_CREATE, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_fsm_wait_write_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message *cbcmsg = fi->priv;
	struct osmo_fsm_inst *peer_fi;

	switch (event) {
	case SMSCB_E_CBSP_WRITE_ACK:
	case SMSCB_E_CBSP_WRITE_NACK:
		/* check if any per-peer children have not yet received the ACK or
		 * timed out */
		llist_for_each_entry(peer_fi, &fi->proc.children, proc.child) {
			if (peer_fi->state == SMSCB_S_WAIT_WRITE_ACK)
				return;
		}
		rest_it_op_set_http_result(cbcmsg->it_op, 201, "Created"); // FIXME: error cases
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_fsm_wait_write_ack_onleave(struct osmo_fsm_inst *fi, uint32_t new_state)
{
	struct cbc_message *cbcmsg = fi->priv;
	/* release the mutex from the REST interface + respond to user */
	rest_it_op_complete(cbcmsg->it_op);
	cbcmsg->it_op = NULL;
}

static void smscb_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message *cbcmsg = fi->priv;

	switch (event) {
	case SMSCB_E_REPLACE:
		OSMO_ASSERT(!cbcmsg->it_op);
		cbcmsg->it_op = data;
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_REPLACE_ACK, 15, T_WAIT_REPLACE_ACK);
		/* forward this event to all child FSMs (i.e. all smscb_message_peer) */
		osmo_fsm_inst_broadcast_children(fi, SMSCB_E_REPLACE, data);
		break;
	case SMSCB_E_STATUS:
		OSMO_ASSERT(!cbcmsg->it_op);
		cbcmsg->it_op = data;
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_STATUS_ACK, 15, T_WAIT_STATUS_ACK);
		/* forward this event to all child FSMs (i.e. all smscb_message_peer) */
		osmo_fsm_inst_broadcast_children(fi, SMSCB_E_STATUS, data);
		break;
	case SMSCB_E_DELETE:
		OSMO_ASSERT(!cbcmsg->it_op);
		cbcmsg->it_op = data;
		osmo_fsm_inst_state_chg(fi, SMSCB_S_WAIT_DELETE_ACK, 15, T_WAIT_DELETE_ACK);
		/* forward this event to all child FSMs (i.e. all smscb_message_peer) */
		osmo_fsm_inst_broadcast_children(fi, SMSCB_E_DELETE, data);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_fsm_wait_replace_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message *cbcmsg = fi->priv;
	struct osmo_fsm_inst *peer_fi;

	switch (event) {
	case SMSCB_E_CBSP_REPLACE_ACK:
	case SMSCB_E_CBSP_REPLACE_NACK:
		llist_for_each_entry(peer_fi, &fi->proc.children, proc.child) {
			if (peer_fi->state == SMSCB_S_WAIT_REPLACE_ACK)
				return;
		}
		rest_it_op_set_http_result(cbcmsg->it_op, 200, "OK"); // FIXME: error cases
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_fsm_wait_replace_ack_onleave(struct osmo_fsm_inst *fi, uint32_t new_state)
{
	struct cbc_message *cbcmsg = fi->priv;
	/* release the mutex from the REST interface + respond to user */
	rest_it_op_complete(cbcmsg->it_op);
	cbcmsg->it_op = NULL;
}

static void smscb_fsm_wait_status_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message *cbcmsg = fi->priv;
	struct osmo_fsm_inst *peer_fi;

	switch (event) {
	case SMSCB_E_CBSP_STATUS_ACK:
	case SMSCB_E_CBSP_STATUS_NACK:
		llist_for_each_entry(peer_fi, &fi->proc.children, proc.child) {
			if (peer_fi->state == SMSCB_S_WAIT_STATUS_ACK)
				return;
		}
		rest_it_op_set_http_result(cbcmsg->it_op, 200, "OK"); // FIXME: error cases
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_fsm_wait_status_ack_onleave(struct osmo_fsm_inst *fi, uint32_t new_state)
{
	struct cbc_message *cbcmsg = fi->priv;
	/* release the mutex from the REST interface + respond to user */
	rest_it_op_complete(cbcmsg->it_op);
	cbcmsg->it_op = NULL;
}

static void smscb_fsm_wait_delete_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct cbc_message *cbcmsg = fi->priv;
	struct osmo_fsm_inst *peer_fi;

	switch (event) {
	case SMSCB_E_CBSP_DELETE_ACK:
	case SMSCB_E_CBSP_DELETE_NACK:
		llist_for_each_entry(peer_fi, &fi->proc.children, proc.child) {
			if (peer_fi->state != SMSCB_S_DELETED)
				return;
		}
		rest_it_op_set_http_result(cbcmsg->it_op, 200, "OK"); // FIXME: error cases
		osmo_fsm_inst_state_chg(fi, SMSCB_S_DELETED, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_fsm_wait_delete_ack_onleave(struct osmo_fsm_inst *fi, uint32_t new_state)
{
	struct cbc_message *cbcmsg = fi->priv;
	/* release the mutex from the REST interface + respond to user */
	if (cbcmsg->it_op) {
		rest_it_op_complete(cbcmsg->it_op);
		cbcmsg->it_op = NULL;
	}
}

static void smscb_fsm_deleted_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	/* release the mutex from the REST interface, then destroy */
	struct cbc_message *cbcmsg = fi->priv;
	if (cbcmsg->it_op) {
		rest_it_op_complete(cbcmsg->it_op);
		cbcmsg->it_op = NULL;
	}
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static struct osmo_fsm_state smscb_fsm_states[] = {
	[SMSCB_S_INIT] = {
		.name = "INIT",
		.in_event_mask = S(SMSCB_E_CREATE),
		.out_state_mask = S(SMSCB_S_WAIT_WRITE_ACK),
		.action = smscb_fsm_init,
	},
	[SMSCB_S_WAIT_WRITE_ACK] = {
		.name = "WAIT_WRITE_ACK",
		.in_event_mask = S(SMSCB_E_CBSP_WRITE_ACK) |
				 S(SMSCB_E_CBSP_WRITE_NACK),
		.out_state_mask = S(SMSCB_S_ACTIVE),
		.action = smscb_fsm_wait_write_ack,
		.onleave = smscb_fsm_wait_write_ack_onleave,
	},
	[SMSCB_S_ACTIVE] = {
		.name = "ACTIVE",
		.in_event_mask = S(SMSCB_E_REPLACE) |
				 S(SMSCB_E_STATUS) |
				 S(SMSCB_E_DELETE),
		.out_state_mask = S(SMSCB_S_ACTIVE) |
				  S(SMSCB_S_WAIT_REPLACE_ACK) |
				  S(SMSCB_S_WAIT_STATUS_ACK) |
				  S(SMSCB_S_WAIT_DELETE_ACK),
		.action = smscb_fsm_active,
	},
	[SMSCB_S_WAIT_REPLACE_ACK] = {
		.name = "WAIT_REPLACE_ACK",
		.in_event_mask = S(SMSCB_E_CBSP_REPLACE_ACK) |
				 S(SMSCB_E_CBSP_REPLACE_NACK),
		.out_state_mask = S(SMSCB_S_ACTIVE),
		.action = smscb_fsm_wait_replace_ack,
		.onleave = smscb_fsm_wait_replace_ack_onleave,
	},
	[SMSCB_S_WAIT_STATUS_ACK] = {
		.name = "WAIT_STATUS_ACK",
		.in_event_mask = S(SMSCB_E_CBSP_STATUS_ACK) |
				 S(SMSCB_E_CBSP_STATUS_NACK),
		.out_state_mask = S(SMSCB_S_ACTIVE),
		.action = smscb_fsm_wait_status_ack,
		.onleave = smscb_fsm_wait_status_ack_onleave,
	},
	[SMSCB_S_WAIT_DELETE_ACK] = {
		.name = "WAIT_DELETE_ACK",
		.in_event_mask = S(SMSCB_E_CBSP_DELETE_ACK) |
				 S(SMSCB_E_CBSP_DELETE_NACK),
		.out_state_mask = S(SMSCB_S_DELETED),
		.action = smscb_fsm_wait_delete_ack,
		.onleave = smscb_fsm_wait_delete_ack_onleave,
	},
	[SMSCB_S_DELETED] = {
		.name = "DELETED",
		.in_event_mask = 0,
		.out_state_mask = 0,
		.onenter = smscb_fsm_deleted_onenter,
		//.action = smscb_fsm_deleted,
	},
};

static int smscb_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	case T_WAIT_WRITE_ACK:
		/* onexit will take care of notifying the user */
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		break;
	case T_WAIT_REPLACE_ACK:
		/* onexit will take care of notifying the user */
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		break;
	case T_WAIT_STATUS_ACK:
		/* onexit will take care of notifying the user */
		osmo_fsm_inst_state_chg(fi, SMSCB_S_ACTIVE, 0, 0);
		break;
	case T_WAIT_DELETE_ACK:
		/* onexit will take care of notifying the user */
		osmo_fsm_inst_state_chg(fi, SMSCB_S_DELETED, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static void smscb_fsm_allstate(struct osmo_fsm_inst *Fi, uint32_t event, void *data)
{
	switch (event) {
	case SMSCB_E_CHILD_DIED:
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void smscb_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct cbc_message *cbcmsg = fi->priv;

	OSMO_ASSERT(llist_empty(&cbcmsg->peers));

	llist_del(&cbcmsg->list);
	/* memory of cbcmsg is child of fi and hence automatically free'd */
}

static struct osmo_fsm smscb_fsm = {
	.name = "SMSCB",
	.states = smscb_fsm_states,
	.num_states = ARRAY_SIZE(smscb_fsm_states),
	.allstate_event_mask = S(SMSCB_E_CHILD_DIED),
	.allstate_action = smscb_fsm_allstate,
	.timer_cb = smscb_fsm_timer_cb,
	.log_subsys = DCBSP,
	.event_names = smscb_fsm_event_names,
	.cleanup= smscb_fsm_cleanup,
};


/* allocate a cbc_message, fill it with data from orig_msg, create FSM */
struct cbc_message *cbc_message_alloc(void *ctx, const struct cbc_message *orig_msg)
{
	struct cbc_message *smscb;
	struct osmo_fsm_inst *fi;
	char idbuf[32];

	if (cbc_message_by_id(orig_msg->msg.message_id)) {
		LOGP(DCBSP, LOGL_ERROR, "Cannot create message_id %u (already exists)\n",
			orig_msg->msg.message_id);
		return NULL;
	}

	snprintf(idbuf, sizeof(idbuf), "%s-%u", orig_msg->cbe_name, orig_msg->msg.message_id);
	fi = osmo_fsm_inst_alloc(&smscb_fsm, ctx, NULL, LOGL_INFO, idbuf);
	if (!fi) {
		LOGP(DCBSP, LOGL_ERROR, "Cannot allocate cbc_message fsm\n");
		return NULL;
	}

	smscb = talloc(fi, struct cbc_message);
	if (!smscb) {
		LOGP(DCBSP, LOGL_ERROR, "Cannot allocate cbc_message\n");
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	/* copy data from original message */
	memcpy(smscb, orig_msg, sizeof(*smscb));
	smscb->cbe_name  = talloc_strdup(smscb, orig_msg->cbe_name);
	/* initialize other members */
	INIT_LLIST_HEAD(&smscb->peers);
	smscb->fi = fi;
	smscb->it_op = NULL;
	smscb->time.created = time(NULL);

	fi->priv = smscb;

	/* add to global list of messages */
	llist_add_tail(&smscb->list, &g_cbc->messages);

	return smscb;
}

__attribute__((constructor)) void smscb_fsm_constructor(void)
{
	OSMO_ASSERT(osmo_fsm_register(&smscb_fsm) == 0);
}
