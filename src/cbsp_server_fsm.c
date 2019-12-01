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

#include <osmocom/core/fsm.h>

#include <osmocom/gsm/cbsp.h>

#include "cbsp_server.h"
#include "internal.h"

#define S(x)	(1 << (x))

#define T_KEEPALIVE			1
#define T_KEEPALIVE_SECS		30

#define T_WAIT_KEEPALIVE_RESP		2
#define T_WAIT_KEEPALIVE_RESP_SECS	10

#define T_WAIT_RESET_RESP		3
#define T_WAIT_RESET_RESP_SECS		5

enum cbsp_server_state {
	/* initial state after client TCP connection established */
	CBSP_SRV_S_INIT,
	/* RESET has been sent to BSC, waiting for response */
	CBSP_SRV_S_RESET_PENDING,
	/* Keep-Alive has been sent, waiting for response */
	CBSP_SRV_S_KEEPALIVE_PENDING,
	/* normal operation (idle) */
	CBSP_SRV_S_IDLE,
};

static const struct value_string cbsp_server_event_names[] = {
	{ CBSP_SRV_E_RX_RST_COMPL, "Rx Reset Complete" },
	{ CBSP_SRV_E_RX_RST_FAIL, "Rx Reset Failure" },
	{ CBSP_SRV_E_RX_KA_COMPL, "Rx Keep-Alive Complete" },
	{ CBSP_SRV_E_RX_RESTART, "Rx Restart" },
	{ CBSP_SRV_E_CMD_RESET, "RESET.cmd" },
	{ 0, NULL }
};

static void cbsp_server_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case CBSP_SRV_E_CMD_RESET:
		osmo_fsm_inst_state_chg(fi, CBSP_SRV_S_RESET_PENDING, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void cbsp_server_s_reset_pending_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_cbsp_cbc_client *client = (struct osmo_cbsp_cbc_client *) fi->priv;
	struct osmo_cbsp_decoded *cbspd;

	if (prev_state == CBSP_SRV_S_RESET_PENDING)
		return;

	cbspd = talloc_zero(fi, struct osmo_cbsp_decoded);
	OSMO_ASSERT(cbspd);
	cbspd->msg_type = CBSP_MSGT_RESET;
	cbspd->u.reset.cell_list.id_discr = CELL_IDENT_BSS;
	INIT_LLIST_HEAD(&cbspd->u.reset.cell_list.list);

	cbsp_cbc_client_tx(client, cbspd);
	/* wait for response */
	osmo_fsm_inst_state_chg(fi, CBSP_SRV_S_RESET_PENDING, T_WAIT_RESET_RESP_SECS,
				T_WAIT_RESET_RESP);
}

static void cbsp_server_s_reset_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case CBSP_SRV_E_RX_RST_COMPL:
		osmo_fsm_inst_state_chg(fi, CBSP_SRV_S_IDLE, 0, 0);
		break;
	case CBSP_SRV_E_RX_RST_FAIL:
		osmo_fsm_inst_state_chg(fi, CBSP_SRV_S_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void cbsp_server_s_keepalive_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case CBSP_SRV_E_RX_KA_COMPL:
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* a bit of a hack to ensure the keep-aliver timer is started every time we enter
 * the IDLE state, without putting the burden on the caller of
 * osmo_fsm_inst_state_chg() to specify T_KEEPALIVE + T_KEEPALIVE_SECS */
static void cbsp_server_s_idle_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	fi->T = T_KEEPALIVE;
	osmo_timer_schedule(&fi->timer, T_KEEPALIVE_SECS, 0);
}

static void cbsp_server_s_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	default:
		OSMO_ASSERT(0);
	}
}

static int cbsp_server_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct osmo_cbsp_cbc_client *client = (struct osmo_cbsp_cbc_client *) fi->priv;
	struct osmo_cbsp_decoded *cbspd;

	switch (fi->T) {
	case T_KEEPALIVE:
		/* send keepalive to peer */
		cbspd = talloc_zero(fi, struct osmo_cbsp_decoded);
		OSMO_ASSERT(cbspd);
		cbspd->msg_type = CBSP_MSGT_KEEP_ALIVE;
		cbspd->u.keep_alive.repetition_period = T_KEEPALIVE_SECS;
		cbsp_cbc_client_tx(client, cbspd);
		/* wait for response */
		osmo_fsm_inst_state_chg(fi, CBSP_SRV_S_KEEPALIVE_PENDING, T_WAIT_KEEPALIVE_RESP_SECS,
					T_WAIT_KEEPALIVE_RESP);
		return 0;
	case T_WAIT_KEEPALIVE_RESP:
	case T_WAIT_RESET_RESP:
		/* ask core to terminate FSM which will terminate TCP connection */
		return 1;
	default:
		OSMO_ASSERT(0);
	}
}

static const struct osmo_fsm_state cbsp_server_fsm_states[] = {
	[CBSP_SRV_S_INIT] = {
		.name = "INIT",
		.in_event_mask = S(CBSP_SRV_E_CMD_RESET),
		.out_state_mask = S(CBSP_SRV_S_RESET_PENDING),
		.action = cbsp_server_s_init,
	},
	[CBSP_SRV_S_RESET_PENDING] = {
		.name = "RESET_PENDING",
		.in_event_mask = S(CBSP_SRV_E_RX_RST_COMPL) |
				 S(CBSP_SRV_E_RX_RST_FAIL),
		.out_state_mask = S(CBSP_SRV_S_IDLE) |
				  S(CBSP_SRV_S_RESET_PENDING),
		.action = cbsp_server_s_reset_pending,
		.onenter = cbsp_server_s_reset_pending_onenter,
	},
	[CBSP_SRV_S_KEEPALIVE_PENDING] = {
		.name = "KEEPALIVE_PENDING",
		.in_event_mask = S(CBSP_SRV_E_RX_KA_COMPL),
		.out_state_mask = S(CBSP_SRV_S_IDLE) |
				  S(CBSP_SRV_S_KEEPALIVE_PENDING),
		.action = cbsp_server_s_keepalive_pending,
	},
	[CBSP_SRV_S_IDLE] = {
		.name = "IDLE",
		.in_event_mask = 0,
		.out_state_mask = S(CBSP_SRV_S_KEEPALIVE_PENDING),
		.action = cbsp_server_s_idle,
		.onenter = cbsp_server_s_idle_onenter,
	},
};

struct osmo_fsm cbsp_server_fsm = {
	.name = "CBSP-SERVER",
	.states = cbsp_server_fsm_states,
	.num_states = ARRAY_SIZE(cbsp_server_fsm_states),
	.timer_cb = cbsp_server_fsm_timer_cb,
	.log_subsys = DCBSP,
	.event_names = cbsp_server_event_names,
};

static int get_msg_id(const struct osmo_cbsp_decoded *dec)
{
	switch (dec->msg_type) {
	case CBSP_MSGT_WRITE_REPLACE_COMPL:
		return dec->u.write_replace_compl.msg_id;
	case CBSP_MSGT_WRITE_REPLACE_FAIL:
		return dec->u.write_replace_fail.msg_id;
	case CBSP_MSGT_KILL_COMPL:
		return dec->u.kill_compl.msg_id;
	case CBSP_MSGT_KILL_FAIL:
		return dec->u.kill_fail.msg_id;
	case CBSP_MSGT_MSG_STATUS_QUERY_COMPL:
		return dec->u.msg_status_query_compl.msg_id;
	case CBSP_MSGT_MSG_STATUS_QUERY_FAIL:
		return dec->u.msg_status_query_fail.msg_id;
	default:
		return -1;
	}
}

/* message was received from remote CBSP peer (BSC) */
int cbc_client_rx_cb(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *dec)
{
	struct cbc_message *smscb;
	struct cbc_message_peer *mp;
	int msg_id;

	/* messages without reference to a specific SMSCB message */
	switch (dec->msg_type) {
	case CBSP_MSGT_RESTART:
		osmo_fsm_inst_dispatch(client->fi, CBSP_SRV_E_RX_RESTART, dec);
		return 0;
	case CBSP_MSGT_KEEP_ALIVE_COMPL:
		osmo_fsm_inst_dispatch(client->fi, CBSP_SRV_E_RX_KA_COMPL, dec);
		return 0;
	case CBSP_MSGT_FAILURE:
		LOGPCC(client, LOGL_ERROR, "CBSP FAILURE (bcast_msg_type=%u)\n",
			dec->u.failure.bcast_msg_type);
		/* TODO: failure list */
		return 0;
	case CBSP_MSGT_ERROR_IND:
		LOGPCC(client, LOGL_ERROR, "CBSP ERROR_IND (cause=%u, msg_id=0x%04x)\n",
			dec->u.error_ind.cause,
			dec->u.error_ind.msg_id ? *dec->u.error_ind.msg_id : 0xffff);
		/* TODO: old/new serial number, channel_ind */
		return 0;
	case CBSP_MSGT_KEEP_ALIVE:
	case CBSP_MSGT_LOAD_QUERY_COMPL:
	case CBSP_MSGT_LOAD_QUERY_FAIL:
	case CBSP_MSGT_SET_DRX_COMPL:
	case CBSP_MSGT_SET_DRX_FAIL:
	case CBSP_MSGT_RESET_COMPL:
	case CBSP_MSGT_RESET_FAIL:
		LOGPCC(client, LOGL_ERROR, "unimplemented message %s\n",
			get_value_string(cbsp_msg_type_names, dec->msg_type));
		return 0;
	default:
		break;
	}

	/* messages with reference to a specific SMSCB message handled below*/
	msg_id = get_msg_id(dec);
	OSMO_ASSERT(msg_id >= 0);

	/* look-up smscb_message */
	smscb = cbc_message_by_id(msg_id);
	if (!smscb) {
		LOGPCC(client, LOGL_ERROR, "%s for unknown message-id 0x%04x\n",
			get_value_string(cbsp_msg_type_names, dec->msg_type), msg_id);
		/* TODO: inform peer? */
		return 0;
	}

	/* look-up smscb_message_peer */
	mp = cbc_message_peer_get(smscb, client->peer);
	if (!mp) {
		LOGPCC(client, LOGL_ERROR, "%s for message-id 0x%04x without peer %s\n",
			get_value_string(cbsp_msg_type_names, dec->msg_type), msg_id, client->peer->name);
		/* TODO: inform peer? */
		return 0;
	}

	/* dispatch event to smscp_p_fms instance */
	switch (dec->msg_type) {
	case CBSP_MSGT_WRITE_REPLACE_COMPL:
		if (dec->u.write_replace_compl.old_serial_nr)
			return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_REPLACE_ACK, dec);
		else
			return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_WRITE_ACK, dec);
	case CBSP_MSGT_WRITE_REPLACE_FAIL:
		if (dec->u.write_replace_fail.old_serial_nr)
			return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_REPLACE_NACK, dec);
		else
			return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_WRITE_NACK, dec);
	case CBSP_MSGT_KILL_COMPL:
		return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_DELETE_ACK, dec);
	case CBSP_MSGT_KILL_FAIL:
		return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_DELETE_NACK, dec);
	case CBSP_MSGT_MSG_STATUS_QUERY_COMPL:
		return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_STATUS_ACK, dec);
	case CBSP_MSGT_MSG_STATUS_QUERY_FAIL:
		return osmo_fsm_inst_dispatch(mp->fi, SMSCB_E_CBSP_STATUS_NACK, dec);
	default:
		LOGPCC(client, LOGL_ERROR, "unknown message %s\n",
			get_value_string(cbsp_msg_type_names, dec->msg_type));
		break;
	}
	return 0;
}

static __attribute__((constructor)) void on_dso_load_cbsp_srv_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&cbsp_server_fsm) == 0);
}
