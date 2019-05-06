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

/* message was received from remote CBSP peer (BSC) */
int cbc_client_rx_cb(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *dec)
{
	switch (dec->msg_type) {
	case CBSP_MSGT_RESTART:
		osmo_fsm_inst_dispatch(client->fi, CBSP_SRV_E_RX_RESTART, dec);
		break;
	default:
		LOGPCC(client, LOGL_ERROR, "unknown/unhandled %s\n",
			get_value_string(cbsp_msg_type_names, dec->msg_type));
		break;
	}
	return 0;
}

static __attribute__((constructor)) void on_dso_load_cbsp_srv_fsm(void)
{
	osmo_fsm_register(&cbsp_server_fsm);
}
