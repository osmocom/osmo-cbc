/* Osmocom CBC (Cell Broacast Centre) */

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

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>

#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/cbc_message.h>
#include <osmocom/cbc/cbc_peer.h>
#include <osmocom/cbc/cbc_vty.h>
#include <osmocom/cbc/cbsp_link.h>
#include <osmocom/cbc/sbcap_link.h>

static const struct value_string cbc_peer_proto_name_vty[] = {
	{ CBC_PEER_PROTO_CBSP, "cbsp" },
	{ CBC_PEER_PROTO_SABP, "sabp" },
	{ CBC_PEER_PROTO_SBcAP, "sbcap" },
	{ 0, NULL }
};

#define CBC_PEER_PROTO_NAME_VTY_CMD "(cbsp|sbcap)"
#define CBC_PEER_PROTO_NAME_VTY_STR "Cell Broadcast Service Protocol (GSM)\n" \
				     "SBc Application Part (LTE)\n"

static void dump_one_cbc_peer(struct vty *vty, const struct cbc_peer *peer)
{
	const char *state = "<disconnected>";
	char rem_addrs[1024] = "<unset>";
	struct osmo_strbuf sb = { .buf = rem_addrs, .len = sizeof(rem_addrs) };
	unsigned int i;

	switch (peer->proto) {
	case CBC_PEER_PROTO_CBSP:
		if (peer->link.cbsp)
			state = osmo_fsm_inst_state_name(peer->link.cbsp->fi);
		break;
	case CBC_PEER_PROTO_SABP:
		break;
	case CBC_PEER_PROTO_SBcAP:
		if (peer->link.sbcap)
			state = osmo_fsm_inst_state_name(peer->link.sbcap->fi);
		break;
	}

	for (i = 0; i < peer->num_remote_host; i++) {
		if (i > 0)
			OSMO_STRBUF_PRINTF(sb, ",");
		OSMO_STRBUF_PRINTF(sb, "%s", peer->remote_host[i]);
	}

	vty_out(vty, "|%-20s| %-15s| %-5d| %-6s| %-20s|%s",
		peer->name ? peer->name : "<unnamed>",
		rem_addrs, peer->remote_port,
		get_value_string(cbc_peer_proto_name, peer->proto), state, VTY_NEWLINE);
}

DEFUN(show_peers, show_peers_cmd,
	"show peers",
	SHOW_STR "Display Information about RAN peers connected to this CBC\n")
{
	struct cbc_peer *peer;

	vty_out(vty,
"|Name                | IP             | Port | Proto | State               |%s", VTY_NEWLINE);
	vty_out(vty,
"|--------------------|----------------|------|-------|---------------------|%s", VTY_NEWLINE);
	llist_for_each_entry(peer, &g_cbc->peers, list)
		dump_one_cbc_peer(vty, peer);

	return CMD_SUCCESS;
}

#define MESSAGES_STR "Display information about currently active SMSCB messages\n"
#define MESSAGES_CBS_STR "Display Cell Broadcast Service (CBS) messages\n"

static void dump_one_cbc_msg(struct vty *vty, const struct cbc_message *cbc_msg)
{
	const struct smscb_message *smscb = &cbc_msg->msg;

	OSMO_ASSERT(!smscb->is_etws);

	vty_out(vty, "| %04X| %04X|%-20s|%-13s|  %-4u|%c| %02x|%s",
		smscb->message_id, smscb->serial_nr, cbc_msg->cbe_name,
		get_value_string(cbsp_category_names, cbc_msg->priority), cbc_msg->rep_period,
		cbc_msg->extended_cbch ? 'E' : 'N', smscb->cbs.dcs,
		VTY_NEWLINE);
}

DEFUN(show_messages_cbs, show_messages_cbs_cmd,
	"show messages cbs",
	SHOW_STR MESSAGES_STR MESSAGES_CBS_STR)
{
	struct cbc_message *cbc_msg;

	vty_out(vty,
"|MsgId|SerNo|      CBE Name      |  Category   |Period|E|DCS|%s", VTY_NEWLINE);
	vty_out(vty,
"|-----|-----|--------------------|-------------|------|-|---|%s", VTY_NEWLINE);

	llist_for_each_entry(cbc_msg, &g_cbc->messages, list) {
		if (cbc_msg->msg.is_etws)
			continue;
		dump_one_cbc_msg(vty, cbc_msg);
	}

	llist_for_each_entry(cbc_msg, &g_cbc->expired_messages, list) {
		if (cbc_msg->msg.is_etws)
			continue;
		dump_one_cbc_msg(vty, cbc_msg);
	}

	return CMD_SUCCESS;
}

static const char *cbc_cell_id2str(const struct cbc_cell_id *cid)
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
	default:
		snprintf(buf, sizeof(buf), "<invalid>");
		break;
	}
	return buf;
}

static void dump_one_msg_peer(struct vty *vty, const struct cbc_message_peer *msg_peer, const char *pfx)
{
	struct cbc_cell_id *cid;

	vty_out(vty, "%sPeer: '%s', State: %s%s", pfx, msg_peer->peer->name,
		osmo_fsm_inst_state_name(msg_peer->fi), VTY_NEWLINE);


	vty_out(vty, "%s Cells Installed:%s", pfx, VTY_NEWLINE);
	llist_for_each_entry(cid, &msg_peer->cell_list, list) {
		vty_out(vty, "%s  %s%s", pfx, cbc_cell_id2str(cid), VTY_NEWLINE);
	}

	vty_out(vty, "%s Cells Failed:%s", pfx, VTY_NEWLINE);
	llist_for_each_entry(cid, &msg_peer->fail_list, list) {
		vty_out(vty, "%s  %s (cause=%d)%s", pfx, cbc_cell_id2str(cid), cid->fail.cause, VTY_NEWLINE);
	}

	vty_out(vty, "%s Number of Broadcasts Completed:%s", pfx, VTY_NEWLINE);
	llist_for_each_entry(cid, &msg_peer->num_compl_list, list) {
		vty_out(vty, "%s  %s (%u/%u)%s", pfx, cbc_cell_id2str(cid),
			cid->num_compl.num_compl, cid->num_compl.num_bcast_info, VTY_NEWLINE);
	}
}


DEFUN(show_message_cbs, show_message_cbs_cmd,
	"show message id <0-65535>",
	SHOW_STR MESSAGES_STR "Message ID\n" "Message ID\n")
{
	const struct cbc_message *cbc_msg;
	const struct smscb_message *smscb;
	struct cbc_message_peer *msg_peer;
	char *timestr;

	cbc_msg = cbc_message_by_id(atoi(argv[0]));
	if (!cbc_msg) {
		vty_out(vty, "Unknown Messsage ID %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	smscb = &cbc_msg->msg;

	vty_out(vty, "Message ID %04X, Serial Number %04X, State: %s%s", smscb->message_id, smscb->serial_nr,
		osmo_fsm_inst_state_name(cbc_msg->fi), VTY_NEWLINE);
	timestr = ctime(&cbc_msg->time.created);
	timestr[strlen(timestr)-1] = '\0';	/* stupid \n termination of ctime() */
	vty_out(vty, " Created by CBE '%s' at %s%s", cbc_msg->cbe_name, timestr, VTY_NEWLINE);
	vty_out(vty, " Repetition Period: %u (%5.2fs), Number of broadcasts: %u%s",
		cbc_msg->rep_period, (float)cbc_msg->rep_period * 1.883,
		cbc_msg->num_bcast, VTY_NEWLINE);

	if (!smscb->is_etws) {
		int i;
		vty_out(vty, " Warning Period: %us%s", cbc_msg->warning_period_sec, VTY_NEWLINE);
		vty_out(vty, " DCS: 0x%02x, Number of pages: %u, User Data Bytes: %u%s", smscb->cbs.dcs,
			smscb->cbs.num_pages, smscb->cbs.data_user_len, VTY_NEWLINE);
		for (i = 0; i < smscb->cbs.num_pages; i++) {
			vty_out(vty, " Page %u: %s%s", i,
				osmo_hexdump_nospc(smscb->cbs.data[i], sizeof(smscb->cbs.data[i])),
				VTY_NEWLINE);
		}
		/* FIXME: more */
	} else {
		vty_out(vty, " ETWS Warning Type Value: 0x%02x, User Alert: %s, Popup: %s%s",
			smscb->etws.warning_type, smscb->etws.user_alert ? "On" : "Off",
			smscb->etws.popup_on_display ? "On" : "Off", VTY_NEWLINE);
		vty_out(vty, " Security: %s%s",
			osmo_hexdump_nospc(smscb->etws.warning_sec_info, sizeof(smscb->etws.warning_sec_info)),
			VTY_NEWLINE);
	}

	llist_for_each_entry(msg_peer, &cbc_msg->peers, list)
		dump_one_msg_peer(vty, msg_peer, " ");

	return CMD_SUCCESS;
}

static void dump_one_etws_msg(struct vty *vty, const struct cbc_message *cbc_msg)
{
	const struct smscb_message *smscb = &cbc_msg->msg;

	OSMO_ASSERT(smscb->is_etws);

	vty_out(vty, "| %04X| %04X|%-20s|%-13s|  %-4u|%c|         %04d|%s",
		smscb->message_id, smscb->serial_nr, cbc_msg->cbe_name,
		get_value_string(cbsp_category_names, cbc_msg->priority), cbc_msg->rep_period,
		cbc_msg->extended_cbch ? 'E' : 'N', smscb->etws.warning_type,
		VTY_NEWLINE);
}

DEFUN(show_messages_etws, show_messages_etws_cmd,
	"show messages etws",
	SHOW_STR MESSAGES_STR "Display ETWS (CMAS, KPAS, EU-ALERT, PWS, WEA) Emergency messages\n")
{
	struct cbc_message *cbc_msg;

	vty_out(vty,
"|MsgId|SerNo|      CBE Name      |  Category   |Period|E|Warning Type|%s", VTY_NEWLINE);
	vty_out(vty,
"|-----|-----|--------------------|-------------|------|-|------------|%s", VTY_NEWLINE);

	llist_for_each_entry(cbc_msg, &g_cbc->messages, list) {
		if (!cbc_msg->msg.is_etws)
			continue;
		dump_one_etws_msg(vty, cbc_msg);
	}

	llist_for_each_entry(cbc_msg, &g_cbc->expired_messages, list) {
		if (!cbc_msg->msg.is_etws)
			continue;
		dump_one_etws_msg(vty, cbc_msg);
	}

	return CMD_SUCCESS;
}

/* TODO: Show a single message; with details about scope + payload */
/* TODO: Delete a single message; either from one peer or globally from all */
/* TODO: Re-send all messages to one peer / all peers? */
/* TODO: Completed / Load status */

static struct cmd_node cbc_node = {
	CBC_NODE,
	"%s(config-cbc)# ",
	1,
};

static struct cmd_node peer_node = {
	PEER_NODE,
	"%s(config-cbc-peer)# ",
	1,
};

DEFUN(cfg_cbc, cfg_cbc_cmd,
	"cbc",
	"Cell Broadcast Centre\n")
{
	vty->node = CBC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_permit_unknown_peers, cfg_permit_unknown_peers_cmd,
	"unknown-peers (accept|reject)",
	"What to do with peers from unknown IP/port\n"
	"Accept peers from unknown/unconfigured source IP/port\n"
	"Reject peers from unknown/unconfigured source IP/port\n")
{
	if (!strcmp(argv[0], "accept"))
		g_cbc->config.permit_unknown_peers = true;
	else
		g_cbc->config.permit_unknown_peers = false;
	return CMD_SUCCESS;
}

static int config_write_ecbe(struct vty *vty);
static int config_write_cbsp(struct vty *vty);
static int config_write_sbcap(struct vty *vty);
static int config_write_peer(struct vty *vty);

static int config_write_cbc(struct vty *vty)
{
	vty_out(vty, "cbc%s", VTY_NEWLINE);
	vty_out(vty, " unknown-peers %s%s",
		g_cbc->config.permit_unknown_peers ? "accept" : "reject", VTY_NEWLINE);
	config_write_ecbe(vty);
	config_write_cbsp(vty);
	config_write_sbcap(vty);
	config_write_peer(vty);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbsp, cfg_cbsp_cmd,
	"cbsp",
	"Cell Broadcast Service Protocol\n")
{
	vty->node = CBSP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_sbcap, cfg_sbcap_cmd,
	"sbcap",
	"SBc Application Part\n")
{
	vty->node = SBcAP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_ecbe, cfg_ecbe_cmd,
	"ecbe",
	"External CBS Entity (REST Interface)\n")
{
	vty->node = ECBE_NODE;
	return CMD_SUCCESS;
}


/* CBSP */

static struct cmd_node cbsp_node = {
	CBSP_NODE,
	"%s(config-cbsp)# ",
	1,
};

static int config_write_cbsp(struct vty *vty)
{
	vty_out(vty, " cbsp%s", VTY_NEWLINE);
	vty_out(vty, "  local-ip %s%s", g_cbc->config.cbsp.local_host, VTY_NEWLINE);
	vty_out(vty, "  local-port %u%s", g_cbc->config.cbsp.local_port, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_cbsp_local_ip, cfg_cbsp_local_ip_cmd,
	"local-ip " VTY_IPV46_CMD,
	"Local IP address for CBSP\n"
	"Local IPv4 address for CBSP\n" "Local IPv6 address for CBSP\n")
{
	osmo_talloc_replace_string(g_cbc, &g_cbc->config.cbsp.local_host, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_cbsp_local_port, cfg_cbsp_local_port_cmd,
	"local-port <0-65535>",
	"Local TCP port for CBSP\n"
	"Local TCP port for CBSP\n")
{
	g_cbc->config.cbsp.local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}


/* ECBE */

static struct cmd_node ecbe_node = {
	ECBE_NODE,
	"%s(config-ecbe)# ",
	1,
};

static int config_write_ecbe(struct vty *vty)
{
	vty_out(vty, " ecbe%s", VTY_NEWLINE);
	vty_out(vty, "  local-ip %s%s", g_cbc->config.ecbe.local_host, VTY_NEWLINE);
	vty_out(vty, "  local-port %u%s", g_cbc->config.ecbe.local_port, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_ecbe_local_ip, cfg_ecbe_local_ip_cmd,
	"local-ip " VTY_IPV46_CMD,
	"Local IP address for CBSP\n"
	"Local IPv4 address for ECBE REST Interface\n"
	"Local IPv6 address for ECBE REST Interface\n")
{
	osmo_talloc_replace_string(g_cbc, &g_cbc->config.ecbe.local_host, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_ecbe_local_port, cfg_ecbe_local_port_cmd,
	"local-port <0-65535>",
	"Local TCP port for ECBE REST Interface\n"
	"Local TCP port for ECBE REST Interface\n")
{
	g_cbc->config.ecbe.local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* SBc-AP */

static struct cmd_node sbcap_node = {
	SBcAP_NODE,
	"%s(config-sbcap)# ",
	1,
};

static int config_write_sbcap(struct vty *vty)
{
	unsigned int i;

	vty_out(vty, " sbcap%s", VTY_NEWLINE);
	for (i = 0; i < g_cbc->config.sbcap.num_local_host; i++)
		vty_out(vty, "  local-ip %s%s", g_cbc->config.sbcap.local_host[i], VTY_NEWLINE);
	vty_out(vty, "  local-port %u%s", g_cbc->config.sbcap.local_port, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_sbcap_local_ip, cfg_sbcap_local_ip_cmd,
	"local-ip " VTY_IPV46_CMD,
	"Local IP address for SBc-AP\n"
	"Local IPv4 address for SBc-AP Interface\n"
	"Local IPv6 address for SBc-AP Interface\n")
{
	unsigned int i;
	const char *newaddr = argv[0];

	if (g_cbc->config.sbcap.num_local_host >= ARRAY_SIZE(g_cbc->config.sbcap.local_host)) {
		vty_out(vty, "%% Only up to %zu addresses allowed%s",
			ARRAY_SIZE(g_cbc->config.sbcap.local_host), VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Check for repeated entries: */
	for (i = 0; i < g_cbc->config.sbcap.num_local_host; i++) {
		if (strcmp(g_cbc->config.sbcap.local_host[i], newaddr) == 0) {
			vty_out(vty, "%% IP address %s already in list%s", newaddr, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}
	osmo_talloc_replace_string(g_cbc,
		&g_cbc->config.sbcap.local_host[g_cbc->config.sbcap.num_local_host], newaddr);
	g_cbc->config.sbcap.num_local_host++;
	return CMD_SUCCESS;
}

DEFUN(cfg_sbcap_no_local_ip, cfg_sbcap_no_local_ip_cmd,
	"no local-ip " VTY_IPV46_CMD,
	NO_STR "Local IP address for SBc-AP\n"
	"Local IPv4 address for SBc-AP Interface\n"
	"Local IPv6 address for SBc-AP Interface\n")
{
	unsigned int i, j;
	const char *rmaddr = argv[0];

	for (i = 0; i < g_cbc->config.sbcap.num_local_host; i++) {
		if (strcmp(g_cbc->config.sbcap.local_host[i], rmaddr) == 0) {
			talloc_free(g_cbc->config.sbcap.local_host[i]);
			g_cbc->config.sbcap.num_local_host--;
			for (j = i; j < g_cbc->config.sbcap.num_local_host; j++) {
				g_cbc->config.sbcap.local_host[j] = g_cbc->config.sbcap.local_host[j + 1];
			}
			g_cbc->config.sbcap.local_host[j] = NULL;
			return CMD_SUCCESS;
		}
	}
	vty_out(vty, "%% IP address %s not in list%s", rmaddr, VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(cfg_sbcap_local_port, cfg_sbcap_local_port_cmd,
	"local-port <0-65535>",
	"Local TCP port for SBc-AP Interface\n"
	"Local TCP port for SBc-AP Interface\n")
{
	g_cbc->config.sbcap.local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}


/* PEER */

DEFUN_DEPRECATED(cfg_cbc_peer_old, cfg_cbc_peer_old_cmd,
	"peer NAME",
	"Remote Peer\n"
	"Name identifying the peer\n")
{
	struct cbc_peer *peer;

	vty_out(vty, "%% This function is deprecated, use "
		"'peer " CBC_PEER_PROTO_NAME_VTY_CMD " NAME' instead. "
		"Assuming 'cbsp' for peers being created%s", VTY_NEWLINE);

	peer = cbc_peer_by_name(argv[0]);
	if (!peer)
		peer = cbc_peer_create(argv[0], CBC_PEER_PROTO_CBSP);
	if (!peer)
		return CMD_WARNING;

	vty->node = PEER_NODE;
	vty->index = peer;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_peer, cfg_cbc_peer_cmd,
	"peer " CBC_PEER_PROTO_NAME_VTY_CMD " NAME",
	"Remote Peer\n"
	CBC_PEER_PROTO_NAME_VTY_STR
	"Name identifying the peer\n")
{
	struct cbc_peer *peer;
	enum cbc_peer_protocol proto;

	proto = get_string_value(cbc_peer_proto_name_vty, argv[0]);
	peer = cbc_peer_by_name(argv[1]);
	if (!peer)
		peer = cbc_peer_create(argv[1], proto);
	if (!peer)
		return CMD_WARNING;

	vty->node = PEER_NODE;
	vty->index = peer;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_no_peer, cfg_cbc_no_peer_cmd,
	"no peer NAME",
	NO_STR "Remote Peer\n"
	"Name identifying the peer\n")
{
	struct cbc_peer *peer;

	peer = cbc_peer_by_name(argv[0]);
	if (!peer) {
		vty_out(vty, "%% Unknown peer '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	cbc_peer_remove(peer);
	return CMD_SUCCESS;
}


DEFUN_DEPRECATED(cfg_peer_proto, cfg_peer_proto_cmd,
	"protocol " CBC_PEER_PROTO_NAME_VTY_CMD,
	"Configure Protocol of Peer\n"
	CBC_PEER_PROTO_NAME_VTY_STR)
{
	vty_out(vty, "%% This function is deprecated and does nothing, use "
		"'peer " CBC_PEER_PROTO_NAME_VTY_CMD " NAME' instead%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_peer_mode, cfg_peer_mode_cmd,
	"mode (server|client|disabled)",
	"Connect to peer as TCP(CBSP)/SCTP(SBc-AP) server or client\n"
	"server: listen for inbound TCP (CBSP) / SCTP (SBc-AP) connections from a remote peer\n"
	"client: establish outbound TCP (CBSP) / SCTP (SBc-AP) connection to a remote peer\n"
	"Disable CBSP link\n",
	CMD_ATTR_NODE_EXIT)
{
	struct cbc_peer *peer = (struct cbc_peer *) vty->index;
	peer->link_mode = get_string_value(cbc_peer_link_mode_names, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_peer_remote_port, cfg_peer_remote_port_cmd,
	"remote-port <0-65535>",
	"Configure remote (TCP) port of peer\n"
	"Remote (TCP) port number of peer\n")
{
	struct cbc_peer *peer = (struct cbc_peer *) vty->index;
	peer->remote_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_peer_no_remote_port, cfg_peer_no_remote_port_cmd,
	"no remote-port",
	NO_STR "Configure remote (TCP) port of peer\n"
	"Disable identification of peer by remote port (only IP is used)\n")
{
	struct cbc_peer *peer = (struct cbc_peer *) vty->index;
	peer->remote_port = -1;
	return CMD_SUCCESS;
}


DEFUN(cfg_peer_remote_ip, cfg_peer_remote_ip_cmd,
	"remote-ip " VTY_IPV46_CMD,
	"Configure remote IP of peer\n"
	"IPv4 address of peer\n" "IPv6 address of peer\n")
{
	struct cbc_peer *peer = (struct cbc_peer *) vty->index;
	unsigned int allowed_address;
	unsigned int i;
	const char *newaddr = argv[0];

	if (peer->proto == CBC_PEER_PROTO_SBcAP)
		allowed_address = ARRAY_SIZE(peer->remote_host);
	else
		allowed_address = 1;

	if (peer->num_remote_host >= allowed_address) {
		vty_out(vty, "%% Only up to %u addresses allowed%s",
			allowed_address, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Check for repeated entries: */
	for (i = 0; i < peer->num_remote_host; i++) {
		if (strcmp(peer->remote_host[i], newaddr) == 0) {
			vty_out(vty, "%% IP address %s already in list%s", newaddr, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}
	osmo_talloc_replace_string(peer, &peer->remote_host[peer->num_remote_host], newaddr);
	peer->num_remote_host++;

	return CMD_SUCCESS;
}

DEFUN(cfg_peer_no_remote_ip, cfg_peer_no_remote_ip_cmd,
	"no remote-ip " VTY_IPV46_CMD,
	NO_STR "Keep remote IP of peer\n"
	"IPv4 address of peer\n" "IPv6 address of peer\n")
{
	struct cbc_peer *peer = (struct cbc_peer *) vty->index;
	unsigned int i, j;
	const char *rmaddr = argv[0];

	for (i = 0; i < peer->num_remote_host; i++) {
		if (strcmp(peer->remote_host[i], rmaddr) == 0) {
			talloc_free(peer->remote_host[i]);
			peer->num_remote_host--;
			for (j = i; j < peer->num_remote_host; j++) {
				peer->remote_host[j] = peer->remote_host[j + 1];
			}
			peer->remote_host[j] = NULL;
			return CMD_SUCCESS;
		}
	}
	vty_out(vty, "%% IP address %s not in list%s", rmaddr, VTY_NEWLINE);
	return CMD_WARNING;
}

static void write_one_peer(struct vty *vty, struct cbc_peer *peer)
{
	unsigned int i;
	vty_out(vty, " peer %s %s%s", get_value_string(cbc_peer_proto_name_vty, peer->proto),
		peer->name, VTY_NEWLINE);
	vty_out(vty, "  mode %s%s", cbc_peer_link_mode_name(peer->link_mode), VTY_NEWLINE);
	if (peer->remote_port == -1)
		vty_out(vty, "  no remote-port%s", VTY_NEWLINE);
	else
		vty_out(vty, "  remote-port %d%s", peer->remote_port, VTY_NEWLINE);
	for (i = 0; i < peer->num_remote_host; i++)
		vty_out(vty, "  remote-ip %s%s", peer->remote_host[i], VTY_NEWLINE);
}

static int config_write_peer(struct vty *vty)
{
	struct cbc_peer *peer;
	llist_for_each_entry(peer, &g_cbc->peers, list) {
		/* only save those configured via the VTY, not the "unknown" peers */
		if (peer->unknown_dynamic_peer)
			continue;
		write_one_peer(vty, peer);
	}
	return CMD_SUCCESS;
}

void cbc_vty_init(void)
{
	install_element_ve(&show_peers_cmd);
	install_element_ve(&show_message_cbs_cmd);
	install_element_ve(&show_messages_cbs_cmd);
	install_element_ve(&show_messages_etws_cmd);

	install_element(CONFIG_NODE, &cfg_cbc_cmd);
	install_node(&cbc_node, config_write_cbc);
	install_element(CBC_NODE, &cfg_permit_unknown_peers_cmd);

	install_element(CBC_NODE, &cfg_cbsp_cmd);
	install_node(&cbsp_node, NULL);
	install_element(CBSP_NODE, &cfg_cbsp_local_ip_cmd);
	install_element(CBSP_NODE, &cfg_cbsp_local_port_cmd);

	install_element(CBC_NODE, &cfg_ecbe_cmd);
	install_node(&ecbe_node, NULL);
	install_element(ECBE_NODE, &cfg_ecbe_local_ip_cmd);
	install_element(ECBE_NODE, &cfg_ecbe_local_port_cmd);

	install_element(CBC_NODE, &cfg_sbcap_cmd);
	install_node(&sbcap_node, NULL);
	install_element(SBcAP_NODE, &cfg_sbcap_local_ip_cmd);
	install_element(SBcAP_NODE, &cfg_sbcap_no_local_ip_cmd);
	install_element(SBcAP_NODE, &cfg_sbcap_local_port_cmd);

	install_element(CBC_NODE, &cfg_cbc_peer_old_cmd);
	install_element(CBC_NODE, &cfg_cbc_peer_cmd);
	install_element(CBC_NODE, &cfg_cbc_no_peer_cmd);
	install_node(&peer_node, NULL);
	install_element(PEER_NODE, &cfg_peer_proto_cmd);
	install_element(PEER_NODE, &cfg_peer_mode_cmd);
	install_element(PEER_NODE, &cfg_peer_remote_port_cmd);
	install_element(PEER_NODE, &cfg_peer_no_remote_port_cmd);
	install_element(PEER_NODE, &cfg_peer_remote_ip_cmd);
	install_element(PEER_NODE, &cfg_peer_no_remote_ip_cmd);

}
