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

#include <osmocom/core/utils.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>

#include "cbc_data.h"

enum cbc_vty_node {
	CBC_NODE = _LAST_OSMOVTY_NODE + 1,
	PEER_NODE,
};

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

static int config_write_cbc(struct vty *vty)
{
	vty_out(vty, "cbc%s", VTY_NEWLINE);
	vty_out(vty, " unknown-peers %s%s",
		g_cbc->config.permit_unknown_peers ? "accept" : "reject", VTY_NEWLINE);
	return CMD_SUCCESS;
}

/* PEER */

DEFUN(cfg_cbc_peer, cfg_cbc_peer_cmd,
	"peer NAME",
	"Remote Peer\n")
{
	struct cbc_peer *peer;

	peer = cbc_peer_by_name(argv[0]);
	if (!peer)
		peer = cbc_peer_create(argv[0], CBC_PEER_PROTO_CBSP);
	if (!peer)
		return CMD_WARNING;

	vty->node = PEER_NODE;
	vty->index = peer;
	return CMD_SUCCESS;
}

DEFUN(cfg_cbc_no_peer, cfg_cbc_no_peer_cmd,
	"no peer NAME",
	NO_STR "Remote Peer\n")
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


DEFUN(cfg_peer_proto, cfg_peer_proto_cmd,
	"protocol (cbsp)",
	"Configure Protocol of Peer\n"
	"Cell Broadcast Service Protocol (GSM)\n")
{
	struct cbc_peer *peer = (struct cbc_peer *) vty->index;
	peer->proto = CBC_PEER_PROTO_CBSP;
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
	"remote-ip A.B.C.D",
	"Configure remote IP of peer\n"
	"Remote IP address of peer\n")
{
	struct cbc_peer *peer = (struct cbc_peer *) vty->index;
	osmo_talloc_replace_string(peer, &peer->remote_host, argv[0]);
	return CMD_SUCCESS;
}



static void write_one_peer(struct vty *vty, struct cbc_peer *peer)
{
	vty_out(vty, " peer %s%s", peer->name, VTY_NEWLINE);
	vty_out(vty, "  protocol cbsp%s", VTY_NEWLINE);
	if (peer->remote_port == -1)
		vty_out(vty, "  no remote-port%s", VTY_NEWLINE);
	else
		vty_out(vty, "  remote-port %d%s", peer->remote_port, VTY_NEWLINE);
	vty_out(vty, "  remote-ip %s%s", peer->remote_host, VTY_NEWLINE);
}

static int config_write_peer(struct vty *vty)
{
	struct cbc_peer *peer;
	llist_for_each_entry(peer, &g_cbc->peers, list)
		write_one_peer(vty, peer);
	return CMD_SUCCESS;
}

void cbc_vty_init(void)
{
	install_lib_element(CONFIG_NODE, &cfg_cbc_cmd);
	install_node(&cbc_node, config_write_cbc);
	install_lib_element(CBC_NODE, &cfg_permit_unknown_peers_cmd);

	install_lib_element(CBC_NODE, &cfg_cbc_peer_cmd);
	install_lib_element(CBC_NODE, &cfg_cbc_no_peer_cmd);
	install_node(&peer_node, config_write_peer);
	install_lib_element(PEER_NODE, &cfg_peer_proto_cmd);
	install_lib_element(PEER_NODE, &cfg_peer_remote_port_cmd);
	install_lib_element(PEER_NODE, &cfg_peer_no_remote_port_cmd);
	install_lib_element(PEER_NODE, &cfg_peer_remote_ip_cmd);

}
