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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include <osmocom/core/stats.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>

#include "internal.h"
#include "cbsp_server.h"
#include "cbc_data.h"

static void *tall_cbc_ctx;
struct cbc *g_cbc;

static const struct log_info_cat log_info_cat[] = {
	[DCBSP] = {
		.name = "DCBSP",
		.description = "Cell Broadcast Service Protocol (CBC-BSC)",
		.color = "\033[1;31m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
};

static const struct log_info log_info = {
	.cat = log_info_cat,
	.num_cat = ARRAY_SIZE(log_info_cat),
};

static const char cbc_copyright[] =
        "Copyright (C) 2019 by Harald Welte <laforge@gnumonks.org>\r\n"
        "License AGPLv3+: GNU Affero GPL Version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
        "This is free software: you are free ot change and redistribute it.\r\n"
        "There is NO WARRANTY, to the extent permitted by law.\r\n\r\n"
        "Free Software lives by contribution.  If you use this, please contribute!\r\n";

static struct vty_app_info vty_info = {
	.name = "OsmoCBC",
	.copyright = cbc_copyright,
	.version = PACKAGE_VERSION,
	.go_parent_cb = NULL,
	.is_config_node = NULL,
};

static struct {
	bool daemonize;
	const char *config_file;
} cmdline_config = {
	.daemonize = false,
	.config_file = "osmo-cbc.cfg",
};

static void print_help(void)
{
	/* FIXME */
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "version", 0, 0, 'V' },
			{ NULL, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hDc:V", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'D':
			cmdline_config.daemonize = true;
			break;
		case 'c':
			cmdline_config.config_file = optarg;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			fprintf(stderr, "Error in command line options. Exiting\n");
			exit(1);
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %d received\n", signal);

	switch (signal){
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_cbc_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

extern int cbc_client_rx_cb(struct osmo_cbsp_cbc_client *client, struct osmo_cbsp_decoded *dec);

int main(int argc, char **argv)
{
	void *tall_rest_ctx;
	int rc;

	tall_cbc_ctx = talloc_named_const(NULL, 1, "osmo-cbc");
	tall_rest_ctx = talloc_named_const(tall_cbc_ctx, 0, "REST");
	msgb_talloc_ctx_init(tall_cbc_ctx, 0);
	osmo_init_logging2(tall_cbc_ctx, &log_info);
	osmo_stats_init(tall_cbc_ctx);
	vty_init(&vty_info);

	g_cbc = talloc_zero(tall_cbc_ctx, struct cbc);
	INIT_LLIST_HEAD(&g_cbc->peers);
	INIT_LLIST_HEAD(&g_cbc->messages);

	cbc_vty_init();

	handle_options(argc, argv);

	logging_vty_add_cmds();
	osmo_fsm_vty_add_cmds();

	rc = vty_read_config_file(cmdline_config.config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed ot parse the config file '%s'\n",
			cmdline_config.config_file);
		exit(1);
	}

	rc = telnet_init_dynif(tall_cbc_ctx, NULL, vty_get_bind_addr(), OSMO_VTY_PORT_CBC);
	if (rc < 0) {
		perror("Error binding VTY port\n");
		exit(1);
	}

	cbsp_cbc_create(tall_cbc_ctx, NULL, -1, &cbc_client_rx_cb);

	rest_api_init(tall_rest_ctx, 12345);

	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	if (cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}
}
