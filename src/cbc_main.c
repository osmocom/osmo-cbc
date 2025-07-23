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
#include <osmocom/core/fsm.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>

#include <osmocom/sbcap/sbcap_common.h>

#include <osmocom/cbc/debug.h>
#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/cbc_vty.h>
#include <osmocom/cbc/cbc_peer.h>

static void *tall_cbc_ctx;
struct cbc *g_cbc;

static const struct log_info_cat log_info_cat[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.description = "Main logging category",
		.color = "\033[1;30m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
	[DSMSCB] = {
		.name = "DSMSCB",
		.description = "SMS Cell Broadcast handling",
		.color = "\033[1;35m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
	[DCBSP] = {
		.name = "DCBSP",
		.description = "Cell Broadcast Service Protocol (CBC-BSC)",
		.color = "\033[1;31m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
	[DSBcAP] = {
		.name = "DSBcAP",
		.description = "SBc Application Part (CBC-MME)",
		.color = "\033[1;32m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
	[DASN1C] = {
		.name = "DASN1C",
		.description = "SBc-AP ASN1C enc/dec",
		.color = "\033[1;34m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
	[DREST] = {
		.name = "DREST",
		.description = "REST interface",
		.color = "\033[1;33m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
};

static const struct log_info log_info = {
	.cat = log_info_cat,
	.num_cat = ARRAY_SIZE(log_info_cat),
};

static int cbc_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case CBSP_NODE:
		g_cbc->config.cbsp.configured = true;
		break;
	case SBcAP_NODE:
		/* If no local addr set, add a default one: */
		cbc_add_sbcap_default_local_host_if_needed(g_cbc);
		g_cbc->config.sbcap.configured = true;
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case PEER_NODE:
		cbc_peer_apply_cfg_chg((struct cbc_peer *)vty->index);
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	}

	return vty->node;
}

static const char cbc_copyright[] =
        "Copyright (C) 2019-2021 by Harald Welte <laforge@gnumonks.org>\r\n"
        "License AGPLv3+: GNU Affero GPL Version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
        "This is free software: you are free ot change and redistribute it.\r\n"
        "There is NO WARRANTY, to the extent permitted by law.\r\n\r\n"
        "Free Software lives by contribution.  If you use this, please contribute!\r\n";

static struct vty_app_info vty_info = {
	.name = "OsmoCBC",
	.copyright = cbc_copyright,
	.go_parent_cb	= cbc_vty_go_parent,
	.version = PACKAGE_VERSION,
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
	printf("Supported options:\n");
	printf("  -h --help                  This text.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -V --version               Print the version of OsmoMSC.\n");

	printf("\nVTY reference generation:\n");
	printf("     --vty-ref-mode MODE     VTY reference generation mode (e.g. 'expert').\n");
	printf("     --vty-ref-xml           Generate the VTY reference XML output and exit.\n");
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static int long_option = 0;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "version", 0, 0, 'V' },
			{ "vty-ref-mode", 1, &long_option, 1},
			{ "vty-ref-xml", 0, &long_option, 2},
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
		case 0:
			handle_long_options(argv[0], long_option);
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

int main(int argc, char **argv)
{
	int rc;

	tall_cbc_ctx = talloc_named_const(NULL, 1, "osmo-cbc");
	msgb_talloc_ctx_init(tall_cbc_ctx, 0);
	osmo_init_logging2(tall_cbc_ctx, &log_info);
	log_enable_multithread();
	sbcap_set_log_area(DSBcAP, DASN1C);
	osmo_stats_init(tall_cbc_ctx);
	osmo_fsm_log_timeouts(true);

	vty_info.tall_ctx = tall_cbc_ctx;
	vty_init(&vty_info);

	g_cbc = cbc_alloc(tall_cbc_ctx);

	cbc_vty_init();

	handle_options(argc, argv);

	logging_vty_add_cmds();
	osmo_fsm_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	rc = vty_read_config_file(cmdline_config.config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed ot parse the config file '%s'\n",
			cmdline_config.config_file);
		exit(1);
	}

	rc = telnet_init_default(tall_cbc_ctx, NULL, OSMO_VTY_PORT_CBC);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}

	rc = cbc_start(g_cbc);
	if (rc < 0)
		exit(1);

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
