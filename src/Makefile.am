AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/src
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMONETIF_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS=$(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-cbc

osmo_cbc_SOURCES = cbc_main.c cbsp_server.c cbsp_server_fsm.c
osmo_cbc_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMONETIF_LIBS)
