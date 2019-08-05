AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/src
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		   $(LIBOSMONETIF_CFLAGS) \
		   $(ULFIUS_CFLAGS) $(JANSSON_CFLAGS) $(ORCANIA_CFLAGS) \
		   $(COVERAGE_CFLAGS)
AM_LDFLAGS=$(COVERAGE_LDFLAGS)

EXTRA_DIST = cbc_data.h cbsp_server.h charset.h internal.h

bin_PROGRAMS = osmo-cbc

osmo_cbc_SOURCES = cbc_main.c cbc_data.c cbc_vty.c cbsp_server.c cbsp_server_fsm.c \
		   rest_api.c charset.c message_handling.c
osmo_cbc_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
		 $(LIBOSMONETIF_LIBS) \
		 $(ULFIUS_LIBS) $(JANSSON_LIBS) $(ORCANIA_LIBS)

