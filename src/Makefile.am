SUBDIRS = sbcap

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_srcdir)/src/sbcap/skel
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		   $(LIBOSMONETIF_CFLAGS) \
		   $(ULFIUS_CFLAGS) $(JANSSON_CFLAGS) $(ORCANIA_CFLAGS) \
		   $(COVERAGE_CFLAGS) $(ASN_MODULE_CFLAGS)
AM_LDFLAGS=$(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-cbc

osmo_cbc_SOURCES = \
	cbc_data.c \
	cbc_main.c \
	cbc_message.c \
	cbc_peer.c \
	cbc_vty.c \
	cbsp_link.c \
	cbsp_link_fsm.c \
	cbsp_msg.c \
	rest_api.c \
	charset.c \
	rest_it_op.c \
	sbcap_msg.c \
	sbcap_link.c \
	sbcap_link_fsm.c \
	smscb_peer_fsm.c \
	smscb_message_fsm.c \
	$(NULL)

osmo_cbc_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
		 $(LIBOSMONETIF_LIBS) \
		 $(ULFIUS_LIBS) $(JANSSON_LIBS) $(ORCANIA_LIBS) $(LIBSCTP_LIBS) \
		 sbcap/libosmo-sbcap.la

regen:
	$(MAKE) -C sbcap regen
