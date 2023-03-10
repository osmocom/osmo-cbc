AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/sbcap/skel \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(ULFIUS_CFLAGS) \
	$(JANSSON_CFLAGS) \
	$(ORCANIA_CFLAGS) \
	$(ASN_MODULE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	sbcap_test.ok \
	$(NULL)

check_PROGRAMS = \
	sbcap_test \
	$(NULL)

sbcap_test_SOURCES = \
	sbcap_test.c \
	$(NULL)

sbcap_test_LDADD = \
	$(top_builddir)/src/sbcap/libosmo-sbcap.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(ULFIUS_LIBS) \
	$(JANSSON_LIBS) \
	$(ORCANIA_LIBS) \
	$(LIBSCTP_LIBS) \
	$(NULL)
