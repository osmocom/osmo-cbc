AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = src

EXTRA_DIST = .version git-version-gen osmoappdesc.py doc/examples/osmo-cbc.cfg

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
