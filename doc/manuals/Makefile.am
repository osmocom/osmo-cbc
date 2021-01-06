EXTRA_DIST = osmocbc-usermanual.adoc \
    osmocbc-usermanual-docinfo.xml \
    osmocbc-vty-reference.xml \
    regen_doc.sh \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmocbc-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmocbc-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  BUILT_REFERENCE_XML = $(builddir)/vty/cbc_vty_reference.xml
  $(builddir)/vty/cbc_vty_reference.xml: $(top_builddir)/src/osmo-cbc
	mkdir -p $(builddir)/vty
	$(top_builddir)/src/osmo-cbc --vty-ref-xml > $@

  OSMO_REPOSITORY = osmo-cbc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
