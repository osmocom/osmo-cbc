/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SBC-AP-IEs"
 * 	found in "../../src/sbcap/asn1/SBC_AP_IEs.asn"
 * 	`asn1c -S /home/pespin/dev/sysmocom/build/new/out/share/asn1c -fcompound-names -gen-APER -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-UPER -no-gen-example`
 */

#include <osmocom/sbcap/SBcAP_ScheduledCellinTAI-Item.h>

asn_TYPE_member_t asn_MBR_SBcAP_ScheduledCellinTAI_Item_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SBcAP_ScheduledCellinTAI_Item, eCGI),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_EUTRAN_CGI,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"eCGI"
		},
	{ ATF_POINTER, 1, offsetof(struct SBcAP_ScheduledCellinTAI_Item, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_ProtocolExtensionContainer_112P21,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_SBcAP_ScheduledCellinTAI_Item_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_SBcAP_ScheduledCellinTAI_Item_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SBcAP_ScheduledCellinTAI_Item_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* eCGI */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_SBcAP_ScheduledCellinTAI_Item_specs_1 = {
	sizeof(struct SBcAP_ScheduledCellinTAI_Item),
	offsetof(struct SBcAP_ScheduledCellinTAI_Item, _asn_ctx),
	asn_MAP_SBcAP_ScheduledCellinTAI_Item_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_SBcAP_ScheduledCellinTAI_Item_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SBcAP_ScheduledCellinTAI_Item = {
	"ScheduledCellinTAI-Item",
	"ScheduledCellinTAI-Item",
	&asn_OP_SEQUENCE,
	asn_DEF_SBcAP_ScheduledCellinTAI_Item_tags_1,
	sizeof(asn_DEF_SBcAP_ScheduledCellinTAI_Item_tags_1)
		/sizeof(asn_DEF_SBcAP_ScheduledCellinTAI_Item_tags_1[0]), /* 1 */
	asn_DEF_SBcAP_ScheduledCellinTAI_Item_tags_1,	/* Same as above */
	sizeof(asn_DEF_SBcAP_ScheduledCellinTAI_Item_tags_1)
		/sizeof(asn_DEF_SBcAP_ScheduledCellinTAI_Item_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_SBcAP_ScheduledCellinTAI_Item_1,
	2,	/* Elements count */
	&asn_SPC_SBcAP_ScheduledCellinTAI_Item_specs_1	/* Additional specs */
};

