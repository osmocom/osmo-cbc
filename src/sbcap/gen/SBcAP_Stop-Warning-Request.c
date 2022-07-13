/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SBC-AP-PDU-Contents"
 * 	found in "../../src/sbcap/asn1/SBC_AP_PDU_Contents.asn"
 * 	`asn1c -S /home/pespin/dev/sysmocom/build/new/out/share/asn1c -fcompound-names -gen-APER -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-UPER -no-gen-example`
 */

#include <osmocom/sbcap/SBcAP_Stop-Warning-Request.h>

static asn_TYPE_member_t asn_MBR_SBcAP_Stop_Warning_Request_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SBcAP_Stop_Warning_Request, protocolIEs),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_ProtocolIE_Container_86P2,
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
		"protocolIEs"
		},
	{ ATF_POINTER, 1, offsetof(struct SBcAP_Stop_Warning_Request, protocolExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_ProtocolExtensionContainer_112P31,
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
		"protocolExtensions"
		},
};
static const int asn_MAP_SBcAP_Stop_Warning_Request_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_SBcAP_Stop_Warning_Request_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SBcAP_Stop_Warning_Request_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* protocolIEs */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* protocolExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_SBcAP_Stop_Warning_Request_specs_1 = {
	sizeof(struct SBcAP_Stop_Warning_Request),
	offsetof(struct SBcAP_Stop_Warning_Request, _asn_ctx),
	asn_MAP_SBcAP_Stop_Warning_Request_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_SBcAP_Stop_Warning_Request_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SBcAP_Stop_Warning_Request = {
	"Stop-Warning-Request",
	"Stop-Warning-Request",
	&asn_OP_SEQUENCE,
	asn_DEF_SBcAP_Stop_Warning_Request_tags_1,
	sizeof(asn_DEF_SBcAP_Stop_Warning_Request_tags_1)
		/sizeof(asn_DEF_SBcAP_Stop_Warning_Request_tags_1[0]), /* 1 */
	asn_DEF_SBcAP_Stop_Warning_Request_tags_1,	/* Same as above */
	sizeof(asn_DEF_SBcAP_Stop_Warning_Request_tags_1)
		/sizeof(asn_DEF_SBcAP_Stop_Warning_Request_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_SBcAP_Stop_Warning_Request_1,
	2,	/* Elements count */
	&asn_SPC_SBcAP_Stop_Warning_Request_specs_1	/* Additional specs */
};

