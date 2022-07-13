/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SBC-AP-IEs"
 * 	found in "../../src/sbcap/asn1/SBC_AP_IEs.asn"
 * 	`asn1c -S /home/pespin/dev/sysmocom/build/new/out/share/asn1c -fcompound-names -gen-APER -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-UPER -no-gen-example`
 */

#include <osmocom/sbcap/SBcAP_CancelledCellinTAI-5GS.h>

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_SBcAP_CancelledCellinTAI_5GS_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 16,  16,  1,  65535 }	/* (SIZE(1..65535)) */,
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static asn_TYPE_member_t asn_MBR_SBcAP_Member_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SBcAP_CancelledCellinTAI_5GS__Member, nR_CGI),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_NR_CGI,
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
		"nR-CGI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SBcAP_CancelledCellinTAI_5GS__Member, numberOfBroadcasts),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_NumberOfBroadcasts,
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
		"numberOfBroadcasts"
		},
	{ ATF_POINTER, 1, offsetof(struct SBcAP_CancelledCellinTAI_5GS__Member, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_ProtocolExtensionContainer_112P6,
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
static const int asn_MAP_SBcAP_Member_oms_2[] = { 2 };
static const ber_tlv_tag_t asn_DEF_SBcAP_Member_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SBcAP_Member_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* nR-CGI */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* numberOfBroadcasts */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_SBcAP_Member_specs_2 = {
	sizeof(struct SBcAP_CancelledCellinTAI_5GS__Member),
	offsetof(struct SBcAP_CancelledCellinTAI_5GS__Member, _asn_ctx),
	asn_MAP_SBcAP_Member_tag2el_2,
	3,	/* Count of tags in the map */
	asn_MAP_SBcAP_Member_oms_2,	/* Optional members */
	1, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_SBcAP_Member_2 = {
	"SEQUENCE",
	"SEQUENCE",
	&asn_OP_SEQUENCE,
	asn_DEF_SBcAP_Member_tags_2,
	sizeof(asn_DEF_SBcAP_Member_tags_2)
		/sizeof(asn_DEF_SBcAP_Member_tags_2[0]), /* 1 */
	asn_DEF_SBcAP_Member_tags_2,	/* Same as above */
	sizeof(asn_DEF_SBcAP_Member_tags_2)
		/sizeof(asn_DEF_SBcAP_Member_tags_2[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_SBcAP_Member_2,
	3,	/* Elements count */
	&asn_SPC_SBcAP_Member_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_SBcAP_CancelledCellinTAI_5GS_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_SBcAP_Member_2,
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
		""
		},
};
static const ber_tlv_tag_t asn_DEF_SBcAP_CancelledCellinTAI_5GS_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_SBcAP_CancelledCellinTAI_5GS_specs_1 = {
	sizeof(struct SBcAP_CancelledCellinTAI_5GS),
	offsetof(struct SBcAP_CancelledCellinTAI_5GS, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_SBcAP_CancelledCellinTAI_5GS = {
	"CancelledCellinTAI-5GS",
	"CancelledCellinTAI-5GS",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_SBcAP_CancelledCellinTAI_5GS_tags_1,
	sizeof(asn_DEF_SBcAP_CancelledCellinTAI_5GS_tags_1)
		/sizeof(asn_DEF_SBcAP_CancelledCellinTAI_5GS_tags_1[0]), /* 1 */
	asn_DEF_SBcAP_CancelledCellinTAI_5GS_tags_1,	/* Same as above */
	sizeof(asn_DEF_SBcAP_CancelledCellinTAI_5GS_tags_1)
		/sizeof(asn_DEF_SBcAP_CancelledCellinTAI_5GS_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_SBcAP_CancelledCellinTAI_5GS_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_OF_constraint
	},
	asn_MBR_SBcAP_CancelledCellinTAI_5GS_1,
	1,	/* Single element */
	&asn_SPC_SBcAP_CancelledCellinTAI_5GS_specs_1	/* Additional specs */
};

