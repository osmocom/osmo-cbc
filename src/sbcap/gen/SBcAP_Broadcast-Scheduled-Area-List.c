/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SBC-AP-IEs"
 * 	found in "../../src/sbcap/asn1/SBC_AP_IEs.asn"
 * 	`asn1c -S /home/pespin/dev/sysmocom/build/new/out/share/asn1c -fcompound-names -gen-APER -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-UPER -no-gen-example`
 */

#include <osmocom/sbcap/SBcAP_Broadcast-Scheduled-Area-List.h>

asn_TYPE_member_t asn_MBR_SBcAP_Broadcast_Scheduled_Area_List_1[] = {
	{ ATF_POINTER, 4, offsetof(struct SBcAP_Broadcast_Scheduled_Area_List, cellId_Broadcast_List),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_CellId_Broadcast_List,
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
		"cellId-Broadcast-List"
		},
	{ ATF_POINTER, 3, offsetof(struct SBcAP_Broadcast_Scheduled_Area_List, tAI_Broadcast_List),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_TAI_Broadcast_List,
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
		"tAI-Broadcast-List"
		},
	{ ATF_POINTER, 2, offsetof(struct SBcAP_Broadcast_Scheduled_Area_List, emergencyAreaID_Broadcast_List),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_EmergencyAreaID_Broadcast_List,
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
		"emergencyAreaID-Broadcast-List"
		},
	{ ATF_POINTER, 1, offsetof(struct SBcAP_Broadcast_Scheduled_Area_List, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SBcAP_ProtocolExtensionContainer_112P0,
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
static const int asn_MAP_SBcAP_Broadcast_Scheduled_Area_List_oms_1[] = { 0, 1, 2, 3 };
static const ber_tlv_tag_t asn_DEF_SBcAP_Broadcast_Scheduled_Area_List_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SBcAP_Broadcast_Scheduled_Area_List_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cellId-Broadcast-List */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tAI-Broadcast-List */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* emergencyAreaID-Broadcast-List */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_SBcAP_Broadcast_Scheduled_Area_List_specs_1 = {
	sizeof(struct SBcAP_Broadcast_Scheduled_Area_List),
	offsetof(struct SBcAP_Broadcast_Scheduled_Area_List, _asn_ctx),
	asn_MAP_SBcAP_Broadcast_Scheduled_Area_List_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_SBcAP_Broadcast_Scheduled_Area_List_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SBcAP_Broadcast_Scheduled_Area_List = {
	"Broadcast-Scheduled-Area-List",
	"Broadcast-Scheduled-Area-List",
	&asn_OP_SEQUENCE,
	asn_DEF_SBcAP_Broadcast_Scheduled_Area_List_tags_1,
	sizeof(asn_DEF_SBcAP_Broadcast_Scheduled_Area_List_tags_1)
		/sizeof(asn_DEF_SBcAP_Broadcast_Scheduled_Area_List_tags_1[0]), /* 1 */
	asn_DEF_SBcAP_Broadcast_Scheduled_Area_List_tags_1,	/* Same as above */
	sizeof(asn_DEF_SBcAP_Broadcast_Scheduled_Area_List_tags_1)
		/sizeof(asn_DEF_SBcAP_Broadcast_Scheduled_Area_List_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_SBcAP_Broadcast_Scheduled_Area_List_1,
	4,	/* Elements count */
	&asn_SPC_SBcAP_Broadcast_Scheduled_Area_List_specs_1	/* Additional specs */
};

