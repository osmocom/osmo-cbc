/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SBC-AP-IEs"
 * 	found in "../../src/sbcap/asn1/SBC_AP_IEs.asn"
 * 	`asn1c -S /home/pespin/dev/sysmocom/build/new/out/share/asn1c -fcompound-names -gen-APER -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-UPER -no-gen-example`
 */

#include <osmocom/sbcap/SBcAP_Warning-Message-Content.h>

int
SBcAP_Warning_Message_Content_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size >= 1UL && size <= 9600UL)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using OCTET_STRING,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_SBcAP_Warning_Message_Content_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 14,  14,  1,  9600 }	/* (SIZE(1..9600)) */,
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const ber_tlv_tag_t asn_DEF_SBcAP_Warning_Message_Content_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SBcAP_Warning_Message_Content = {
	"Warning-Message-Content",
	"Warning-Message-Content",
	&asn_OP_OCTET_STRING,
	asn_DEF_SBcAP_Warning_Message_Content_tags_1,
	sizeof(asn_DEF_SBcAP_Warning_Message_Content_tags_1)
		/sizeof(asn_DEF_SBcAP_Warning_Message_Content_tags_1[0]), /* 1 */
	asn_DEF_SBcAP_Warning_Message_Content_tags_1,	/* Same as above */
	sizeof(asn_DEF_SBcAP_Warning_Message_Content_tags_1)
		/sizeof(asn_DEF_SBcAP_Warning_Message_Content_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_SBcAP_Warning_Message_Content_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SBcAP_Warning_Message_Content_constraint
	},
	0, 0,	/* No members */
	&asn_SPC_OCTET_STRING_specs	/* Additional specs */
};
