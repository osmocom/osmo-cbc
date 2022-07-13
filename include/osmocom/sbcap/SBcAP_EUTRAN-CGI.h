/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SBC-AP-IEs"
 * 	found in "../../src/sbcap/asn1/SBC_AP_IEs.asn"
 * 	`asn1c -S /home/pespin/dev/sysmocom/build/new/out/share/asn1c -fcompound-names -gen-APER -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-UPER -no-gen-example`
 */

#ifndef	_SBcAP_EUTRAN_CGI_H_
#define	_SBcAP_EUTRAN_CGI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/sbcap/SBcAP_PLMNidentity.h>
#include <osmocom/sbcap/SBcAP_CellIdentity.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SBcAP_ProtocolExtensionContainer;

/* SBcAP_EUTRAN-CGI */
typedef struct SBcAP_EUTRAN_CGI {
	SBcAP_PLMNidentity_t	 pLMNidentity;
	SBcAP_CellIdentity_t	 cell_ID;
	struct SBcAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SBcAP_EUTRAN_CGI_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SBcAP_EUTRAN_CGI;
extern asn_SEQUENCE_specifics_t asn_SPC_SBcAP_EUTRAN_CGI_specs_1;
extern asn_TYPE_member_t asn_MBR_SBcAP_EUTRAN_CGI_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */

#endif	/* _SBcAP_EUTRAN_CGI_H_ */
#include <asn_internal.h>
