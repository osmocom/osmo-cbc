/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SBC-AP-IEs"
 * 	found in "../../src/sbcap/asn1/SBC_AP_IEs.asn"
 * 	`asn1c -S /home/pespin/dev/sysmocom/build/new/out/share/asn1c -fcompound-names -gen-APER -no-gen-BER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-UPER -no-gen-example`
 */

#ifndef	_SBcAP_Send_Write_Replace_Warning_Indication_H_
#define	_SBcAP_Send_Write_Replace_Warning_Indication_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SBcAP_Send_Write_Replace_Warning_Indication {
	SBcAP_Send_Write_Replace_Warning_Indication_true	= 0
} e_SBcAP_Send_Write_Replace_Warning_Indication;

/* SBcAP_Send-Write-Replace-Warning-Indication */
typedef long	 SBcAP_Send_Write_Replace_Warning_Indication_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_SBcAP_Send_Write_Replace_Warning_Indication_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_SBcAP_Send_Write_Replace_Warning_Indication;
extern const asn_INTEGER_specifics_t asn_SPC_Send_Write_Replace_Warning_Indication_specs_1;
asn_struct_free_f Send_Write_Replace_Warning_Indication_free;
asn_struct_print_f Send_Write_Replace_Warning_Indication_print;
asn_constr_check_f Send_Write_Replace_Warning_Indication_constraint;
per_type_decoder_f Send_Write_Replace_Warning_Indication_decode_aper;
per_type_encoder_f Send_Write_Replace_Warning_Indication_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _SBcAP_Send_Write_Replace_Warning_Indication_H_ */
#include <asn_internal.h>
