#ifndef FIPS205_internal_h
#define FIPS205_internal_h

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include "FIPS_205_Params.h"
#include "FIPS_205_Fors.h"
#include "FIPS205_ht.h"
#include "FIPS205_WOTS.h"
#include "FIPS_205_xmss.h"
#include "AVX512.h"
#ifndef SHAKE
extern uint32_t is_predcalc_pk_256;
extern __m256i AVX_predcalc_pk_256;
extern __m256i AVX_predcalc_pk_256_[];	// block
#if FIPS205_N != 16
extern uint32_t is_predcalc_pk_512;
extern __m256i AVX_predcalc_pk_512[];
extern __m256i AVX_predcalc_pk_512_[];
#endif
#endif


void FIPS205_keygen_internal(uint8_t* PK_root, const uint8_t* SK_seed, const uint8_t* SK_prf, const uint8_t* PK_seed);
void FIPS205_sign_internal(uint8_t* sign, const uint8_t* M, uint32_t M_len, const uint8_t* SK, uint8_t* addrng);
void FIPS205_sign_internal_new__(uint8_t* sign, const uint8_t* M, uint32_t M_len, const uint8_t* SK, uint8_t* addrng);
SUCCESS FIPS205_verify_internal(const uint8_t* M, uint32_t M_len, const uint8_t* SIG, uint32_t SIG_len, const uint8_t* PK);
SUCCESS FIPS205_verify_internal_new__(const uint8_t* M, uint32_t M_len, const uint8_t* SIG, uint32_t SIG_len, const uint8_t* PK);

#endif
