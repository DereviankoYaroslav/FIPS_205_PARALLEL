#ifndef _AVX512_h
#include <stdio.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>   // covers AVX, SSE, FMA, etc.
#endif
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "FIPS_205_Adr.h"
#include "FIPS_205_Params.h"

void AVX_sha512_predcalc_pk_(__m256i state256[8], const uint8_t* in);
void AVX_sha512_predcalc_pk(uint64_t* state64, const uint8_t* pk);
void AVX_sha512_compress(uint64_t* state, __m256i* w);
void AVX_sha512_one_block(uint8_t* out, uint64_t* predcalc, uint8_t* in, size_t inlen, size_t out_len);
void AVX_sha512_compress4(__m256i* state256, __m256i* block256);
void AVX_sha512(uint8_t* hash, const uint8_t* in, uint32_t in_len, uint32_t out_len);
// sha512 + PREDCALC pk 
void AVX_PREDCALC_sha512(uint8_t* out, const uint64_t* pk, const uint8_t* in, uint32_t in_len, uint32_t out_len);
// inlen < 56
// pk_seed ||
void AVX_sha512_PREDCALC_VALUE(uint64_t* state, const uint8_t* in, uint32_t in_len);
void AVX_sha512_WITH_PREDCALC(uint8_t* hash, const uint64_t* state, const uint8_t* in, uint32_t in_len, uint32_t out_len);
void AVX_PREDCALC_W_sha512_(uint8_t* out, const uint64_t* pk, const uint8_t* in, uint32_t in_len, uint32_t out_len);
void AVX_sha512_WITH_PREDCALC4(uint8_t hash[4][FIPS205_N], const uint64_t state[8], const uint8_t in[4][2 * FIPS205_N + ADR_SIZE]);
void AVX_sha512_WITH_PREDCALC(uint8_t* hash, const uint64_t* state, const uint8_t* in, uint32_t in_len, uint32_t out_len);
void AVX_HMAC512(uint8_t* dest, const uint8_t* sk, uint32_t sk_len, const uint8_t* src, uint32_t src_len, uint32_t dest_len);
void AVX_MGF1_sha512(
    uint8_t* out,
    uint32_t outlen,
    const uint8_t* in,
    uint32_t inlen);

#endif
