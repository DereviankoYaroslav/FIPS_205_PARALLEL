#ifndef AVX256_H
#define AVX256_H
#include <stdio.h>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "SHA256_device.h"
#include "FIPS_205_Adr.h"

void AVX_sha256_compress(
    uint32_t* state, 
    __m256i* block256/*const uint8_t* block*/);

void AVX_sha256_compress8(
    __m256i state[8], 
    const __m256i block[16]);

void AVX_sha256_one_block(
    uint8_t* out, 
    uint32_t* predcalc,
    uint8_t* in, 
    size_t inlen, 
    size_t out_len);

void AVX_sha256(
    uint8_t* hash, 
    const uint8_t* in, 
    uint32_t in_len, 
    uint32_t out_len);

void AVX_sha256_with_predcalc(
    uint8_t* out, 
    const uint32_t* pk, 
    const uint8_t* in, 
    uint32_t in_len, 
    uint32_t out_len);

void AVX_sha256_predcalc_pk(
    uint32_t* state, 
    const uint8_t* in);

void AVX_sha256_predcalc_pk_(
    __m256i state256[8], 
    const uint8_t* in);

void AVX_PREDCALC_sha256(
    uint8_t* hash, 
    const uint32_t* state, 
    const uint8_t* in, 
    uint32_t in_len, 
    uint32_t out_len);

void AVX_sha256_WITH_PREDCALC1(
    uint8_t* hash, 
    const uint32_t* state, 
    const uint8_t* in, 
    uint32_t in_len, 
    uint32_t out_len);

void AVX_sha256_WITH_PREDCALC4(
    uint8_t hash[4][FIPS205_N], 
    const uint32_t state[8], 
    const uint8_t in[4][FIPS205_N + ADR_SIZE]);

void AVX_sha256_WITH_PREDCALC8(
    uint8_t hash[8][FIPS205_N], 
    const uint32_t state[8], 
    const uint8_t in[8][FIPS205_N + ADR_SIZE]);

void AVX_HMAC256(
    uint8_t* dest, 
    const uint8_t* sk, 
    uint32_t sk_len, 
    const uint8_t* src, 
    uint32_t len);

void AVX_MGF1_sha256(
    uint8_t* out, 
    uint32_t outlen,
    const uint8_t* in, 
    uint32_t inlen);


#endif

