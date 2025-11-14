#ifndef SHA256_device_h
#define SHA256_device_h
#include <inttypes.h>
#include <immintrin.h>
#include "SHA256_defines.h"
int check_properties(int fun, uint32_t index, uint32_t bit);
int check_sha256();
int check_sha512();
// out_len <= 32!
// void AVX_sha256_device_predcalc_pk(uint32_t* state, uint8_t* pk, int n)
//void AVX_sha256_device_predcalc_pk(uint32_t* state, uint8_t* pk, int n);
//void AVX_sha256_device_compress(uint32_t* state, const uint8_t* in);
//void AVX_sha256_device_WITH_PREDCALC(uint8_t* hash, uint32_t* predcalc_key, const uint8_t* in);
//void AVX_sha256_device_predcalc_pk(uint32_t *state, uint8_t* data);
void AVX_sha256_device_predcalc_pk_(__m256i state256[8], uint8_t* data);
void AVX_sha256_device_compress(uint32_t state[8], const uint8_t* data);
void AVX_sha256_device(uint8_t* out, const uint8_t* data, uint32_t length, uint32_t out_len);
void AVX_MGF1_sha256_device(unsigned char* out, unsigned long outlen,
    const unsigned char* in, unsigned long inlen);
void AVX_HMAC_device(uint8_t* dest, uint8_t* sk, uint32_t sk_len, uint8_t* src, uint32_t len);
__m128i _mm_sha256rnds2_epu32_emu(__m128i  a, __m128i  b, __m128i k);
__m128i _mm_sha256msg1_epu32_emu(__m128i a, __m128i b);
__m128i  _mm_sha256msg2_epu32_emu(__m128i a, __m128i b);
#endif
