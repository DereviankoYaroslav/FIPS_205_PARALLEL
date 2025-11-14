#ifndef _SHA512_H
#define _SHA512_H
#include <inttypes.h>

void sha512(uint8_t* out, const uint8_t* in, size_t inlen);
void HMAC512(uint8_t* dest, const uint8_t* sk, const uint8_t* src, uint32_t len);
void MGF1_sha512(uint8_t* out, uint32_t outlen, const uint8_t* in, uint32_t inlen);


void sha512_predcalc_pk(uint64_t* state64, const uint8_t* in_);

// Для даних завдовжки один блок
void sha512_with_predcalc2_(uint8_t* out, uint64_t* state, const uint8_t* in, uint32_t inlen);
// Для даних довільної довжини
size_t sha512_with_predcalc_(uint8_t* out, uint64_t* predcalc_pk, uint8_t* in, size_t inlen);

//int test_sha512_with_predcalc();
//int test_sha512();
//int test_AVX_SHA512();
//void HMAC512(uint8_t* out, const uint8_t* sk, uint32_t sk_len, const uint8_t* in, uint32_t inlen, uint32_t out_len);
//int test_HMAC512();

#endif
