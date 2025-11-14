#ifndef SHA_2_H
#define SHA_2_H

#include <stddef.h>
#include <stdint.h>
#include "FIPS_205_Params.h"

//#define SHA2_NAMESPACE(s) pqcrystals_sha2_ref##s

//#define sha256 SHA2_NAMESPACE(_sha2)
void sha256(uint8_t* out, const uint8_t* in, size_t inlen);
void sha224(uint8_t* out, const uint8_t* in, size_t inlen);
void sha384(uint8_t* out, const uint8_t* in, size_t inlen);
//#define sha512 SHA2_NAMESPACE(_sha512)
//void sha512(uint8_t out[64], const uint8_t *in, size_t inlen);
//void sha512(uint8_t* out, const uint8_t* in, size_t inlen);
//void sha512_224(uint8_t* out, const uint8_t* in, size_t inlen);
//void sha512_256(uint8_t* out, const uint8_t* in, size_t inlen);
//
//void sha512(uint8_t* out, const uint8_t* in, uint32_t inlen);
//void HMAC512(uint8_t* dest, const uint8_t* sk, uint32_t sk_len, const uint8_t* src, uint32_t len, uint32_t dest_len);
//void MGF1_sha512(uint8_t* out, uint32_t outlen, const uint8_t* in, uint32_t inlen);
//void sha512_with_predcalc2_(uint8_t* out, uint64_t* state, const uint8_t* in, uint32_t inlen, uint32_t outlen);
void HMAC256(uint8_t* dest, const uint8_t* sk, const uint8_t* src, size_t len);

int test_sha2();


void mgf1_sha256(unsigned char* out, unsigned long outlen,
    const unsigned char* in, unsigned long inlen);

//void mgf1_sha_256(unsigned char* out, unsigned long outlen,
//    const unsigned char* in, unsigned long inlen);
//void mgf1_sha512(unsigned char* out, unsigned long outlen,
//    const unsigned char* in, unsigned long inlen);

void HMAC256(uint8_t* dest, const uint8_t* sk, const uint8_t* src, size_t len);
SUCCESS Test_HMAC_256();

#ifdef _PREDCALC
void sha256_with_predcalc2_(uint8_t* out, const uint32_t* predcalc, uint8_t* in, size_t inlen);
void sha256_with_predcalc_(uint8_t* out, uint32_t* predcalc, uint8_t* in, size_t inlen);

void sha256_chain_with_predcalc(uint8_t* res, int i, int s, uint32_t* predcalc_pk, uint8_t* adr, uint8_t* src2, int n);
#endif

#endif
