#ifndef FIPS_205_Common_fun_h
#define FIPS_205_Common_fun_h
#include "FIPS_205_Params.h"
size_t gen_len2(size_t n, size_t lgw);

uint32_t toInt32(const uint8_t* X, size_t n);
uint64_t toInt64(const uint8_t* X, size_t n);
void toByte64(uint8_t* S, uint64_t x, size_t n);
void base_2b(uint32_t* base_b, const uint8_t* X, size_t b, size_t out_len);
uint32_t base_2b_(uint32_t* base_b, const uint8_t* X, uint32_t out_len);
size_t gen_m(size_t h, size_t h_, size_t k, size_t a);
size_t gen_len2(size_t n, size_t lgw);
SUCCESS test_toInt_toByte();
void toByte32(uint8_t* S, uint32_t x_, size_t n);
#if 1
uint64_t DigestParse(uint32_t* idxleaf, const uint8_t* digest);
#else
uint64_t DigestParse(uint8_t* md, uint32_t* idxleaf, const uint8_t* digest);
#endif

#endif

