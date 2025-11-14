
#ifndef _FIPS205_WOTS_H
#define _FIPS205_WOTS_H

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include "FIPS_205_Params.h"

#include "FIPS_205_Adr.h"


#include "FIPS_205_Hashs.h"

#include "AVXconst.h"
#include "AVX256.h"
#include "OLD/sha256.h"

void replace_blocks_key8__(__m256i blockdest_[16], __m256i blockkey256[8]);

void FIPS205_wots_gen_sk_old(uint8_t sk[][FIPS205_N], const uint8_t* SK_seed, const uint8_t* PK_seed, const uint8_t* Adr);
void FIPS205_wots_gen_common_part(__m256i dest[8][2], const uint8_t* SK_seed, const uint8_t* Adr);
void FIPS205_wots_gen_common_part1(__m256i dest[2], const uint8_t* SK_seed, const uint8_t* Adr);
void FIPS205_wots_gen_sk8(__m256i sk256[]/*[8]*/, const __m256i* in256, /*const uint8_t* SK_seed, */const uint32_t* state /*const uint8_t* Adr*/);
void FIPS205_wots_gen_pk8(__m256i* pk, const uint8_t* SK_seed, const uint32_t* state, uint8_t* Adr);
void FIPS205_wots_gen_pk8_(__m256i* keys, const uint8_t* SK_seed, const uint32_t* state, uint8_t* Adr);
void FIPS205_wots_gen_pk8__(__m256i* keys, const uint8_t* SK_seed, const __m256i* predcalc_block, uint8_t* Adr);
void FIPS205_wots_genpk(uint8_t* pk, const uint8_t* SK_seed, const void* PK_seed, uint8_t* Adr);
void FIPS205_wots_gen_pk(uint8_t pk[FIPS205_LEN][FIPS205_N], const uint8_t sk[FIPS205_LEN][FIPS205_N], const uint8_t* PK_seed, uint8_t* Adr);
void AVX_FIPS205_wots_chain8(uint8_t out[][FIPS205_N], const void* pk, __m256i sk[8], uint8_t Adr[ADR_SIZE], int b, int e, int ind);
void simple_replace_key(__m256i dest[2], uint8_t adr[22], __m256i key256);
void simple_replace_key8(__m256i dest[8][2], uint8_t adr[8][22], __m256i key256[8]);
void FIPS205_wots_gen_common_pk(uint8_t* pk, const __m256i* keys, const void* predcalc_key, uint8_t* adr);
void FIPS205_wots_gen_pk_old(uint8_t pk[FIPS205_LEN][FIPS205_N], const uint8_t sk[FIPS205_LEN][FIPS205_N], const uint8_t* PK_seed, uint8_t* Adr);
void FIPS205_wots_gen_common_pk_old(uint8_t common_pk[FIPS205_N], const uint8_t pk[FIPS205_LEN][FIPS205_N], const uint8_t* PK_seed, uint8_t* Adr);
void FIPS205_wots_gen_pk_new(
	__m256i* pk,
	const uint8_t* SK_seed,
	const __m256i* state256,
#if FIPS205_N > 16
	const __m256i* state512,
#endif
	uint8_t* adr);

void FIPS205_wots_gen_pk_new_(
	__m256i* pk,
	const uint8_t* SK_seed,
	//const __m256i* keysBlocks,
	const __m256i* state256,
#if FIPS205_N > 16
	const __m256i* state512,
#endif
	uint8_t* adr);

void FIPS205_wots_gen_pk_new__(
	__m256i* pk,
	const uint8_t* SK_seed,
	//const __m256i* keysBlocks,
	const __m256i* state256_block,
	uint8_t* adr);

void FIPS205_AVX_wots_gen_pks(
	uint8_t* pk,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const __m256i* state256,
#endif
	uint8_t* adr);

void FIPS205_wots_gen_pkFromSig_new_(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr);



void FIPS205_AVX_wots_gen_pkFromSig(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr);


void FIPS205_wots_gen_sign_old(
	uint8_t sign[][FIPS205_N], 
	const uint8_t* M, 
	const uint8_t* SK_seed, 
	const uint8_t* PK_seed, 
	uint8_t* Adr);
void init_in_block(__m256i* in256, const uint8_t* adr, const uint8_t* key);
void create_blocks_for_in64(__m256i* blocks, __m256i* in64);
void convert_to_m256_block_keys(__m256i* keys, __m256i* block_keys);
void replace_key(__m256i* dest_, __m256i key_);
void FIPS205_wots_chain_new(uint8_t* out, const __m256i predcalc_pk, __m256i in[2], __m256i key, int32_t i, int32_t s);
void FIPS205_wots_chain_old(uint8_t* out, const uint8_t* pk, const uint8_t* in, uint8_t* Adr, int i, int s);
void FIPS205_wots_gen_sign_old(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, const uint8_t* PK_seed, uint8_t* Adr);
void FIPS205_wots_gen_sign_new(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, __m256i state256, const __m256i blocksstate256[8], uint8_t* adr);
void FIPS205_wots_gen_sign_new_(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, const __m256i* state256, const __m256i blocksstate256[8], uint8_t* adr);
void FIPS205_AVX_wots_sign(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, /*const __m256i* state256, */const __m256i* blockstate256, uint8_t* adr);
void FIPS205_wots_gen_sign_new___(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, /*const __m256i* state256, */const __m256i* blockstate256, uint8_t* adr);

void FIPS205_wots_gen_pkFromSig_old(uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const uint8_t* PK_seed,
	uint8_t* adr);

void FIPS205_wots_gen_pkFromSig_new(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr);
void FIPS205_wots_gen_pkFromSig_new__(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr);
void FIPS205_wots_gen_pkFromSig_new___(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr);

void FIPS205_wots_gen_pkFromSig_new____(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr);
void FIPS205_wots_gen_pkFromSig_new_____(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr);

// FULL wots_gen_pk
void FIPS205_AVX_wots_gen_pk(
	uint8_t* pk,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed;
#else
	const __m256i* state256,
	/*
	#if FIPS205_N > 16
		const __m256i* state512,
		*/
	const void *predcalc,
#endif

	uint8_t* adr);

void
FIPS205_AVX_wots_pkFromSig
(
	uint8_t pk[FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
#ifdef SHAKE
	const uint8_t* pk,
#else
	const __m256i* blockstate256,
	const void* pk_n,
#endif
	uint8_t* adr);
#endif

