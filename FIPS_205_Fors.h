#ifndef FIPS_205_Fors_h
#define FIPS_205_Fors_h

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include "FIPS_205_Params.h"
#include "FIPS_205_Adr.h"
#include "FIPS205_WOTS.h"
#include "AVXconst.h"
#include "AVX256.h"
#include "Common.h"
void FIPS205_AVX_fors_init_in_block0(__m256i* in256, const uint8_t* adr);
void FIPS205_AVX_fors_init(__m256i *in64, const uint8_t* SK_seed, uint8_t* adr);
void create_blocks_for_in128(__m256i* blocks, __m256i* in128);
void AVX_fors_init_in_block0(__m256i* in256, const uint8_t* adr);

void AVX_fors_replace_blocks_keys4__(__m256i blockdest_[], __m256i blockkey256_1[], __m256i blockkey256_2[]);
void convert_32_64(__m256i dest[2][4], const __m256i src[8]);
void FIPS205_AVX_fors_sk(uint8_t sk[][FIPS205_N], const uint8_t* SK_seed, const void* PK_seed, const uint8_t* adr);
void FIPS205_AVX_fors_node(uint8_t node[FIPS205_N], const void* PK_seed, const void* PK_seed_n, __m256i in64[2], uint32_t i, uint32_t z);
// sk for fors tree
void FIPS205_AVX_fors_sks(uint8_t *sk,
	__m256i* in_block,
	const void* PK_seed,
	uint32_t* ind);
uint8_t* FIPS205_AVX_fors_sign__(uint8_t* SigFors, uint8_t* md,
	__m256i* in_block,
	const void* PK_seed_,		// One, 256 or 512
	const void* PK_seed,		// Block 256
	const void* PK_seed_n);		// 256 or 512 single

void FIPS205_AVX_fors_pkFromSig(
	uint8_t* pkFromSig,
	const uint8_t* SigFors,
	const uint8_t* md,
	const void* PK_seed_,		// One, 256 or 512
	const void* PK_seed,		// Block 256
	const void* PK_seed_n,		// Block 256 512
	uint8_t* adr);

void FIPS205_AVX_fors_pkFromSig_new__(
	uint8_t* pkFromSig,
	const uint8_t* SigFors,
	const uint8_t* md,
	const void* PK_seed_,		// one 256 0r 512
	const void* PK_seed,		// one 256
	//const void* PK_seed_n,		// block 512
	uint8_t* adr);

// sign + pk
uint8_t* FIPS205_AVX_fors_sign_and_PK(
	uint8_t* sign,
	uint8_t* pk,
	const uint8_t* md,
	const uint8_t* SK_seed,
	const void* PK_256,
	const void* PK_256_512,
	uint8_t* adr);


// next
uint8_t* FIPS205_AVX_fors_sign(
	uint8_t* SigFors,
	const uint8_t* md,
	//__m256i* in_block,
	const uint8_t* SK_seed,
	//const void* PK_seed_, 
	const void* PK_seed,  // block 256
	const void* PK_seed_n, // block 256/512
	uint8_t* adr);

uint8_t* FIPS205_AVX_fors_sign_new(
	uint8_t* sign, 
	uint8_t* md, /*auth[FIPS205_K][FIPS205_A][FIPS205_N], */
	const uint8_t* SK_seed, 
	const void* PK_256, 
	const void* PK_256_512, 
	uint8_t* adr);

uint8_t* FIPS205_AVX_fors_sign_new__(
	uint8_t* sign, 
	uint8_t* md, 
	const uint8_t* SK_seed, 
	const void* PK_256, 
	const void* PK_256_512, 
	uint8_t* adr);
#endif
