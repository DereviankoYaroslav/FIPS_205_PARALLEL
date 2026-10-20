#ifndef FIPS_205_xmss_h
#define FIPS_205_xmss_h

#include "FIPS_205_Params.h"

#include "FIPS205_WOTS.h"


#include "FIPS_205_Adr.h"

void FIPS205_AVX_xmss_node(
	uint8_t* PK_root,
	const uint8_t* SK_seed,
	size_t  i,
	size_t z,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,			// 256 - block
	const void* PK_seed_n,			// 256 or 512 single
#endif
	uint8_t* adr);

void FIPS205_AVX_xmss_node__(
	uint8_t* root,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed_,
#else
	const void* PK_seed_,  // block 256
	const void* PK_seed_n_,// single 256 or 512
#endif
	uint8_t* adr);

void FIPS205_AVX_xmss_sign(
	uint8_t* SIGtmp,
	const uint8_t* Msg,
	const uint8_t* SK_seed,
	size_t idx,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

void FIPS205_AVX_xmss_sign_(
	uint8_t* SIGtmp,
	const uint8_t* Msg,
	const uint8_t* SK_seed,
	size_t idx,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

void FIPS205_AVX_xmss_pkFromSig(
	//uint8_t* root,
	uint8_t* node,
	size_t idx,
	const uint8_t* SIGtmp,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);


#if 0
void xmss_node(uint8_t* PK_root, const uint8_t* SK_seed, size_t /*target_node_index*/ i, size_t /*target_node_height */z,
	const uint8_t* PK_seed, uint8_t* adr);

void xmss_node_(uint8_t* PK_root, const uint8_t* SK_seed, size_t /*target_node_index*/ i, size_t /*target_node_height */z,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

void xmss_node_not_recurse__(
	uint8_t* PK_root,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr
);


void xmss_sign(uint8_t* SIGtmp, const uint8_t* Msg, const uint8_t* SK_seed,
	size_t idx, const uint8_t* PK_seed, uint8_t* adr);

void xmss_sign_(uint8_t* SIGtmp, const uint8_t* Msg, const uint8_t* SK_seed,
	size_t idx,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);


void xmss_pkFromSig(
	uint8_t* root,
	size_t idx,
	const uint8_t* SIGtmp,
	const uint8_t* Msg,
	const uint8_t* PK_seed,
	uint8_t* adr);

void xmss_pkFromSig_(
	uint8_t* root,
	size_t idx,
	const uint8_t* SIGtmp,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);
int test_xmss();
#endif
#endif
