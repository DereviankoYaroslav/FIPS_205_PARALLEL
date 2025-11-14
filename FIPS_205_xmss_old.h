#ifndef FIPS_205_xmss_old_h
#define FIPS_205_xmss_old_h
#include "FIPS_205_Params.h"
#include "FIPS_205_Adr_old.h"
#include "FIPS_205_Hashs_old.h"
#include "FIPS_205_wots_old.h"

//void xmss_node_OLD(
//	uint8_t* PK_root,
//	const uint8_t* SK_seed,
//	size_t i,
//	size_t z,
//	const uint8_t* PK_seed,
//	uint8_t* adr);

void xmss_node__OLD(
	uint8_t* PK_root,
	const uint8_t* SK_seed,
	size_t  i,
	size_t z,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);




//void xmss_node_not_recurse_OLD(
//	uint8_t* PK_root,
//	const uint8_t* SK_seed,
//#ifdef SHAKE
//	const uint8_t* PK_seed,
//#else
//	const void* PK_seed,
//	const void* PK_seed_n,
//#endif
//	uint8_t* adr
//	);
//
//void xmss_sign_OLD(uint8_t* SIGtmp, const uint8_t* Msg, const uint8_t* SK_seed,
//	size_t idx,
//	const uint8_t* PK_seed,
//	uint8_t* adr);


void xmss_sign__OLD(uint8_t* SIGtmp, const uint8_t* Msg, const uint8_t* SK_seed,
	size_t idx,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

//void xmss_pkFromSig_OLD(
//	uint8_t* root,
//	size_t idx,
//	const uint8_t* SIGtmp,
//	const uint8_t* Msg,
//	const uint8_t* PK_seed,
//	uint8_t* adr);

void xmss_pkFromSig__OLD(
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
#endif
