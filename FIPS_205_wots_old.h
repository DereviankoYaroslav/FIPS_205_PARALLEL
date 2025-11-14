#ifndef FIPS_205_wots_OLD_h
#define FIPS_205_wots_OLD_h
//#include "FIPS_205_Params.h"
#include "FIPS_205_Hashs.h"
#include "FIPS_205_Adr_old.h"
void wots_sign_OLD(
	uint8_t* WOTS_SIG,
	const uint8_t* Msg,
	const uint8_t* SK_seed,
	const uint8_t* PK_seed,
	PADR_OLD adr);

void wots_sign__OLD(
	uint8_t* WOTS_SIG,
	const uint8_t* Msg,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);


void wots_pkFromSig(
	uint8_t* pksig,
	const uint8_t* sig,
	const uint8_t* Msg,
	const uint8_t* PK_seed,
	PADR_OLD adr);

void wots_pkFromSig_(
	uint8_t* pksig,
	const uint8_t* sig,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

void wots_pkFromSig__(
#if 0
	uint8_t* pksig,
#else
	uint8_t tmp[][FIPS205_N],
#endif
	const uint8_t* sig,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif

	uint8_t* adr);

//void wots_pkGen(
//	uint8_t* pk,
//
//	const uint8_t* SK_seed,
//	const uint8_t* PK_seed,
//	PADR_OLD adr);

void wots_pkGen_(
	//uint8_t* pk,
	uint8_t pk[][FIPS205_N],
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

/*
void wots_pkGen__(
	uint8_t pk[][FIPS205_N],
	//uint8_*pk,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr)
*/

void wots_pkGen__(
	uint8_t pk[][FIPS205_N],
	//uint8_*pk, 
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

void wots_pkGenFull__(
	uint8_t *pk,
	//uint8_*pk, 
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);

void wots_pkFromSig_(

	uint8_t* pksig,
	const uint8_t* sig,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif

	uint8_t* adr);

//void wots_pkFromSig_Full(
//	uint8_t* pk,
//	const uint8_t* SK_seed,
//#ifdef SHAKE
//	const uint8_t* PK_seed,
//#else
//	const void* PK_seed,
//	const void* PK_seed_n,
//#endif
//	uint8_t* adr);

void wots_pkFromSig_Full(

	uint8_t* pksig,

	const uint8_t* sig,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif

	uint8_t* adr);

int test_wots();
#endif