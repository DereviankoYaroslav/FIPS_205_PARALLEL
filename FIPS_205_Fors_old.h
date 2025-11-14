#ifndef FIPS_205_Fors_OLD_h
#define FIPS_205_Fors_OLD_h
#include "FIPS_205_Params.h"
#include "FIPS_205_Hashs_old.h"
#include "Common.h"

void fors_skGen__OLD(uint8_t* pFORS, const uint8_t* SK_seed, const void* PK_seed,
	uint8_t* adr, uint32_t ind);

void fors_node__OLD(uint8_t* pFORS, const uint8_t* SK_seed, uint32_t i, uint32_t z,
	const void* PK_seed_,
#ifndef SHAKE
	const void* PK_seed_n,
#endif
	uint8_t* adr);

uint8_t* fors_sign__OLD(
	uint8_t* FORS,
	const uint8_t* md,
	const uint8_t* SK_seed,
	const void* PK_seed,
#ifndef SHAKE
	const void* PK_seed_n,
#endif
	uint8_t* adr);


uint8_t* fors_sign__OLD(
	uint8_t* FORS,
	const uint8_t* md,
	const uint8_t* SK_seed,
	const void* PK_seed,
#ifndef SHAKE
	const void* PK_seed_n,
#endif
	uint8_t* adr);

uint8_t* fors_sign___OLD(
	uint8_t* FORS,
	const uint8_t* md,
	const uint8_t* SK_seed,
	const void* PK_seed,
#ifndef SHAKE
	const void* PK_seed_n,
#endif
	uint8_t* adr);
void fors_pkFromSig__OLD(uint8_t* PK_fors, const uint8_t* SIGfors, const uint8_t* md, const

	const void* PK_seed_,
#ifndef SHAKE
	const void* PK_seed_n,
#endif
	uint8_t* adr);
void fors_pkFromSig___OLD(uint8_t* PK_fors, const uint8_t* SIGfors, const uint8_t* md, const

	void* PK_seed_,
#ifndef SHAKE
	void* PK_seed_n,
#endif
	uint8_t* adr);

int test_fors_sign();
#endif
