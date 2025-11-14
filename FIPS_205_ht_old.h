#ifndef FIPS_205_ht_OLD_h
#define FIPS_205_ht_OLD_h
#include "FIPS_205_Params.h"
//#include "FIPS_205_Hashs.h"
#include "FIPS_205_xmss_old.h"
//#include "FIPS_205_Fors.h"

uint8_t* ht_sign__OLD(uint8_t* pSig, const uint8_t* PK_fors, const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint64_t idxtree,
	uint32_t idxleaf);



SUCCESS ht_verify__OLD(const uint8_t* MSG, const uint8_t* SIGHT, 
#ifdef SHAKE
	const uint8_t* PK_seed, 
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint64_t idxtree, uint32_t idxleaf, const uint8_t* PK_root);
#endif

