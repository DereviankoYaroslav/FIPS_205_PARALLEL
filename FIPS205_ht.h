#ifndef FIPS_205_ht_h
#define FIPS_205_ht_h
#include "FIPS_205_Params.h"
#include "FIPS_205_xmss.h"


uint8_t* FIPS205_AVX_ht_sign(uint8_t* pSig, const uint8_t* PK_fors, const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,			// 256 block
	const void* PK_seed_n,			// 256 or 512 single
#endif
	uint64_t idxtree,
	uint32_t idxleaf);



SUCCESS FIPS205_AVX_ht_verify(const uint8_t* MSG, const uint8_t* SIGHT,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint64_t idxtree, uint32_t idxleaf, const uint8_t* PK_root);
#endif


