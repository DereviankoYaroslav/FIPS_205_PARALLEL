#ifndef FIPS_205_Internal_OLD_h
#define FIPS_205_Internal_OLD_h

#include "FIPS_205_Params.h"
//#include "rng.h"
#include "FIPS_205_Adr_old.h"
#include "FIPS_205_Hashs_old.h"

void slh_keygen_internal__OLD(uint8_t* PK_root, const uint8_t* SK_seed, const uint8_t* SK_prf, const uint8_t* PK_seed_);

SUCCESS slh_sign_internal__OLD(uint8_t* SIG, const uint8_t* M_, size_t m_len,
	const uint8_t* SK, const uint8_t* ADRand);

SUCCESS slh_verify_internal__OLD(const uint8_t* M_, size_t M_len, const uint8_t* SIG, size_t SIG_len, const uint8_t* PK);

int test_internal();

#endif
