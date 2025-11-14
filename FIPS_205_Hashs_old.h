#ifndef FIPS_205_Hashs_OLD_h
#define FIPS_205_Hashs_OLD_h
#include <malloc.h>
#include <string.h>
#include "FIPS_205_Params.h"
#include "FIPS_205_Adr_old.h"
#include "fips202.h"
#include"sha2.h"

#ifdef _PREDCALC
#ifndef SHAKE
void predcalcs_pk_OLD(
	uint32_t* dest_PK_seed,
#if FIPS205_N == 16
	uint32_t* dest_PK_seed_n,
#else
	uint64_t* dest_PK_seed_n,
#endif
	uint8_t* PK_seed);
#endif

SUCCESS HMsg_OLD(uint8_t* dest, const uint8_t* R, const uint8_t* PK_seed, const uint8_t* PK_root, const uint8_t* msg, size_t m_len);
void sha256_with_predcalc2_OLD(uint8_t* out, uint32_t* predcalc, uint8_t* in, size_t inlen);
size_t sha256_with_predcalc_OLD(uint8_t* out, uint32_t* predcalc, uint8_t* in, size_t inlen);
void PRF_with_predcalc_OLD(uint8_t* dest, void*pk, uint8_t* adr_short, uint8_t* SK_seed);
void HASH_with_predcalc_OLD(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg[2][FIPS205_N]);
void HASH_with_predcalcAdr_OLD(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t** Msg);
void HASH_with_predcalc2_OLD(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg1[FIPS205_N], uint8_t Msg2[FIPS205_N]);
void Tl_with_predcalc_OLD(
	uint8_t* out,
	void* pk,
#ifndef SHAKE
	void* pk_n,
#endif
	uint8_t* adr,
	const uint8_t Msg[][FIPS205_N],
	size_t len);

#endif
void HMsg__OLD(uint8_t* dest, const uint8_t* R,
	const uint8_t* PK,
	const uint8_t* msg, size_t m_len, uint8_t *buf);

void PRFmsg__OLD(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, const uint8_t* Msg, size_t Msg_len, uint8_t *buf);

void PRF_OLD(uint8_t* prf_value, const uint8_t* PK_seed, const uint8_t* Adr, const uint8_t* SK_seed );
SUCCESS Tl_OLD(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][FIPS205_N], size_t len);
void HASH_OLD(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[2][FIPS205_N]);
void F_OLD(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t* Msg);

void chain_OLD(uint8_t* Y, const uint8_t* X, size_t i, size_t s, const uint8_t* PK_seed, PADR_OLD ADRS);
#define F_with_predcalc_OLD PRF_with_predcalc_OLD
void HASH_with_predcalc_256_OLD(uint8_t* hash_value, const void* pk, uint8_t* Adr, const uint8_t Msg[2][FIPS205_N]);
void chain_with_predcalc_OLD(uint8_t* res, int i, int s, void* pk_, uint8_t* adr, uint8_t* sk);
int test_chain_with_predcalc_OLD();
SUCCESS test_hashs_OLD();

#endif
