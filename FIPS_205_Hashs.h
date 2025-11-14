#ifndef FIPS_205_Hashs_h
#define FIPS_205_Hashs_h
#include <malloc.h>
#include <string.h>
#include "FIPS_205_Params.h"
#include "FIPS_205_Adr.h"
#include "AVXconst.h"
void AVX_PREDCALC_VALUE(void* state_, const uint8_t* in, uint32_t in_len);

#define	PRF	F
void F(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[]);
#define	AVX_PRF	AVX_F
void AVX_F(uint8_t* hash_value, const void* PK_seed_, uint8_t* Adr, const uint8_t Msg[]);
#define	AVX_PRF4	AVX_F4
//void AVX_F4(uint8_t hash_value[4][FIPS205_N], const void* PK_seed_, uint8_t Adr[4][22], const uint8_t Msg[4][FIPS205_N]);
#define	AVX_PRF8	AVX_F8
void AVX_F8(uint8_t hash_value[8][FIPS205_N], const void* PK_seed_, uint8_t Adr[22], const uint8_t Msg[FIPS205_N], int i);

void HASH(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][FIPS205_N]);
void AVX_HASH(uint8_t* hash_value, const void* PK_seed_, uint8_t* Adr, const uint8_t Msg[][FIPS205_N]);

//int test_AVX_F();
//int test_AVX_F4();



void PRFmsg_(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, const uint8_t* Msg, uint32_t Msg_len, uint8_t* buf);

void HMsg(
	uint8_t* dest,
	const uint8_t* R,
	const uint8_t* PK,
	const uint8_t* msg,
	uint32_t m_len,
	uint8_t* buf);

void AVX_HMsg(
	uint8_t* dest,
	const uint8_t* R,
	const uint8_t* PK,
	const uint8_t* msg,
	uint32_t m_len,
	uint8_t* buf);

/*
void AVXPRFmsg(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, 
const uint8_t* Msg, uint32_t Msg_len, uint8_t *buf)
*/
//SUCCESS AVXPRFmsg(
void AVX_PRFmsg(
	uint8_t* dest,
	const uint8_t* SK_prf,
	const uint8_t* opt_rand,
	const uint8_t* Msg,
	uint32_t Msg_len,
	uint8_t *buf);

void PRFmsg(
	uint8_t* dest, 
	const uint8_t* SK_prf, 
	const uint8_t* optrand, 
	const uint8_t* m, 
	uint32_t mlen);

void Tl(
	uint8_t* hash_value, 
	const uint8_t* PK_seed, 
	uint8_t* Adr, 
	const uint8_t Msg[][FIPS205_N], 
	uint32_t len
	);

//void AVX_Tl(
//	uint8_t* hash_value, 
//	const void* PK_seed, 
//	uint8_t* Adr, 
//	const uint8_t Msg[][FIPS205_N], 
//	uint32_t len 
//	);


void PRF_with_predcalc(uint8_t* dest, void* pred_pk, uint8_t* adr, uint8_t* SK_seed, uint32_t out_len);
int test_PRF();
void AVX_HMAC(uint8_t* dest, const uint8_t* sk, const uint8_t* src, uint32_t len);


#if 0
#ifdef _PREDCALC
#ifndef SHAKE
void predcalcs_pk(
	uint32_t* dest_PK_seed,
#if N == 16
	uint32_t* dest_PK_seed_n,
#else
	uint64_t* dest_PK_seed_n,
#endif
	uint8_t* PK_seed);
#endif


//void predcalcs_pk(void *destPK_seed, uint8_t* PK_seed);
void sha256_with_predcalc2_(uint8_t* out, uint32_t* predcalc, uint8_t* in, size_t inlen);
size_t sha256_with_predcalc_(uint8_t* out, uint32_t* predcalc, uint8_t* in, size_t inlen);
//#if N > 16
//void sha512_with_predcalc2_(uint8_t* out, uint64_t* predcalc, const uint8_t* in, size_t inlen);
//#endif
void PRF_with_predcalc(uint8_t* dest, void*pk, uint8_t* adr_short, uint8_t* SK_seed);
void HASH_with_predcalc(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg[2][N]);
void HASH_with_predcalcAdr(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t** Msg);
void HASH_with_predcalc2(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg1[N], uint8_t Msg2[N]);
//void Tl_with_predcalc(uint8_t* out, void* pk, uint8_t* adr, const uint8_t Msg[][N], size_t len);
void Tl_with_predcalc(
	uint8_t* out,
	void* pk,
#ifndef SHAKE
	void* pk_n,
#endif
	uint8_t* adr,
	const uint8_t Msg[][N],
	size_t len);

// void Tl_with_predcalc (uint8_t* out, void *pk, uint8_t *adr, const uint8_t Msg[][N], size_t len)
#endif




void PRF(uint8_t* prf_value, const uint8_t* PK_seed, const uint8_t* Adr, const uint8_t* SK_seed );
SUCCESS Tl(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][N], size_t len);
void HASH(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[2][N]);
void F(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t* Msg);

void chain(uint8_t* Y, const uint8_t* X, size_t i, size_t s, const uint8_t* PK_seed, PADR ADRS);
#define F_with_predcalc PRF_with_predcalc

void HASH_with_predcalc_256(uint8_t* hash_value, const void* pk, uint8_t* Adr, const uint8_t Msg[2][N]);
//int test_sha256_chain_with_predcalc();
void chain_with_predcalc(uint8_t* res, int i, int s, void* pk_, uint8_t* adr, uint8_t* sk);
int test_chain_with_predcalc();
SUCCESS test_hashs();


#endif

void AVX_Tl(uint8_t* out, void *predcalc_pk,  uint8_t adr[], __m256i* keys, uint32_t keys_count);
void AVX_Tl_(uint8_t* out, const void* predcalc_pk, uint8_t adr[], uint8_t *keys, uint32_t keys_count);
void H_with_predcalc(
	uint8_t* hash_value,
	const void* pk,
	uint8_t* Adr,
	//const uint8_t Msg[2][FIPS205_N]);
	const uint8_t Msg1[FIPS205_N],
	const uint8_t Msg2[FIPS205_N]);
#endif

