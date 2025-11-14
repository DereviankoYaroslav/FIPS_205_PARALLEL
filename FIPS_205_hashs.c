#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>


#include "FIPS_205_Hashs.h"
#include "AVX256.h"
#include "OLD/sha256.h"
#include "OLD/hash.h"
#if FIPS205_N > 16
#include "SHA512.h"
#include "AVX512.h"
#endif

#if defined(_MSC_VER)
#  define ALIGN64 __declspec(align(64))
#else
#  define ALIGN64 __attribute__((aligned(64)))
#endif

#if defined(_MSC_VER)
#  define ALIGN32 __declspec(align(32))
#else
#  define ALIGN32 __attribute__((aligned(32)))
#endif


#ifndef _DEBUG
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
uint64_t tacts;
uint64_t min_tacts;
#endif
void sha256(uint8_t* out, const uint8_t* in, size_t inlen);


void AVX_PREDCALC_VALUE(void* state_, const uint8_t* in, uint32_t in_len)
{
#if FIPS205_N == 16
	void* state = (uint32_t*)state_;
	AVX_sha256_predcalc_pk(state, in/*, FIPS205_N*/);
#else
	void* state = (uint64_t*)state_;
	AVX_sha512_predcalc_pk(state, in);
#endif

}



/*
Функцію застосовують для обчислення гешу  в разі, коли повідомлення не довільної завдовжки
як для функції Tl, а завдовжки n.
*/

void F(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[])
{
	/*
	Вхід.
	PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
	ADR – дані про дерева, структура завдовжки 32 (22) байта
	M – повідомлення довжини  n (вхідне дане або попереднє значення гешу)
	Вихід.
	HashValue – значення гешу, рядок байтів завдовжки n байтів.

	*/

	uint32_t len;

#ifdef SHAKE
	uint8_t buf[N + 32 + N];
	len = N + 32 + N;
	memcpy(buf, PK_seed, N);
	memcpy(buf + N, Adr, 32);
	memcpy(buf + N + 32, Msg, N);
	shake256(hash_value, N, buf, len);
#else
	
	uint8_t temp[32];
	/*ADR_C Adr_c;
	toShort(&Adr_c, (PADR)Adr);*/

	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀1)) 
	uint8_t buf[64 + 22 + FIPS205_N];
	len = sizeof (buf);
	memcpy(buf, PK_seed, FIPS205_N);
	memset(buf + FIPS205_N, 0, 64 - FIPS205_N);
	memcpy(buf + 64, Adr, 22);
	memcpy(buf + 64 + 22, Msg, FIPS205_N);
	sha256(temp, buf, len);
	memcpy(hash_value, temp, FIPS205_N);
#endif

}



void AVX_F(uint8_t* hash_value, const void* PK_seed_, uint8_t* Adr, const uint8_t Msg[])
{
#ifdef SHAKE
	uint8_t* PK_seed = (uint8_t*)PK_seed_;
	uint8_t buf[N + 32 + N];
	len = N + 32 + N;
	memcpy(buf, PK_seed, N);
	memcpy(buf + N, Adr, 32);
	memcpy(buf + N + 32, Msg, N);
	shake256(hash_value, N, buf, len);
#else
	//uint8_t temp[32];
	const uint32_t* PK_seed = (const uint32_t*)PK_seed_;
	uint8_t in[22 + FIPS205_N];
	memcpy(in, Adr, 22);
	memcpy(in + 22, Msg, FIPS205_N);
	AVX_sha256_WITH_PREDCALC1(hash_value, PK_seed, in, 22 + FIPS205_N, FIPS205_N);
	
	/*ADR_C Adr_c;
	toShort(&Adr_c, (PADR)Adr);*/

	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀1)) 
	
#endif

}

void AVX_F8(
	uint8_t hash_value[8][FIPS205_N], const void* PK_seed_, uint8_t Adr[22], const uint8_t Msg[FIPS205_N], int i)
{
#ifdef SHAKE
	uint8_t* PK_seed = (uint8_t*)PK_seed_;
	uint8_t buf[N + 32 + N];
	len = N + 32 + N;
	memcpy(buf, PK_seed, N);
	memcpy(buf + N, Adr, 32);
	memcpy(buf + N + 32, Msg, N);
	shake256(hash_value, N, buf, len);
#else
	//uint8_t temp[32];
	const uint32_t* PK_seed = (const uint32_t*)PK_seed_;
	uint8_t in[8][22 + FIPS205_N];
	memcpy(in[0], Adr, ADR_SIZE);
	memcpy(in[0] + ADR_SIZE, Msg, FIPS205_N); setChainAddress(in[0], i++);
	memcpy(in[1], in[0], 22 + FIPS205_N); setChainAddress(in[1], i++);
	memcpy(in[2], in[0], 22 + FIPS205_N); setChainAddress(in[2], i++);
	memcpy(in[3], in[0], 22 + FIPS205_N); setChainAddress(in[3], i++);
	
	memcpy(in[4], in[0], 22 + FIPS205_N); setChainAddress(in[4], i++);
	memcpy(in[5], in[0], 22 + FIPS205_N); setChainAddress(in[5], i++);
	memcpy(in[6], in[0], 22 + FIPS205_N); setChainAddress(in[6], i++);
	memcpy(in[7], in[0], 22 + FIPS205_N); setChainAddress(in[7], i++);

	//memcpy(in + 22, Msg, FIPS205_N);
	
	AVX_sha256_WITH_PREDCALC8(hash_value, PK_seed, in);

	/*ADR_C Adr_c;
	toShort(&Adr_c, (PADR)Adr);*/

	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀1)) 

#endif

}

// PRF and F - equals!!!!

void HASH(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][FIPS205_N])
{
	/*
Вхід.
PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
ADR – дані про дерева, структура завдовжки 32 байта
Msg – повідомлення довжини 2 * n
Вихід.
HashValue – значення гешу, рядок байтів завдовжки n байтів.

	*/


	uint32_t cur_len;

#ifdef SHAKE
	uint8_t buf[FIPS205_N + 32 + 2 * FIPS205_N];
	cur_len = FIPS205_N + 32 + 2 * FIPS205_N;
	memcpy(buf, PK_seed, FIPS205_N);
	memcpy(buf + FIPS205_N, Adr, 32);
	memcpy(buf + FIPS205_N + 32, Msg[0], FIPS205_N);
	memcpy(buf + FIPS205_N + 32 + FIPS205_N, Msg[1], FIPS205_N);

	shake256(hash_value, FIPS205_N, buf, cur_len);


#else
	uint8_t temp[64];
	
#if FIPS205_N == 16
	
	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	cur_len = 64 + 22 + 2 * FIPS205_N;
	uint8_t buf[64 + 22 + 2 * FIPS205_N];


	memcpy(buf, PK_seed, FIPS205_N);
	memset(buf + FIPS205_N, 0, 64 - FIPS205_N);
	memcpy(buf + 64, Adr, 22);
	memcpy(buf + 64 + 22, Msg[0], FIPS205_N);
	memcpy(buf + 64 + 22 + FIPS205_N, Msg[1], FIPS205_N);

	sha256(temp, buf, cur_len);
	memcpy(hash_value, temp, FIPS205_N);

#else
	// Trunc𝑛 (SHA-512(PK.seed ∥ toByte (0,128−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ)) 
	cur_len = 128 + 22 + 2 * FIPS205_N;
	uint8_t buf[128 + 22 + 2 * FIPS205_N];

	memcpy(buf, PK_seed, FIPS205_N);
	memset(buf + FIPS205_N, 0, 128 - FIPS205_N);
	memcpy(buf + 128, (uint8_t*)Adr, 22);
	memcpy(buf + 128 + 22, Msg[0], FIPS205_N);
	memcpy(buf + 128 + 22 + FIPS205_N, Msg[1], FIPS205_N);

	sha512(temp, buf, cur_len);
	memcpy (hash_value, temp, FIPS205_N);
	//memcpy(hash_value, temp, FIPS205_N);


#endif
#endif


}

void AVX_HASH(uint8_t* hash_value, const void* PK_seed_, uint8_t* Adr, const uint8_t Msg[][FIPS205_N])
{
	/*
Вхід.
PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
ADR – дані про дерева, структура завдовжки 32 байта
Msg – повідомлення довжини 2 * n
Вихід.
HashValue – значення гешу, рядок байтів завдовжки n байтів.

	*/


	uint32_t buf_len;

#ifdef SHAKE
	uint8_t* PK_seed = (uint8_t*)PK_seed_;
	uint8_t buf[FIPS205_N + 32 + 2 * FIPS205_N];
	cur_len = FIPS205_N + 32 + 2 * FIPS205_N;
	memcpy(buf, PK_seed, FIPS205_N);
	memcpy(buf + FIPS205_N, Adr, 32);
	memcpy(buf + FIPS205_N + 32, Msg[0], FIPS205_N);
	memcpy(buf + FIPS205_N + 32 + FIPS205_N, Msg[1], FIPS205_N);

	shake256(hash_value, FIPS205_N, buf, buf_len);

#else
	
	uint8_t buf[ADR_SIZE + 2 * FIPS205_N];
	buf_len = ADR_SIZE + 2 * FIPS205_N;
	memcpy(buf, Adr, ADR_SIZE);
	memcpy(buf + ADR_SIZE, Msg[0], FIPS205_N);
	memcpy(buf + ADR_SIZE + FIPS205_N, Msg[1], FIPS205_N);

#if FIPS205_N == 16
	const uint32_t* PK_seed = (const uint32_t*)PK_seed_;
	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	AVX_sha256_WITH_PREDCALC1(hash_value, PK_seed, buf, buf_len, FIPS205_N);

#else
	const uint64_t* PK_seed = (const uint64_t*)PK_seed_;
	AVX_sha512_WITH_PREDCALC(hash_value, PK_seed, buf, buf_len, FIPS205_N);
	
#endif
#endif


}

void AVX_HMAC(uint8_t* dest, const uint8_t* sk, const uint8_t* src, uint32_t len)
{
#if FIPS205_N == 16
	AVX_HMAC256(dest, sk, FIPS205_N, src, len/*, FIPS205_N*/);
#else
	AVX_HMAC512(dest, sk, FIPS205_N, src, len, FIPS205_N);
#endif
}

void PRFmsg(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* optrand, const uint8_t* m, uint32_t mlen)
{
	//SUCCESS success = ERROR;
	
	//uint32_t len;
	//uint8_t* buf = 0;
	
#ifdef SHAKE
		
		uint32_t len = FIPS205_N + FIPS205_N + mlen;
		char* buf = malloc(len);
		memcpy(buf, SK_prf, N);
		memcpy(buf + N, opt_rand, N);
		memcpy(buf + 2 * N, Msg, Msg_len);
		shake256(dest, N, buf, len);
		free(buf);
#elif 1
	gen_message_random(dest, SK_prf, optrand, m, mlen);
#else
/*
H𝑚𝑠𝑔(𝑅,PK.seed,PK.root,𝑀) =
MGF1-SHA-512(𝑅 ∥ PK.seed ∥ SHA-512(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀),𝑚)
*/

#endif
}

void AVX_PRFmsg(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, const uint8_t* Msg, uint32_t Msg_len, uint8_t *buf)
{
	SUCCESS success = ERROR;
	//#ifdef _DEBUG
	//	++PRFmsgCnt;
	//#endif
	uint32_t len;
	//uint8_t* buf = 0;
	{
#ifdef SHAKE
		//buf = malloc(N + N + Msg_len);
		//if (buf)
		{
			success = OK;
			len = N + N + Msg_len;
			memcpy(buf, SK_prf, N);
			memcpy(buf + N, opt_rand, N);
			memcpy(buf + 2 * N, Msg, Msg_len);
			shake256(dest, N, buf, len);
		}

#else
		//uint8_t temp[64];
		/*
		PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑,𝑀) →
Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀))
		*/
		len = FIPS205_N + Msg_len;
		//buf = malloc(len);
		//if (buf)
		{
			//success = OK;
			memcpy(buf, opt_rand, FIPS205_N);
			memcpy(buf + FIPS205_N, Msg, Msg_len);
			AVX_HMAC(dest, SK_prf, buf, len);
		}

#endif
	}
	/*if (success == OK)
		free(buf);

	return success;*/
}

void HMsg(
	uint8_t* dest,
	const uint8_t* R,
	const uint8_t* PK,
	const uint8_t* msg,
	uint32_t m_len,
	uint8_t* buf
	)
{
	uint32_t len = 3 * FIPS205_N + m_len;
	memcpy(buf, R, FIPS205_N);
	memcpy(buf + FIPS205_N, PK, 2 * FIPS205_N);
	memcpy(buf + 3 * FIPS205_N, msg, m_len);

#ifdef SHAKE

	shake256(dest, FIPS205_M, buf, len);

#else
#if FIPS205_N == 16
	sha256(buf + 2 * FIPS205_N, buf, len);
	/*void mgf1(unsigned char* out, unsigned long outlen,
		const unsigned char* in, unsigned long inlen);*/
	/*
	void mgf1_sha256(unsigned char* out, unsigned long outlen,
    const unsigned char* in, unsigned long inlen)
	*/
	mgf1(dest, FIPS205_M, buf, 2 * FIPS205_N + 32);
#else
	sha512(buf + 2 * FIPS205_N, buf, len);
	MGF1_sha512(dest, FIPS205_M,
		buf, 2 * FIPS205_N + 64);
#endif
#endif

}

void AVX_HMsg(
	uint8_t* dest,
	const uint8_t* R,
	const uint8_t* PK,
	const uint8_t* msg,
	uint32_t m_len,
	uint8_t* buf
)
{
	uint32_t len = 3 * FIPS205_N + m_len;
	memcpy(buf, R, FIPS205_N);
	memcpy(buf + FIPS205_N, PK, 2 * FIPS205_N);
	memcpy(buf + 3 * FIPS205_N, msg, m_len);

#ifdef SHAKE

	shake256(dest, FIPS205_M, buf, len);

#else
#if FIPS205_N == 16
	AVX_sha256(buf + 2 * FIPS205_N, buf, len, 32);
	AVX_MGF1_sha256(dest, FIPS205_M, buf, 2 * FIPS205_N + 32);
#else
	AVX_sha512(buf + 2 * FIPS205_N, buf, len, 64);
	AVX_MGF1_sha512(dest, FIPS205_M, buf, 2 * FIPS205_N + 64);
#endif
#endif

}

#if FIPS205_LEN > FIPS205_K 
#define ARRAY_SIZE	FIPS205_N * FIPS205_LEN
#else
#define ARRAY_SIZE	FIPS205_N * FIPS205_K
#endif

void Tl(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][FIPS205_N], uint32_t len)
{
	/*
Вхід.
PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
ADR – дані про дерева, структура завдовжки 32 байта
M – len повідомлень, кожне завдовжки n.
Вихід.
hash_value – значення гешу, рядок байтів завдовжки n байтів.


	*/
	
	//SUCCESS success = ERROR;
	//uint8_t* buf = 0;
	size_t cur_len ;


#ifdef SHAKE
	uint8_t buf [FIPS205_N + ADR_SIZE + ARRAY_SIZE];
#else
		#if FIPS205_N == 16
			uint8_t buf[64 + ADR_SIZE + ARRAY_SIZE];
		#else
			uint8_t buf[128 + ADR_SIZE + ARRAY_SIZE];
		#endif
#endif

#ifdef SHAKE
	cur_len = FIPS205_N + ADR_SIZE + len * FIPS205_N;

	//buf = malloc(cur_len);
	//if (buf)
	//{
		//success = OK;
		memcpy(buf, PK_seed, FIPS205_N);
		memcpy(buf + FIPS205_N, Adr, ADR_SIZE);
		uint8_t* p = buf + FIPS205_N + ADR_SIZE;
		size_t j;
		for (j = 0; j < len; ++j)
		{
			memcpy(p, Msg[j], ADR_SIZE);
			p += ADR_SIZE;
		}

		shake256(hash_value, ADR_SIZE, buf, cur_len);
		//free(buf);
	}
#else
	
#if FIPS205_N == 16
	const uint32_t size = 64;
#else
	const uint32_t size = 128;
#endif
	cur_len = size + ADR_SIZE + len * FIPS205_N;
	
	//buf = malloc(cur_len);
	
	//if (buf)
	//{
		//success = OK;
		memcpy(buf, PK_seed, FIPS205_N);
		memset(buf + FIPS205_N, 0, size - FIPS205_N);
		memcpy(buf + size, Adr, ADR_SIZE);
		uint8_t* p = buf + size + ADR_SIZE;
		size_t j;
		for (j = 0; j < len; ++j)
		{
			memcpy(p, Msg[j], FIPS205_N);
			p += FIPS205_N;
		}
		uint8_t temp[64];
#if FIPS205_N == 16 
		
		sha256(temp, buf, cur_len);
		//memcpy(hash_value, temp, FIPS205_N);
#else
		sha512(temp, buf, cur_len);
		

#endif
		
		//free(buf);
	//}
		memcpy(hash_value, temp, FIPS205_N);
#endif

	//return success;

}

#if 0
// PRFmsg
// Генерація псевдовипадкових даних.
/*
Вхід:
SK_prf – компонент секретного ключа, рядок байтів завдовжки n байтів;
𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 – випадкове дане, рядок байтів завдовжки n байтів;
M – повідомлення для генерації ЦП, рядок байтів заданої довжини.
Вихід.
Prf – рядок байтів завдовжки n байтів.
*/
// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀) = SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀,8𝑛)
// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑,𝑀) =
//     Trunc𝑛(HMAC - SHA - 256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀))



void PRFmsg_(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, const uint8_t* Msg, uint32_t Msg_len, uint8_t* buf)
{
	uint32_t len;


#ifdef SHAKE

	len = FIPS205_N + FIPS205_N + Msg_len;
	memcpy(buf, SK_prf, FIPS205_N);
	memcpy(buf + N, opt_rand, FIPS205_N);
	memcpy(buf + 2 * FIPS205_N, Msg, Msg_len);
	shake256(dest, FIPS205_N, buf, len);
#else
	uint8_t temp[64];
	/*
	PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑,𝑀) →
Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀))
		*/
	len = FIPS205_N + Msg_len;
	memcpy(buf, opt_rand, FIPS205_N);
	memcpy(buf + FIPS205_N, Msg, Msg_len);
	AVX_HMAC(temp, SK_prf, buf, len);
	memcpy(dest, temp, FIPS205_N);


#endif


}


void HMsg_(
	uint8_t* dest,
	const uint8_t* R,
	const uint8_t* PK,
	const uint8_t* msg,
	uint32_t m_len,
	uint8_t* buf)
{
	uint32_t len = 3 * FIPS205_N + m_len;
	memcpy(buf, R, FIPS205_N);
	memcpy(buf + FIPS205_N, PK, 2 * FIPS205_N);
	memcpy(buf + 3 * FIPS205_N, msg, m_len);

#ifdef SHAKE
	
	shake256(dest, FIPS205_M, buf, len);

#else
#if FIPS205_N == 16
	AVX_SHA256(buf + 2 * FIPS205_N, buf, len, 32);
	
	AVX_MGF1_SHA256(dest, FIPS205_M, buf, 2 * FIPS205_N + 64);
#else
	AVX_SHA512(buf + 2 * FIPS205_N, buf, len, 64);
	AVX_MGF1_SHA512(dest, FIPS205_M, buf, 2 * FIPS205_N + 128, 53);
#endif
#endif

}


void Parallel_PRF_with_predcalc(uint8_t* dest[], void* pred_pk, uint8_t* adr[], uint8_t* SK_seed)
{
	
}



int test_PRF()
{
	uint8_t PK_seed[FIPS205_N], SK_seed[FIPS205_N], dest1 [FIPS205_N], dest2[FIPS205_N];
	uint8_t adr[ADR_SIZE];
	srand(0);
	for (uint32_t i = 0; i < FIPS205_N; ++i)
	{
		PK_seed[i] = rand() % 256;
		SK_seed[i] = rand() % 256;
	}
	
	for (uint32_t i = 0; i < ADR_SIZE; ++i)
	{
		adr[i] = rand() % 256;
	}

	PRF(dest1, PK_seed, adr, SK_seed);
	uint32_t state[8];
#ifdef SHAKE
	PRF_with_predcalc(dest2, PK_seed, adr, SK_seed);
#else
	AVX_SHA256_PREDCALC_VALUE(state, PK_seed, FIPS205_N);
	PRF_with_predcalc(dest2, state, adr, SK_seed, FIPS205_N);
#endif
	

	int res = memcmp(dest1, dest2, FIPS205_N);
	return res;

}

#if 0


#ifdef _DEBUG
int PRFmsgCnt = 0, PRFCnt = 0, TlCnt = 0, HASHCnt = 0, FCnt = 0, HMsgCnt = 0;
#endif
#ifndef _DEBUG
uint64_t HMsgTime1 = 0xFFFFFFFFFFFFFFFF, PRFTime1= 0xFFFFFFFFFFFFFFFF, 
PRFmsgTime1 = 0xFFFFFFFFFFFFFFFF, FTime1 = 0xFFFFFFFFFFFFFFFF, HTime1 = 0xFFFFFFFFFFFFFFFF, 
TlTime1= 0xFFFFFFFFFFFFFFFF, TlTime1_K = 0xFFFFFFFFFFFFFFFF;
uint64_t HMsgTime2 = 0xFFFFFFFFFFFFFFFF, PRFTime2 = 0xFFFFFFFFFFFFFFFF,
PRFmsgTime2 = 0xFFFFFFFFFFFFFFFF, FTime2 = 0xFFFFFFFFFFFFFFFF, HTime2 = 0xFFFFFFFFFFFFFFFF, 
TlTime2 = 0xFFFFFFFFFFFFFFFF, TlTime2_K = 0xFFFFFFFFFFFFFFFF;
#endif


// Функцію застосовують для генерації гешу при генерації ЦП
// Вхід
//𝑅 – Заданий рядок байтів завдовжки n байтів;
//PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
//PK.root – компонент відкритого ключа, рядок байтів завдовжки n байтів;
//M – повідомлення для генерації ЦП, рядок байтів заданої довжини.
//Вихід.
//Hash_value – рядок байтів завдовжки m байтів, де m – залежит від алгоритму для гешування

SUCCESS HMsg(uint8_t* dest, const uint8_t* R, const uint8_t* PK_seed, const uint8_t* PK_root, const uint8_t* msg, size_t m_len)
{
	SUCCESS success = ERROR;
	uint8_t* buf = 0;
	size_t len;
#ifdef _DEBUG
	++HMsgCnt;
#endif
#ifdef SHAKE
	len = 3 * N + m_len;
	buf = malloc(len);
	if (buf)
	{
		success = OK;
		memcpy(buf, R, N);
		memcpy(buf + N, PK_seed, N);
		memcpy(buf + 2 * N, PK_root, N);
		memcpy(buf + 3 * N, msg, m_len);
		shake256(dest, M, buf, len);
	}

#else
#if N == 16
	// MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀),𝑚)
	len =  3 * N + m_len;
	/*if (len < 128)
		len = 128;*/
	buf = malloc((len >= 128? len : 128));
	if (buf)
	{
		success = OK;
		memcpy(buf, R, N);
		memcpy(buf + N, PK_seed, N);
		memcpy(buf + 2 * N, PK_root, N);
		memcpy(buf + 3 * N, msg, m_len);
		sha256(buf + 2 * N, buf, len);
		mgf1_sha_256(dest, M, buf, 2 * N + 32);

	}
#else
	// MGF1-SHA-512 (𝑅 ∥ PK.seed ∥ SHA-512 ( 𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀),𝑚) 
	len = len = 3 * N + m_len;
	buf = malloc(len + 64);
	if (buf)
	{
		success = OK;
		memcpy(buf, R, N);
		memcpy(buf + N, PK_seed, N);
		memcpy(buf + 2 * N, PK_root, N);
		memcpy(buf + 3 * N, msg, m_len);
		sha512(buf + 2 * N, buf, len);
		mgf1_sha_512(dest, M, buf, 2 * N + 64);
	}
#endif
#endif
	if (success == OK)
		free(buf);
	return success;
}

/*
Функцію застосовують для генерації секретних значень для секретних ключів для дерев WOTS+ та FORS.
Якщо Shake, то Adr, eles AdrShort
*/


/*
Функцію застосовують для обчислення гешу .
*/

/*
Функцію застосовують для обчислення гешу  в разі, коли повідомлення не довільної завдовжки 
як для функції Tl, а завдовжки 2n.
*/

void HASH(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][N])
{
	/*
Вхід.
PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
ADR – дані про дерева, структура завдовжки 32 байта
Msg – повідомлення довжини 2 * n
Вихід.
HashValue – значення гешу, рядок байтів завдовжки n байтів.

	*/
	
	
	size_t cur_len;
#ifdef _DEBUG
	++HASHCnt;
#endif
#ifdef SHAKE
	uint8_t buf[N + 32 + 2 * N];
	cur_len = N + 32 + 2 * N;
	memcpy(buf, PK_seed, N);
	memcpy(buf + N, Adr, 32);
	memcpy(buf + N + 32, Msg[0], N);
	memcpy(buf + N + 32 + N, Msg[1], N);
	
	shake256(hash_value, N, buf, cur_len);


#else
	uint8_t temp[64];
	ADR_C Adr_c;
	toShort(&Adr_c, (PADR)Adr);
#if N == 16
	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	cur_len = 64 + 22 + 2 * N;
	uint8_t buf[64 + 22 + 2 * N];

	
	memcpy(buf, PK_seed, N);
	memset(buf + N, 0, 64 - N);
	memcpy(buf + 64, (uint8_t*)&Adr_c, 22);
	memcpy(buf + 64 + 22, Msg[0], N);
	memcpy(buf + 64 + 22 + N, Msg[1], N);
	
	sha256(temp, buf, cur_len);
	memcpy(hash_value, temp, N);
	
#else
	// Trunc𝑛 (SHA-512(PK.seed ∥ toByte (0,128−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ)) 
	cur_len = 128 + 22 + 2 * N;
	uint8_t buf[128 + 22 + 2 * N];
	
	memcpy(buf, PK_seed, N);
	memset(buf + N, 0, 128 - N);
	memcpy(buf + 128, (uint8_t *)&Adr_c, 22);
	memcpy(buf + 128 + 22, Msg[0], N);
	memcpy(buf + 128 + 22 + N, Msg[1], N);
		
	sha512(temp, buf, cur_len);
	memcpy(hash_value, temp, N);
	

#endif
#endif
	
	
}

/*
Функцію застосовують для обчислення гешу  в разі, коли повідомлення не довільної завдовжки
як для функції Tl, а завдовжки n.
*/

void F(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t *Adr, const uint8_t Msg[])
{
	/*
Вхід.
PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
ADR – дані про дерева, структура завдовжки 32 байта
M – повідомлення довжини  n
Вихід.
HashValue – значення гешу, рядок байтів завдовжки n байтів.

	*/

	size_t len;
#ifdef _DEBUG
	++FCnt;
#endif
#ifdef SHAKE
	uint8_t buf[N + 32 + N];
	len = N + 32 + N;
	memcpy(buf, PK_seed, N);
	memcpy(buf + N, Adr, 32);
	memcpy(buf + N + 32, Msg, N);
	shake256(hash_value, N, buf, len);
#else
	uint8_t temp[32];
	ADR_C Adr_c;
	toShort(&Adr_c, (PADR)Adr);

	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀1)) 
	uint8_t buf[64 + 22 + N];
	len = 64 + 22 + N;
	memcpy(buf, PK_seed, N);
	memset(buf + N, 0, 64 - N);
	memcpy(buf + 64, (uint8_t*)&Adr_c, 22);
	memcpy(buf + 64 + 22, Msg, N);
	sha256(temp, buf, len);
	memcpy(hash_value, temp, N);
#endif
	
}

#ifdef _PREDCALC
// pk for SHAKE and predcalc_pk for SHA
// adr - full structure for SHAKE and short adr for SHA 
void PRF_with_predcalc(uint8_t* dest, void *pred_pk, uint8_t* adr, uint8_t* SK_seed)
{
#ifdef SHAKE
	uint8_t in[N + 32 + N];
	uint8_t* pk = (uint8_t*)pred_pk;
	memcpy(in, pk, N);
	memcpy(in + N, adr, 32);
	memcpy(in + N + 32, SK_seed, N);
	short_shake256(dest, N, in, N + 32 + N);

#if 0
	ALIGN64 uint64_t s[25] = { 0 };
	uint8_t* ps = (uint8_t*)s;
	memcpy(ps, pk, N );
	memcpy(ps + N , adr, 32);
	memcpy(ps + N  + 32, SK_seed, N );
	
	s[(N + N + 32) / 8] = 0x1F;
	s[16] ^= 1ULL << 63;
	KeccakF1600_StatePermute(s);
	memcpy(dest, s, N);
#endif
#else
	
	uint8_t in[22 + N];
	memcpy(in, adr, 22);
	memcpy(in + 22, SK_seed, N);
	uint32_t* pk = (uint32_t*)pred_pk;
	sha256_with_predcalc2_(dest, pk, in, 22 + N);
#endif
}
//#define F_with_predcalc PRF_with_predcalc	

void HASH_with_predcalc_256(uint8_t* hash_value, const void* pk, uint8_t* Adr, const uint8_t Msg[2][N])
{
#ifdef SHAKE
	uint8_t in[N + 32 + 2 * N];
	const uint8_t* pk_ = (const uint8_t*)pk;
	memcpy(in, pk_, N);
	memcpy(in + N, Adr, 32);
	memcpy(in + N + 32, (uint8_t*)Msg, 2 * N);
	short_shake256(hash_value, N, in, N + 32 + 2 * N);
#else
	uint8_t in[22 + 2 * N];
	const uint32_t* predcalc_pk = (const uint32_t*)pk;
	memcpy(in, Adr, 22);
	memcpy(in + 22, Msg [0] , N);
	memcpy(in + 22 + N, Msg[1], N);
	sha256_with_predcalc2_(hash_value, predcalc_pk, in, 22 + 2 * N);
#endif
}

void Tl_with_predcalc (
	uint8_t* out, 
	void *pk, 
#ifndef SHAKE
	void* pk_n,
#endif
	uint8_t *adr, 
	const uint8_t Msg[][N], 
	size_t len)
{

#if LEN > K
	#ifdef SHAKE
		uint8_t in[N + 32 + LEN * N];
	#else
		uint8_t in[22 + LEN * N];
	#endif
#else
	#ifdef SHAKE
		uint8_t in[22 + K * N];
	#else
		uint8_t in[22 + K * N];
	#endif
#endif // LEN > K
		size_t inlen, j;
		char* p;
		#ifdef SHAKE
			uint8_t* _pk = (uint8_t*)pk;
			inlen = N + 32 + len * N;
			memcpy(in, _pk, N);
			memcpy(in + N, adr, 32);
			p = in + N + 32;
			for (j = 0; j < len; ++j)
			{
				memcpy(p, Msg[j], N);
				p += N;
			}
			//shake256(out, N, in, inlen);
			uint64_t state[25] = { 0 };
			fast_shake256_blocks(state, in, inlen);
			memcpy(out, state, N);
		#else	
			inlen = 22 + len * N;
			memcpy(in, (uint8_t*)adr, 22);
			p = in + 22;
			for (j = 0; j < len; ++j)
			{
				memcpy(p, Msg[j], N);
				p += N;
			}

			#if N == 16
				//uint32_t* predcalc_pk = (uint32_t*)pk;
				sha256_with_predcalc_(out, (uint32_t*)pk_n, in, inlen);
			#endif
			#if N == 24
				//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
				sha512_with_predcalc_(out, (uint64_t*)pk_n, in, inlen);
			#endif
			#if N == 32
				//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
				sha512_with_predcalc_(out, (uint64_t*)pk_n, in, inlen);
			#endif
#endif
}
void HASH_with_predcalc (uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg[2][N])
{
#ifdef SHAKE
	uint8_t in[3 * N + 32];
	uint8_t* _pk = (uint8_t*)pk;
	memcpy(in, _pk, N);
	memcpy(in + N, adr, 32);
	memcpy(in + N + 32, Msg[0], N);
	memcpy(in + N + 32 + N, Msg[1], N);
	short_shake256(out, N, in, 3 * N + 32);
#else
	uint8_t in[22 + 2 * N];
	memcpy(in, adr, 22);
	memcpy(in + 22, Msg[0], N);
	memcpy(in + 22 + N, Msg[1], N);
#if N == 16
	//uint32_t* predcalc_pk = (uint32_t*)predcalc_pk_256;
	sha256_with_predcalc2_(out, /*predcalc_pk*/ (uint32_t*)pk, in, 22 + 2 * N);
#endif
#if N == 24
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * N);
#endif
#if N == 32
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * N);
#endif

#endif
}

void HASH_with_predcalcAdr(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t **Msg)
{
#ifdef SHAKE
	uint8_t in[3 * N + 32];
	uint8_t* _pk = (uint8_t*)pk;
	memcpy(in, _pk, N);
	memcpy(in + N, adr, 32);
	memcpy(in + N + 32, Msg[0], N);
	memcpy(in + N + 32 + N, Msg[1], N);
	short_shake256(out, N, in, 3 * N + 32);
#else
	uint8_t in[22 + 2 * N];
	memcpy(in, adr, 22);
	memcpy(in + 22, Msg[0], N);
	memcpy(in + 22 + N, Msg[1], N);
#if N == 16
	//uint32_t* predcalc_pk = (uint32_t*)predcalc_pk_256;
	sha256_with_predcalc2_(out, /*predcalc_pk*/ (uint32_t*)pk, in, 22 + 2 * N);
#endif
#if N == 24
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * N);
#endif
#if N == 32
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * N);
#endif

#endif
}

void HASH_with_predcalc2(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg1[N], uint8_t Msg2[N])
{
#ifdef SHAKE
	uint8_t in[3 * N + 32];
	uint8_t* _pk = (uint8_t*)pk;
	memcpy(in, _pk, N);
	memcpy(in + N, adr, 32);
	memcpy(in + N + 32, Msg1, N);
	memcpy(in + N + 32 + N, Msg2, N);
	short_shake256(out, N, in, 3 * N + 32);
#else
	uint8_t in[22 + 2 * N];
	memcpy(in, adr, 22);
	memcpy(in + 22, Msg1, N);
	memcpy(in + 22 + N, Msg2, N);
#if N == 16
	//uint32_t* predcalc_pk = (uint32_t*)predcalc_pk_256;
	sha256_with_predcalc2_(out, /*predcalc_pk*/ (uint32_t*)pk, in, 22 + 2 * N);
#endif
#if N == 24
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * N);
#endif
#if N == 32
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * N);
#endif

#endif
}

#endif
SUCCESS test_hashs()
{
	SUCCESS success = OK;
	uint8_t SK_seed[N], SK_prf[N], PK_seed_[N], PK_root[N];
	uint8_t PK [2 * N];
	uint8_t R[N], opt_rand[N];
	uint8_t adr[32], adr_short[22];
	static uint8_t Msg[K + LEN][N] = {0}, Msg2[2][N], Msg1[N];
	uint8_t Msg0[256];
	size_t i, j, k, Msg_len;
	uint8_t dest[M];

	uint8_t dest1[ M];

	//FILE* f = fopen("new_hashs.bin", "wb");
	srand(0);
	for (i = 0; i < 256; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			SK_seed[j] = rand() % 256;
			SK_prf[j] = rand() % 256;
			PK_seed_[j] = rand() % 256;
			PK_root[j] = rand() % 256;
			R[j] = rand() % 256;
			opt_rand[j] = rand() % 256;

		}
		memcpy(PK, PK_seed_, N);
		memcpy(PK + N, PK_root, N);

#ifdef SHAKE
		uint8_t* PK_seed = PK_seed_;
#else
		uint32_t PK_seed[8];
#if N == 16
		uint32_t PK_seed_n[8];
#else
		uint64_t PK_seed_n[8];
#endif
		predcalcs_pk(PK_seed, PK_seed_n, PK_seed_);
#endif


		Msg_len = 50;
		for (j = 0; j < Msg_len; ++j)
			Msg0[j] = rand() % 256;


		for (j = 0; j < 32; ++j)
			adr[j] = rand() % 256;
		toShort((PADR_C)adr_short, (PADR)adr);
				
		for (j = 0; j < 8; ++j)
			for (k = 0; k < N; ++k)
				Msg[j][k] = rand() % 256;
		for (j = 0; j < 2 ; ++j)
			for (k = 0; k < N; ++k)
				Msg2[j][k] = rand() % 256;

		for (j = 0; j < N; ++j)
			Msg1[j] = rand() % 256;

		size_t buf_len = 3 * N + Msg_len + 64;
		if (buf_len < 128)
			buf_len = 128;
		uint8_t* buf = malloc(buf_len);
#ifndef _DEBUG
		uint64_t tacts, mintacts;
		mintacts = 0xFFFFFFFFFFFFFFFF;
		for (i = 0; i < 1024; ++i)
		{
			tacts = __rdtsc();
#endif
			
			success = HMsg(dest, R, PK_seed_, PK_root, Msg0, Msg_len);
#ifndef _DEBUG
			tacts = __rdtsc() - tacts;
			if (tacts < mintacts)
				mintacts = tacts;
		}
		printf("HMsg time = %I64d\n", mintacts);
#endif
		/*if (success == ERROR)
			printf("HMsg Error\n");*/
		//printf("HMsg - %s\n", success == OK ? "OK" : "ERROR");
#ifndef _DEBUG
		mintacts = 0xFFFFFFFFFFFFFFFF;
		for (i = 0; i < 1024; ++i)
		{
			tacts = __rdtsc();
#endif
		HMsg_(dest1, R, 
#if 0
			PK_seed_, PK_root, 
#else
			PK,
#endif
			Msg0, Msg_len, buf);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < mintacts)
			mintacts = tacts;
		}
		printf("HMsg_ time = %I64d\n", mintacts);
#endif
		if (success == OK)
			success = memcmp(dest, dest1, N);
		//printf("HMsg == HMsg_? %s\n", success == 0 ? "OK" : "ERROR");
//#ifdef _DEBUG
//		printf("HMsg - %s\n", success == OK ? "OK" : "ERROR");
//#endif

		//fwrite(dest, M, 1, f);
#ifndef _DEBUG
		mintacts = 0xFFFFFFFFFFFFFFFF;
		for (i = 0; i < 1024; ++i)
		{
			tacts = __rdtsc();
#endif
		success = PRFmsg(dest, SK_prf, opt_rand, Msg0, Msg_len);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < mintacts)
			mintacts = tacts;
		}
		printf("PRFmsg time = %I64d\n", mintacts);
#endif
#ifndef _DEBUG
		mintacts = 0xFFFFFFFFFFFFFFFF;
		for (i = 0; i < 1024; ++i)
		{
			tacts = __rdtsc();
#endif
		PRFmsg_(dest1, SK_prf, opt_rand, Msg0, Msg_len, buf);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < mintacts)
			mintacts = tacts;
		}
		printf("PRFmsg_ time = %I64d\n", mintacts);
#endif
		if (success == OK)
			success = memcmp(dest, dest1, N);
//#ifdef _DEBUG
//			printf("PRFmsg - %s\n", success == OK ? "OK" : "ERROR");
//#endif
		free(buf);
		//void PRF(uint8_t * prf_value, const uint8_t * PK_seed, const uint8_t * SK_seed, uint32_t * Adr);
		//printf("PRF\n");
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		PRF(dest, PK_seed_, adr, SK_seed);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < PRFTime1)
			PRFTime1 = tacts;
		printf("PRF tacts: %I64d\n", tacts);
#endif
#ifdef _PREDCALC
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
#ifdef SHAKE
		PRF_with_predcalc(dest1, PK_seed, adr, SK_seed);
#else
		PRF_with_predcalc(dest1, PK_seed, adr_short, SK_seed);
#endif

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		printf("PRF_with_predcalc tacts: %I64d\n", tacts);
		if (tacts < PRFTime2)
			PRFTime2 = tacts;
#endif
		//success = OK;
		for (j = 0; j < N; ++j)
		{
			if (dest[j] != dest1[j])
				success = ERROR;
		}
//#ifdef _DEBUG
//			printf("PRF - %s\n", success == OK ? "OK" : "ERROR");
//#endif
#endif

#ifndef _DEBUG
		tacts = __rdtsc();
#endif		
		HASH(dest, PK_seed_, adr, Msg);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < HTime1)
			HTime1 = tacts;
		printf("HASH tacts: %I64d\n", tacts);
#endif

//#ifdef _PREDCALC

#ifndef _DEBUG
		tacts = __rdtsc();
#endif
#ifdef SHAKE
		HASH_with_predcalc(dest1, PK_seed, adr, Msg);
#else
		HASH_with_predcalc(dest1, PK_seed_n, adr_short, Msg);

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < HTime2)
			HTime2 = tacts;
		printf("HASH_with_predcalc tacts: %I64d\n", tacts);

#endif
		//success = OK;
		for (j = 0; j < N; ++j)
		{
			if (dest[j] != dest1[j])
				success = ERROR;
		}


#endif

		//SUCCESS Tl(uint8_t * hash_value, const uint8_t * PK_seed, uint32_t * Adr, const uint8_t * Msg, size_t Msg_len);		
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		success = Tl(dest, PK_seed_, adr, Msg, LEN);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < TlTime1)
			TlTime1 = tacts;
		printf("Tl tacts (LEN = %d\t): %I64d\n", LEN, tacts);
#endif

#ifdef _PREDCALC


#ifdef SHAKE
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
	Tl_with_predcalc(dest1, PK_seed, adr, Msg, LEN);
#ifndef _DEBUG
	tacts = __rdtsc() - tacts;
	if (tacts < TlTime2)
		TlTime2 = tacts;
	printf("Tl tacts (LEN = %d\t): %I64d\n", LEN, tacts);
#endif
#else
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		Tl_with_predcalc(dest1, PK_seed, PK_seed_n, adr_short, Msg, LEN);

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < TlTime2)
			TlTime2 = tacts;
		printf("Tl_with_predcalc_tacts (LEN = %d\t): %I64d\n", LEN, tacts);
#endif
		

#endif

		//success = OK;
		for (j = 0; j < N; ++j)
		{
			if (dest[j] != dest1[j])
				success = ERROR;
		}


#endif

#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		success = Tl(dest, PK_seed_, adr, Msg, K);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < TlTime1_K)
			TlTime1_K = tacts;
		printf("Tl tacts (K = %d\n): %I64d\n", K, tacts);
#endif

//#ifdef _PREDCALC


#ifdef SHAKE
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		Tl_with_predcalc(dest1, PK_seed, adr, Msg, K);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < TlTime2_K)
			TlTime2_K = tacts;
		printf("Tl With predcalc (K = %d\t) tacts: %I64d\n", K, tacts);
#endif
#else
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		Tl_with_predcalc(dest1, PK_seed, PK_seed_n, adr_short, Msg, K);

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < TlTime2_K)
			TlTime2_K = tacts;
		printf("Tl_with_predcalc_tacts (K = %d\t): %I64d\n", K, tacts);
#endif
		

#endif
		//success = OK;
		for (j = 0; j < N; ++j)
		{
			if (dest[j] != dest1[j])
				success = ERROR;
		}


#ifndef _DEBUG
		tacts = __rdtsc() ;
#endif

		F(dest, PK_seed_, adr, Msg1);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < FTime1)
			FTime1 = tacts;
		printf("F tacts = %I64d\n", tacts);
#endif

#ifdef _PREDCALC
#ifndef _DEBUG
			tacts = __rdtsc();
			
#endif
#ifdef SHAKE
		F_with_predcalc(dest1, PK_seed, adr, Msg1);
#else
		F_with_predcalc(dest1, PK_seed, adr_short, Msg1);
#endif
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		printf("F tacts =  % I64d\n", tacts);
		if (tacts < FTime2)
			FTime2 = tacts;
#endif
		//success = OK;
		for (j = 0; j < N; ++j)
		{
			if (dest[j] != dest1[j])
				success = ERROR;
		}

#endif
		/*fprintf(f, "F\n");
		fwrite(dest, N, 1, f);*/
//#endif

	}
#ifndef _DEBUG
	printf("PRFTime = %I64d %I64d\n", PRFTime1, PRFTime2);
	printf("TlTime (LEN = %d\t) = %I64d %I64d\n", LEN, TlTime1, TlTime2);
	printf("TlTime (K = %d\t) = %I64d %I64d\n", K, TlTime1_K, TlTime2_K);
	printf("HTime = %I64d %I64d\n", HTime1, HTime2);
	printf("FTime = %I64d %I64d\n", FTime1, FTime2);
#endif
	return success;
}

//Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
//Chaining function used in WOTS + .Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS.Output : Value of F iterated 𝑠 times on 𝑋.
void chain(uint8_t* Y, const uint8_t* X, size_t i, size_t s, const uint8_t* PK_seed, PADR ADRS)
{
	//1 : 𝑡𝑚𝑝 ← 𝑋
	//ADR ADRS = *ADRS_;
	memcpy(Y, X, N);
	//2 : for 𝑗 from 𝑖 to 𝑖 + 𝑠 − 1 do
	size_t j;
	for (j = i; j < i + s; ++j)
	{
		//3 : ADRS.setHashAddress(𝑗)
		setHashAddress(ADRS, (uint32_t)j);
		//4 : 𝑡𝑚𝑝 ← F(PK.seed, ADRS, 𝑡𝑚𝑝)
		F(Y, PK_seed, (uint8_t*)ADRS, Y);
		//5 : end for
	}

}



#ifndef SHAKE
void predcalcs_pk(
	uint32_t *dest_PK_seed, 
#if N == 16
	uint32_t *dest_PK_seed_n, 
#else
	uint64_t* dest_PK_seed_n,
#endif
uint8_t *PK_seed)
{
	predcalc_pk_sha256(dest_PK_seed, PK_seed);

#if N == 16
	memcpy(dest_PK_seed_n, dest_PK_seed, 32);
#else
	predcalc_pk_sha512(dest_PK_seed_n, PK_seed);
#endif

}
#endif
void shake_chain_with_predcalc(uint8_t* res, int i, int s, void* pk_, uint8_t* adr, uint8_t* sk)
{
	//uint8_t adr[32];
	uint8_t* pk = (uint8_t*)pk_;
	uint8_t temp[N + 32 + N];
	//memcpy(adr, adr_, 32);
	//SetAddress4_0(adr, HashAddressOFFSET);
	memcpy(temp, pk, N);
	memcpy(temp + N, adr, 32);
	memcpy(temp + N + 32, sk, N);
	size_t len = 2 * N + 32;
	int j, is = i + s;
	for (j = i; j < is; ++j)
	{
		temp[N + 31] = j;
		short_shake256(temp + N + 32, N, temp, len);
		
	}
	memcpy(res, temp + N + 32, N);
}

void chain_with_predcalc(uint8_t* res, int i, int s, void* pk_, uint8_t* adr, uint8_t* sk)
{
#ifdef SHAKE
	uint8_t* pk = (uint8_t*)pk_;
	/*uint8_t adr[22];
	memcpy(adr, adr_, 22);*/
	shake_chain_with_predcalc(res, i, s, pk, adr, sk);
#else
	uint32_t* pk = (uint32_t*)pk_;
	ShortSetAddress4_0(adr, ShortHashAddressOFFSET);
	sha256_chain_with_predcalc(res, i, s, pk, adr, sk, N);
#endif

}
int test_chain_with_predcalc()
{
	srand(0);
	uint8_t adr[32] = {0,0,0,8}, sk[32], pk[32], res1[32], res2[32];
	#ifndef SHAKE
		uint8_t adr_c[22];
	
		uint32_t predcalc_pk [8];
	#endif
	int i;
	
	for (i = 0; i < 32; ++i)
	{
		//adr[i] = rand() % 256;
		sk[i] = rand() % 256;
		pk[i] = rand() % 256;

	}
#ifndef SHAKE
	toShort((PADR_C)adr_c, (PADR)adr);

	predcalc_pk_sha256(predcalc_pk, pk);
#endif

#ifndef _DEBUG
	uint64_t tacts, mintacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 256; ++i)
	{

		tacts = __rdtsc();
#endif
		chain(res1, sk, 0, 15, pk, (PADR)adr);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < mintacts)
			mintacts = tacts;
	}

	printf("chain time = %I64d\n", mintacts);
	mintacts = 0xFFFFFFFFFFFFFFFF;

	for (i = 0; i < 256; ++i)
	{
		tacts = __rdtsc();
#endif
#ifdef SHAKE
		chain_with_predcalc(res2, 0, 15, pk, adr, sk);
#else
		chain_with_predcalc(res2, 0, 15, predcalc_pk, adr_c, sk);
#endif
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < mintacts)
			mintacts = tacts;
	}
	printf("chain_with_predcalc time = %I64d\n", mintacts);
#endif
	
	/*ShortSetAddress4_0(src1_c, ShortHashAddressOFFSET);
	sha256_chain_with_predcalc(res2, 0, 15, predcalc_pk, src1_c, src2, 16 );*/

	int res = 0;
	for (i = 0; i < 16; ++i)
	{
		if (res1[i] != res2[i])
			res = 1;
	}
	return res;

}

#endif
#endif



void AVX_Tl(uint8_t* out, void* predcalc_pk, uint8_t adr[], __m256i* keys, uint32_t keys_count)
{
#if FIPS205_N == 16
#define MIN_ZEROS_COUNT 8
#define  BLOCK_SIZE  64

	uint32_t* pk = (uint32_t*)predcalc_pk;
	ALIGN64 uint32_t state[8];
#else
#define MIN_ZEROS_COUNT  16 
#define  BLOCK_SIZE  128
	uint64_t* pk = (uint64_t*)predcalc_pk;
	ALIGN64 uint64_t state[8];


#endif
	__m256i *state256 = (__m256i*)state;
#define BYTES_COUNT_MAX  ((FIPS205_LEN > FIPS205_K? FIPS205_LEN :  FIPS205_K) * FIPS205_N + ADR_SIZE)
#define BLOCKS_COUNT_MAX (((BYTES_COUNT_MAX + BLOCK_SIZE - 1)/BLOCK_SIZE) + 1)

	__m256i blocks[BLOCKS_COUNT_MAX][BLOCK_SIZE / sizeof(__m256i)];
	uint32_t* blocks32 = (uint32_t*)blocks;
	uint8_t* blocks8 = (uint8_t*)blocks;
	uint8_t* cur_addr = blocks8, * keys8;
	uint32_t i;
	memcpy(cur_addr, adr, ADR_SIZE);
	cur_addr += ADR_SIZE;
	for (i = 0; i < keys_count; ++i)
	{
		keys8 = (uint8_t*)(keys + i);
		memcpy(cur_addr, keys8, FIPS205_N);
		cur_addr += FIPS205_N;
	}
	(*cur_addr++) = 0x80;
	uint32_t bytes = ADR_SIZE + FIPS205_N * keys_count + BLOCK_SIZE;
	uint32_t cur_bytes = ADR_SIZE + FIPS205_N * keys_count + 1;
	uint32_t max_bytes = (cur_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
	uint32_t zeros_count = max_bytes - cur_bytes;
	if (zeros_count < MIN_ZEROS_COUNT)
		zeros_count += BLOCK_SIZE;
	uint8_t* end_addr = cur_addr + zeros_count;

	memset(cur_addr, 0, zeros_count - 4);
	*(end_addr - 4) = (uint8_t)(bytes >> 21);
	*(end_addr - 3) = (uint8_t)(bytes >> 13);
	*(end_addr - 2) = (uint8_t)(bytes >> 5);
	*(end_addr - 1) = (uint8_t)(bytes << 3);

	uint32_t blocks_count = (uint32_t)((size_t)(end_addr - blocks8) / BLOCK_SIZE);
	memcpy(state, pk, sizeof(state));

#if FIPS205_N == 16
	__m256i w [16];
#else 
	__m256i w[20];
#endif

	for (i = 0; i < blocks_count; ++i)
	{
#if FIPS205_N == 16
		w[0] = _mm256_shuffle_epi8(blocks[i][0], maska_for_shuffle_32);
		w[1] = _mm256_shuffle_epi8(blocks[i][1], maska_for_shuffle_32);
		AVX_sha256_compress(state, w);
#else
		w[0] = _mm256_shuffle_epi8(blocks[i][0], maska_for_shuffle_64);
		w[1] = _mm256_shuffle_epi8(blocks[i][1], maska_for_shuffle_64);
		w[2] = _mm256_shuffle_epi8(blocks[i][2], maska_for_shuffle_64);
		w[3] = _mm256_shuffle_epi8(blocks[i][3], maska_for_shuffle_64);
		AVX_sha512_compress(state, w);
#endif
		
	}
#if FIPS205_N == 16
	state256[0] = _mm256_shuffle_epi8(state256[0], maska_for_shuffle_32);
#else
	state256[0] = _mm256_shuffle_epi8(state256[0], maska_for_shuffle_64);
#endif

	memcpy(out, state, FIPS205_N);


#undef	BYTES_COUNT_MAX
#undef	BLOCKS_COUNT_MAX
#undef	MIN_ZERO_NUMBER
#undef  BLOCK_SIZE  
}

void AVX_Tl_(uint8_t* out, const void* predcalc_pk, uint8_t adr[], uint8_t *keys, uint32_t keys_count)
{
#if FIPS205_N == 16
#define MIN_ZEROS_COUNT 8
#define  BLOCK_SIZE  64

	uint32_t* pk = (uint32_t*)predcalc_pk;
	ALIGN64 uint32_t state[8];
	
#else
#define MIN_ZEROS_COUNT  16 
#define  BLOCK_SIZE  128
	uint64_t* pk = (uint64_t*)predcalc_pk;
	ALIGN64 uint64_t state[8];


#endif
	memcpy(state, predcalc_pk, sizeof(state));
	//__m256i* state256 = (__m256i*)pk;
#define BYTES_COUNT_MAX  ((FIPS205_LEN > FIPS205_K? FIPS205_LEN :  FIPS205_K) * FIPS205_N + ADR_SIZE)
#define BLOCKS_COUNT_MAX (((BYTES_COUNT_MAX + BLOCK_SIZE - 1)/BLOCK_SIZE) + 1)

	__m256i blocks[BLOCKS_COUNT_MAX][BLOCK_SIZE / sizeof(__m256i)];
	//__m256i* blocks = (__m256i*)keys;
	uint32_t* blocks32 = (uint32_t*)blocks;
	//uint8_t* blocks8 = (uint8_t*)blocks;
	uint8_t* cur_addr = (uint8_t*)blocks;
	uint32_t i;
	uint32_t key_size = keys_count * FIPS205_N;
	memcpy(cur_addr, adr, ADR_SIZE);
	memcpy(cur_addr + ADR_SIZE, keys, key_size);

	cur_addr += ADR_SIZE + key_size;
	(*cur_addr++) = 0x80;
	uint32_t bytes = ADR_SIZE + BLOCK_SIZE + key_size;
	uint32_t cur_bytes = ADR_SIZE + key_size + 1;
	uint32_t max_bytes = (cur_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
	uint32_t zeros_count = max_bytes - cur_bytes;
	if (zeros_count < MIN_ZEROS_COUNT)
	{
		zeros_count += BLOCK_SIZE;
		max_bytes += BLOCK_SIZE;
	}
	uint8_t* end_addr = cur_addr + zeros_count;

	memset(cur_addr, 0, zeros_count - 4);
	*(end_addr - 4) = (uint8_t)(bytes >> 21);
	*(end_addr - 3) = (uint8_t)(bytes >> 13);
	*(end_addr - 2) = (uint8_t)(bytes >> 5);
	*(end_addr - 1) = (uint8_t)(bytes << 3);

	uint32_t blocks_count = max_bytes / BLOCK_SIZE;
	//memcpy(state, pk, sizeof(state));

#if FIPS205_N == 16
	
	__m256i w[16];
#else 
	
	__m256i w[20];
#endif
	
	
	for (i = 0; i < blocks_count; ++i)
	{
#if FIPS205_N == 16
		w[0] = _mm256_shuffle_epi8(blocks[i][0], maska_for_shuffle_32);
		w[1] = _mm256_shuffle_epi8(blocks[i][1], maska_for_shuffle_32);
		AVX_sha256_compress(state, w);
#else
		w[0] = _mm256_shuffle_epi8(blocks[i][0], maska_for_shuffle_64);
		w[1] = _mm256_shuffle_epi8(blocks[i][1], maska_for_shuffle_64);
		w[2] = _mm256_shuffle_epi8(blocks[i][2], maska_for_shuffle_64);
		w[3] = _mm256_shuffle_epi8(blocks[i][3], maska_for_shuffle_64);
		AVX_sha512_compress(state, w);
#endif

	}
	__m256i* state256 = (__m256i*)state;
#if FIPS205_N == 16
	state256[0] = _mm256_shuffle_epi8(state256[0], maska_for_shuffle_32);
#else
	state256[0] = _mm256_shuffle_epi8(state256[0], maska_for_shuffle_64);
#endif

	memcpy(out, state, FIPS205_N);


#undef	BYTES_COUNT_MAX
#undef	BLOCKS_COUNT_MAX
#undef	MIN_ZERO_NUMBER
#undef  BLOCK_SIZE  
}

void H_with_predcalc(
	uint8_t* hash_value,
	const void* pk,
	uint8_t* Adr,
	//const uint8_t Msg[2][FIPS205_N])
	const uint8_t Msg1[FIPS205_N],
	const uint8_t Msg2[FIPS205_N])
{
#ifdef SHAKE
	uint8_t in[N + 32 + 2 * N];
	const uint8_t* pk_ = (const uint8_t*)pk;
	memcpy(in, pk_, FIPS205_N);
	memcpy(in + FIPS205_N, Adr, 32);
	memcpy(in + FIPS205_N + 32, Msg1,  FIPS205_N);
	memcpy(in + FIPS205_N + 32 + FIPS205_N, Msg2, FIPS205_N);
	short_shake256(hash_value, FIPS205_N, in, FIPS205_N + 32 + 2 * FIPS205_N);
#else
	uint8_t in[22 + 2 * FIPS205_N];
	const uint32_t* predcalc_pk = (const uint32_t*)pk;
	memcpy(in, Adr, 22);
	memcpy(in + 22, Msg1, FIPS205_N);
	memcpy(in + 22 + FIPS205_N, Msg2, FIPS205_N);
#if FIPS205_N == 16
	AVX_sha256_one_block(hash_value, (uint32_t*)pk, in, 22 + 2 * FIPS205_N, FIPS205_N);
#else
	AVX_sha512_one_block(hash_value, (uint64_t*)pk, in, 22 + 2 * FIPS205_N, FIPS205_N);
#endif
#endif
	
}
