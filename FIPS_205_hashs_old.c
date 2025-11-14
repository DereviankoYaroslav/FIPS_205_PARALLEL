#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "FIPS_205_Params.h"

#ifndef _DEBUG
#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
uint64_t tacts;
#endif

#include "FIPS_205_Hashs_old.h"
#include "FIPS_205_Adr_old.h"
#include "sha2.h"
#include "SHA512.h"

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
SUCCESS PRFmsg_OLD(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, const uint8_t* Msg, size_t Msg_len)
{
	SUCCESS success = ERROR;
#ifdef _DEBUG
	++PRFmsgCnt;
#endif
	size_t len;
	uint8_t* buf = 0;
	{
#ifdef SHAKE
		buf = malloc(N + FIPS205_N + Msg_len);
		if (buf)
		{
			success = OK;
			len = FIPS205_N + FIPS205_N + Msg_len;
			memcpy(buf, SK_prf, FIPS205_N);
			memcpy(buf + FIPS205_N, opt_rand, FIPS205_N);
			memcpy(buf + 2 * FIPS205_N, Msg, Msg_len);
			shake256(dest, FIPS205_N, buf, len);
		}

#else
		uint8_t temp[64];
		/*
		PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑,𝑀) → 
Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀)) 
		*/
		len = FIPS205_N + Msg_len;
		buf = malloc(len);
		if (buf)
		{
			success = OK;
			memcpy(buf, opt_rand, FIPS205_N);
			memcpy(buf + FIPS205_N, Msg, Msg_len);
#if FIPS205_N == 16
			HMAC256(temp, SK_prf, buf, (uint32_t)len);
#else
			HMAC512(temp, SK_prf, buf, (uint32_t)len);
#endif

			memcpy(dest, temp, FIPS205_N);
		}

#endif
	}
	if (success == OK)
		free(buf);
	
	return success;
}


void PRFmsg__OLD(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, const uint8_t* Msg, size_t Msg_len, uint8_t *buf)
{
	size_t len;
	
	
#ifdef SHAKE
		
	len = FIPS205_N + FIPS205_N + Msg_len;
	memcpy(buf, SK_prf, FIPS205_N);
	memcpy(buf + FIPS205_N, opt_rand, FIPS205_N);
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
#if FIPS205_N == 16
	HMAC256(temp, SK_prf, buf, (uint32_t)len);
#else
	HMAC512(temp, SK_prf, buf, (uint32_t)len);
#endif

	memcpy(dest, temp, FIPS205_N);
		

#endif
	
	
}




// Функцію застосовують для генерації гешу при генерації ЦП
// Вхід
//𝑅 – Заданий рядок байтів завдовжки n байтів;
//PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
//PK.root – компонент відкритого ключа, рядок байтів завдовжки n байтів;
//M – повідомлення для генерації ЦП, рядок байтів заданої довжини.
//Вихід.
//Hash_value – рядок байтів завдовжки m байтів, де m – залежит від алгоритму для гешування

SUCCESS HMsg_OLD(uint8_t* dest, const uint8_t* R, const uint8_t* PK_seed, const uint8_t* PK_root, const uint8_t* msg, size_t m_len)
{
	SUCCESS success = ERROR;
	uint8_t* buf = 0;
	size_t len;
#ifdef _DEBUG
	++HMsgCnt;
#endif
#ifdef SHAKE
	len = 3 * FIPS205_N + m_len;
	buf = malloc(len);
	if (buf)
	{
		success = OK;
		memcpy(buf, R, FIPS205_N);
		memcpy(buf + N, PK_seed, FIPS205_N);
		memcpy(buf + 2 * FIPS205_N, PK_root, FIPS205_N);
		memcpy(buf + 3 * FIPS205_N, msg, m_len);
		shake256(dest, FIPS205_M, buf, len);
	}

#else
#if FIPS205_N == 16
	// MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀),𝑚)
	len =  3 * FIPS205_N + m_len;
	/*if (len < 128)
		len = 128;*/
	buf = malloc((len >= 128? len : 128));
	if (buf)
	{
		success = OK;
		memcpy(buf, R, FIPS205_N);
		memcpy(buf + FIPS205_N, PK_seed, FIPS205_N);
		memcpy(buf + 2 * FIPS205_N, PK_root, FIPS205_N);
		memcpy(buf + 3 * FIPS205_N, msg, m_len);
		sha256(buf + 2 * FIPS205_N, buf, len);
		mgf1_sha256(dest, FIPS205_M, buf, 2 * FIPS205_N + 32);

	}
#else
	// MGF1-SHA-512 (𝑅 ∥ PK.seed ∥ SHA-512 ( 𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀),𝑚) 
	len = 3 * FIPS205_N + m_len;
	buf = malloc(len + 64);
	if (buf)
	{
		success = OK;
		memcpy(buf, R, FIPS205_N);
		memcpy(buf + FIPS205_N, PK_seed, FIPS205_N);
		memcpy(buf + 2 * FIPS205_N, PK_root, FIPS205_N);
		memcpy(buf + 3 * FIPS205_N, msg, m_len);
		sha512(buf + 2 * FIPS205_N, buf, len);
		MGF1_sha512(dest, FIPS205_M, buf, 2 * FIPS205_N + 64);
	}
#endif
#endif
	if (success == OK)
		free(buf);
	return success;
}


void HMsg__OLD(
	uint8_t* dest, 
	const uint8_t* R, 
	const uint8_t* PK,
	const uint8_t* msg, 
	size_t m_len,
	uint8_t *buf)
{
	SUCCESS success = ERROR;
	
	size_t len;

#ifdef SHAKE
	len = 3 * FIPS205_N + m_len;
	
	memcpy(buf, R, FIPS205_N);

	memcpy(buf + N, PK, 2 * N);

	memcpy(buf + 3 * FIPS205_N, msg, m_len);
	shake256(dest, FIPS205_M, buf, len);
	

#else
	len = 3 * FIPS205_N + m_len;
	memcpy(buf, R, FIPS205_N);

	memcpy(buf + FIPS205_N, PK, 2 * FIPS205_N);

	memcpy(buf + 3 * FIPS205_N, msg, m_len);
#if FIPS205_N == 16

	sha256(buf + 2 * FIPS205_N, buf, len);

	mgf1_sha256(dest, FIPS205_M, buf, 2 * FIPS205_N + 32);

#else

	sha512(buf + 2 * FIPS205_N, buf, len);
	MGF1_sha512(dest, FIPS205_M, buf, 2 * FIPS205_N + 64);
	
#endif
#endif
	
}


/*
Функцію застосовують для генерації секретних значень для секретних ключів для дерев WOTS+ та FORS.
Якщо Shake, то Adr, eles AdrShort
*/
void PRF_OLD(uint8_t* prf_value, const uint8_t* PK_seed, const uint8_t* Adr, const uint8_t* SK_seed)
{
	/*
	Вхід.
PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
SK.seed – компонент секретного ключа, рядок байтів завдовжки n байтів;
ADR – дані про дерева, структура завдовжки 32 байта
Вихід.
prf_value – рядок байтів завдовжки n байтів.

	*/
#ifdef _DEBUG
	++PRFCnt;
#endif
#ifdef SHAKE
	uint8_t buf [FIPS205_N + FIPS205_N + 32];
	memcpy(buf, PK_seed, FIPS205_N);
	memcpy(buf + FIPS205_N, Adr, 32);
	memcpy(buf + FIPS205_N + 32, SK_seed, FIPS205_N);
	
	shake256(prf_value, FIPS205_N, buf, 2 * FIPS205_N + 32);
	//short_shake256(prf_value, N, buf, 2 * N + 32);
#else
	uint8_t temp[64];
	ADR_C_OLD Adr_c;
	toShort_OLD(&Adr_c, (PADR_OLD)Adr);
	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ SK.seed)) 
	uint8_t buf[64 + 22 + FIPS205_N];
	size_t len = 64 + 22 + FIPS205_N;
	memcpy(buf, PK_seed, FIPS205_N);
	memset(buf + FIPS205_N, 0, 64 - FIPS205_N);
	memcpy(buf + 64, (uint8_t*)&Adr_c, 22);
	memcpy(buf + 64 + 22, SK_seed, FIPS205_N);
	sha256(temp, buf, len);
	memcpy(prf_value, temp, FIPS205_N);


#endif
	
}

/*
Функцію застосовують для обчислення гешу .
*/
SUCCESS Tl_OLD(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][FIPS205_N], size_t len)
{
	/*
Вхід.
PK.seed – компонент відкритого ключа, рядок байтів завдовжки n байтів;
ADR – дані про дерева, структура завдовжки 32 байта
M – len повідомлень, кожне завдовжки n.
Вихід.
hash_value – значення гешу, рядок байтів завдовжки n байтів.


	*/
	SUCCESS success = ERROR;
	uint8_t* buf = 0;
	size_t cur_len;
#ifdef _DEBUG
	++TlCnt;
#endif
#ifdef SHAKE
	cur_len = FIPS205_N + 32 + len * FIPS205_N;
	buf = malloc(cur_len);
	if (buf)
	{
		success = OK;
		memcpy(buf, PK_seed, FIPS205_N);
		memcpy(buf + FIPS205_N, Adr, 32);
		uint8_t* p = buf + FIPS205_N + 32;
		size_t j;
		for (j = 0; j < len; ++j)
		{
			memcpy(p, Msg[j], FIPS205_N);
			p += FIPS205_N;
		}

		shake256(hash_value, FIPS205_N, buf, cur_len);

	}

#else
	uint8_t temp[64];
	ADR_C_OLD Adr_c;
	toShort_OLD(&Adr_c, (PADR_OLD)Adr);
#if FIPS205_N == 16
	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	cur_len = 64 + 22 + len * FIPS205_N;
	buf = malloc(cur_len);
	if (buf)
	{
		success = OK;
		memcpy(buf, PK_seed, FIPS205_N);
		memset(buf + FIPS205_N, 0, 64 - FIPS205_N);
		memcpy(buf + 64, (uint8_t*)&Adr_c, 22);
		uint8_t* p = buf + 64 + 22;
		size_t j;
		for (j = 0; j < len; ++j)
		{
			memcpy(p, Msg[j], FIPS205_N);
			p += FIPS205_N;
		}
		
		sha256(temp, buf, cur_len);
		memcpy(hash_value, temp, FIPS205_N);
	}
#else
	// Trunc𝑛 (SHA-512(PK.seed ∥ toByte (0,128−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ)) 
	cur_len = 128 + 22 + len * FIPS205_N;
	buf = malloc(cur_len);
	if (buf)
	{
		success = OK;
		memcpy(buf, PK_seed, FIPS205_N);
		memset(buf + FIPS205_N, 0, 128 - FIPS205_N);
		memcpy(buf + 128, (uint8_t*)&Adr_c, 22);
		uint8_t* p = buf + 128 + 22;
		size_t j;
		for (j = 0; j < len; ++j)
		{
			memcpy(p, Msg[j], FIPS205_N);
			p += FIPS205_N;
		}

		//memcpy(buf + 128 + 22, Msg, Msg_len);
		sha512(temp, buf, cur_len);
		memcpy(hash_value, temp, FIPS205_N);
	}
	
#endif
#endif
	if (success == OK)
		free(buf);
	return success;
}

/*
Функцію застосовують для обчислення гешу  в разі, коли повідомлення не довільної завдовжки 
як для функції Tl, а завдовжки 2n.
*/

void HASH_OLD(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[2][FIPS205_N])
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
	uint8_t buf[FIPS205_N + 32 + 2 * FIPS205_N];
	cur_len = FIPS205_N + 32 + 2 * FIPS205_N;
	memcpy(buf, PK_seed, FIPS205_N);
	memcpy(buf + FIPS205_N, Adr, 32);
	memcpy(buf + FIPS205_N + 32, Msg[0], FIPS205_N);
	memcpy(buf + FIPS205_N + 32 + FIPS205_N, Msg[1], FIPS205_N);
	
	shake256(hash_value, FIPS205_N, buf, cur_len);


#else
	uint8_t temp[64];
	ADR_C_OLD Adr_c;
	toShort_OLD(&Adr_c, (PADR_OLD)Adr);
#if FIPS205_N == 16
	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	cur_len = 64 + 22 + 2 * FIPS205_N;
	uint8_t buf[64 + 22 + 2 * FIPS205_N];

	
	memcpy(buf, PK_seed, FIPS205_N);
	memset(buf + FIPS205_N, 0, 64 - FIPS205_N);
	memcpy(buf + 64, (uint8_t*)&Adr_c, 22);
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
	memcpy(buf + 128, (uint8_t *)&Adr_c, 22);
	memcpy(buf + 128 + 22, Msg[0], FIPS205_N);
	memcpy(buf + 128 + 22 + FIPS205_N, Msg[1], FIPS205_N);
		
	sha512(temp, buf, cur_len);
	memcpy(hash_value, temp, FIPS205_N);
	

#endif
#endif
	
	
}

/*
Функцію застосовують для обчислення гешу  в разі, коли повідомлення не довільної завдовжки
як для функції Tl, а завдовжки n.
*/

void F_OLD(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t *Adr, const uint8_t Msg[])
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
	uint8_t buf[FIPS205_N + 32 + FIPS205_N];
	len = FIPS205_N + 32 + FIPS205_N;
	memcpy(buf, PK_seed, FIPS205_N);
	memcpy(buf + FIPS205_N, Adr, 32);
	memcpy(buf + FIPS205_N + 32, Msg, FIPS205_N);
	shake256(hash_value, FIPS205_N, buf, len);
#else
	uint8_t temp[32];
	ADR_C_OLD Adr_c;
	toShort_OLD(&Adr_c, (PADR_OLD)Adr);

	// Trunc𝑛(SHA-256(PK.seed ∥ toByte(0,64−𝑛) ∥ ADRS𝑐 ∥ 𝑀1)) 
	uint8_t buf[64 + 22 + FIPS205_N];
	len = 64 + 22 + FIPS205_N;
	memcpy(buf, PK_seed, FIPS205_N);
	memset(buf + FIPS205_N, 0, 64 - FIPS205_N);
	memcpy(buf + 64, (uint8_t*)&Adr_c, 22);
	memcpy(buf + 64 + 22, Msg, FIPS205_N);
	sha256(temp, buf, len);
	memcpy(hash_value, temp, FIPS205_N);
#endif
	
}

#ifdef _PREDCALC
// pk for SHAKE and predcalc_pk for SHA
// adr - full structure for SHAKE and short adr for SHA 
void PRF_with_predcalc_OLD(uint8_t* dest, void *pred_pk, uint8_t* adr, uint8_t* SK_seed)
{
#ifdef SHAKE
	uint8_t in[FIPS205_N + 32 + FIPS205_N];
	uint8_t* pk = (uint8_t*)pred_pk;
	memcpy(in, pk, FIPS205_N);
	memcpy(in + FIPS205_N, adr, 32);
	memcpy(in + FIPS205_N + 32, SK_seed, FIPS205_N);
	short_shake256(dest, FIPS205_N, in, FIPS205_N + 32 + FIPS205_FIPS205_N);


#else
	
	uint8_t in[22 + FIPS205_N];
	memcpy(in, adr, 22);
	memcpy(in + 22, SK_seed, FIPS205_N);
	uint32_t* pk = (uint32_t*)pred_pk;
	sha256_with_predcalc2_(dest, pk, in, 22 + FIPS205_N);
#endif
}
//#define F_with_predcalc PRF_with_predcalc	

void HASH_with_predcalc_256_OLD(uint8_t* hash_value, const void* pk, uint8_t* Adr, const uint8_t Msg[2][FIPS205_N])
{
#ifdef SHAKE
	uint8_t in[FIPS205_N + 32 + 2 * FIPS205_N];
	const uint8_t* pk_ = (const uint8_t*)pk;
	memcpy(in, pk_, FIPS205_N);
	memcpy(in + FIPS205_N, Adr, 32);
	memcpy(in + FIPS205_N + 32, (uint8_t*)Msg, 2 * FIPS205_N);
	short_shake256(hash_value, FIPS205_N, in, FIPS205_N + 32 + 2 * FIPS205_N);
#else
	uint8_t in[22 + 2 * FIPS205_N];
	const uint32_t* predcalc_pk = (const uint32_t*)pk;
	memcpy(in, Adr, 22);
	memcpy(in + 22, Msg [0] , FIPS205_N);
	memcpy(in + 22 + FIPS205_N, Msg[1], FIPS205_N);
	sha256_with_predcalc2_(hash_value, predcalc_pk, in, 22 + 2 * FIPS205_N);
#endif
}

void Tl_with_predcalc_OLD (
	uint8_t* out, 
	void *pk, 
#ifndef SHAKE
	void* pk_n,
#endif
	uint8_t *adr, 
	const uint8_t Msg[][FIPS205_N],
	size_t len)
{

#if FIPS205_LEN > FIPS205_K
	#ifdef SHAKE
		uint8_t in[N + 32 + FIPS205_LEN * FIPS205_N];
	#else
		uint8_t in[22 + FIPS205_LEN * FIPS205_N];
	#endif
#else
	#ifdef SHAKE
		uint8_t in[22 + FIPS205_K * FIPS205_N];
	#else
		uint8_t in[22 + FIPS205_K * FIPS205_N];
	#endif
#endif // LEN > K
		size_t inlen, j;
		uint8_t temp[64];
		char* p;
		#ifdef SHAKE
			uint8_t* _pk = (uint8_t*)pk;
			inlen = FIPS205_N + 32 + len * FIPS205_N;
			memcpy(in, _pk, FIPS205_N);
			memcpy(in + FIPS205_N, adr, 32);
			p = in + FIPS205_N + 32;
			for (j = 0; j < len; ++j)
			{
				memcpy(p, Msg[j], FIPS205_N);
				p += FIPS205_N;
			}
			//shake256(out, N, in, inlen);
			uint64_t state[25] = { 0 };
			fast_shake256_blocks(state, in, inlen);
			memcpy(out, state, FIPS205_N);
		#else	
			inlen = 22 + len * FIPS205_N;
			memcpy(in, (uint8_t*)adr, 22);
			p = in + 22;
			for (j = 0; j < len; ++j)
			{
				memcpy(p, Msg[j], FIPS205_N);
				p += FIPS205_N;
			}

			#if FIPS205_N == 16
				//uint32_t* predcalc_pk = (uint32_t*)pk;
			//void sha256_with_predcalc2_(uint8_t * out, uint32_t * predcalc, uint8_t * in, size_t inlen)
				sha256_with_predcalc_(temp, (uint32_t*)pk_n, in, inlen);
			#endif
			#if FIPS205_N == 24
				//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
				sha512_with_predcalc_(temp, (uint64_t*)pk_n, in, inlen);
			#endif
			#if FIPS205_N == 32
				//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
				sha512_with_predcalc_(temp, (uint64_t*)pk_n, in, inlen);
			#endif
				memcpy(out, temp, FIPS205_N);
#endif
}
void HASH_with_predcalc_OLD (uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg[2][FIPS205_N])
{
	uint8_t temp[64];
#ifdef SHAKE
	uint8_t in[3 * FIPS205_N + 32];
	uint8_t* _pk = (uint8_t*)pk;
	memcpy(in, _pk, FIPS205_N);
	memcpy(in + FIPS205_N, adr, 32);
	memcpy(in + FIPS205_N + 32, Msg[0], FIPS205_N);
	memcpy(in + FIPS205_N + 32 + FIPS205_N, Msg[1], FIPS205_N);
	short_shake256(out, FIPS205_N, in, 3 * FIPS205_N + 32);
#else
	uint8_t in[22 + 2 * FIPS205_N];
	memcpy(in, adr, 22);
	memcpy(in + 22, Msg[0], FIPS205_N);
	memcpy(in + 22 + FIPS205_N, Msg[1], FIPS205_N);
#if FIPS205_N == 16
	//uint32_t* predcalc_pk = (uint32_t*)predcalc_pk_256;
	sha256_with_predcalc2_(temp, /*predcalc_pk*/ (uint32_t*)pk, in, 22 + 2 * FIPS205_N);
#endif
#if FIPS205_N == 24
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
	// void sha512_with_predcalc2_(uint8_t* out, uint64_t* state, const uint8_t* in, uint32_t inlen, uint32_t outlen)
	sha512_with_predcalc2_(temp, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * FIPS205_N/*, FIPS205_N*/);
#endif
#if FIPS205_N == 32
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
	sha512_with_predcalc2_(temp, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * FIPS205_N/*, FIPS205_N*/);
#endif
	memcpy(out, temp, FIPS205_N);

#endif
}

void HASH_with_predcalcAdr_OLD(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t **Msg)
{
#ifdef SHAKE
	uint8_t in[3 * FIPS205_N + 32];
	uint8_t* _pk = (uint8_t*)pk;
	memcpy(in, _pk, FIPS205_N);
	memcpy(in + FIPS205_N, adr, 32);
	memcpy(in + FIPS205_N + 32, Msg[0], FIPS205_N);
	memcpy(in + FIPS205_N + 32 + FIPS205_N, Msg[1], FIPS205_N);
	short_shake256(out, FIPS205_N, in, 3 * FIPS205_N + 32);
#else
	uint8_t in[22 + 2 * FIPS205_N];
	memcpy(in, adr, 22);
	memcpy(in + 22, Msg[0], FIPS205_N);
	memcpy(in + 22 + FIPS205_N, Msg[1], FIPS205_N);
#if FIPS205_N == 16
	//uint32_t* predcalc_pk = (uint32_t*)predcalc_pk_256;
	sha256_with_predcalc2_(out, /*predcalc_pk*/ (uint32_t*)pk, in, 22 + 2 * FIPS205_N);
#endif
#if FIPS205_N == 24
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * FIPS205_N);
#endif
#if FIPS205_N == 32
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * FIPS205_N);
#endif

#endif
}

void HASH_with_predcalc2_OLD(uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg1[FIPS205_N], uint8_t Msg2[FIPS205_N])
{
#ifdef SHAKE
	uint8_t in[3 * FIPS205_N + 32];
	uint8_t* _pk = (uint8_t*)pk;
	memcpy(in, _pk, FIPS205_N);
	memcpy(in + FIPS205_N, adr, 32);
	memcpy(in + FIPS205_N + 32, Msg1, N);
	memcpy(in + FIPS205_N + 32 + FIPS205_N, Msg2, FIPS205_N);
	short_shake256(out, FIPS205_N, in, 3 * FIPS205_N + 32);
#else
	uint8_t in[22 + 2 * FIPS205_N];
	memcpy(in, adr, 22);
	memcpy(in + 22, Msg1, FIPS205_N);
	memcpy(in + 22 + FIPS205_N, Msg2, FIPS205_N);
#if FIPS205_N == 16
	//uint32_t* predcalc_pk = (uint32_t*)predcalc_pk_256;
	sha256_with_predcalc2_(out, /*predcalc_pk*/ (uint32_t*)pk, in, 22 + 2 * FIPS205_N);
#endif
#if FIPS205_N == 24
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_384;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * FIPS205_N);
#endif
#if FIPS205_N == 32
	//uint64_t* predcalc_pk = (uint64_t*)predcalc_pk_512;
	sha512_with_predcalc2_(out, (uint64_t*)/*predcalc_pk*/pk, in, 22 + 2 * FIPS205_N);
#endif

#endif
}

#endif

//Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
//Chaining function used in WOTS + .Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS.Output : Value of F iterated 𝑠 times on 𝑋.
void chain_OLD(uint8_t* Y, const uint8_t* X, size_t i, size_t s, const uint8_t* PK_seed, PADR_OLD ADRS)
{
	//1 : 𝑡𝑚𝑝 ← 𝑋
	//ADR ADRS = *ADRS_;
	memcpy(Y, X, FIPS205_N);
	//2 : for 𝑗 from 𝑖 to 𝑖 + 𝑠 − 1 do
	size_t j;
	for (j = i; j < i + s; ++j)
	{
		//3 : ADRS.setHashAddress(𝑗)
		setHashAddress_OLD(ADRS, (uint32_t)j);
		//4 : 𝑡𝑚𝑝 ← F(PK.seed, ADRS, 𝑡𝑚𝑝)
		F_OLD(Y, PK_seed, (uint8_t*)ADRS, Y);
		//5 : end for
	}

}



#ifndef SHAKE
void predcalcs_pk(
	uint32_t *dest_PK_seed, 
#if FIPS205_N == 16
	uint32_t *dest_PK_seed_n, 
#else
	uint64_t* dest_PK_seed_n,
#endif
uint8_t *PK_seed)
{
	sha256_predcalc_pk(dest_PK_seed, PK_seed);

#if FIPS205_N == 16
	memcpy(dest_PK_seed_n, dest_PK_seed, 32);
#else
	sha512_predcalc_pk(dest_PK_seed_n, PK_seed);
#endif

}
#endif

void shake_chain_with_predcalc_OLD(uint8_t* res, int i, int s, void* pk_, uint8_t* adr, uint8_t* sk)
{
	//uint8_t adr[32];
	uint8_t* pk = (uint8_t*)pk_;
	uint8_t temp[FIPS205_N + 32 + FIPS205_N];
	//memcpy(adr, adr_, 32);
	//SetAddress4_0(adr, HashAddressOFFSET);
	memcpy(temp, pk, FIPS205_N);
	memcpy(temp + FIPS205_N, adr, 32);
	memcpy(temp + FIPS205_N + 32, sk, FIPS205_N);
	size_t len = 2 * FIPS205_N + 32;
	int j, is = i + s;
	for (j = i; j < is; ++j)
	{
		temp[FIPS205_N + 31] = j;
		short_shake256(temp + FIPS205_N + 32, FIPS205_N, temp, len);
		
	}
	memcpy(res, temp + FIPS205_N + 32, FIPS205_N);
}

void chain_with_predcalc_OLD(uint8_t* res, int i, int s, void* pk_, uint8_t* adr, uint8_t* sk)
{
#ifdef SHAKE
	uint8_t* pk = (uint8_t*)pk_;
	/*uint8_t adr[22];
	memcpy(adr, adr_, 22);*/
	shake_chain_with_predcalc(res, i, s, pk, adr, sk);
#else
	uint32_t* pk = (uint32_t*)pk_;
	ShortSetAddress4_0_OLD(adr, ShortHashAddressOFFSET_OLD);
	sha256_chain_with_predcalc(res, i, s, pk, adr, sk, FIPS205_N);
#endif

}