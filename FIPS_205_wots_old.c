#include <omp.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _GETTIME
#include <intrin.h>

#endif
#include "FIPS_205_Hashs_old.h"
#include "FIPS_205_wots_old.h"

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
/*
Algorithm 7 wots_sign(𝑀, SK.seed, PK.seed, ADRS)
Generates a WOTS+ signature on an 𝑛-byte message.
	Input:
		Message 𝑀sg,
		secret seed SK.seed,
		public seed PK.seed,
		address ADRS.
	Output:
		WOTS+ signature 𝑠𝑖𝑔.
*/



void wots_sign_OLD(
	uint8_t* WOTS_SIG,
	const uint8_t* Msg,
	const uint8_t* SK_seed,
	const uint8_t* PK_seed,
	PADR_OLD adr)
{
	// 1: 𝑐𝑠𝑢𝑚 ← 0

//#ifdef _GETTIME
//	uint64_t tacts;
//	tacts = __rdtsc();
//#endif
	
	uint8_t* p = WOTS_SIG;
	size_t csum = 0, i;
	uint32_t msg[FIPS205_LEN1 + 10];
	// 𝑚𝑠𝑔 ← base_2b(𝑀,𝑙𝑔𝑤,𝑙𝑒𝑛1) ▷ convert message to base 𝑤
	base_2b(msg, Msg, FIPS205_LOGW, FIPS205_LEN1);
	// 	3: for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum

	for (i = 0; i < FIPS205_LEN1; ++i)
	{
		// 4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
		csum += FIPS205_W - 1 - msg[i];

	}
	// 6: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8) ▷ for 𝑙𝑔𝑤 = 4, left shift by 4
	csum <<= ((8 - ((FIPS205_LEN2 * FIPS205_LOGW) % 8)) % 8);
	// 7: 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈𝑙𝑒𝑛2⋅𝑙𝑔𝑤 ⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2) ▷ convert to base 𝑤
	uint8_t temp[10];
	toByte32(temp, (uint32_t)csum, (FIPS205_LEN2 * FIPS205_LOGW + 7) / 8);
	base_2b(msg + FIPS205_LEN1, temp, FIPS205_LOGW, FIPS205_LEN2);
	ADR_OLD skADRS;
	//8: skADRS ← ADRS ▷ copy address to create key generation key address
	memcpy(&skADRS, adr, sizeof(ADR_OLD));
	//9: skADRS.setTypeAndClear(WOTS_PRF)
	setTypeAndClear_OLD(&skADRS, WOTS_PRF);
	// 10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	setKeyPairAddress_OLD(&skADRS, getKeyPairAddress_OLD(adr));
	// 11: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
	for (i = 0; i < FIPS205_LEN; ++i)
	{

		uint8_t sk[FIPS205_N];
	/*	if (i == 13)
			printf("");*/
		// 12: skADRS.setChainAddress(𝑖)
		setChainAddress_OLD(&skADRS, (uint32_t)i);
		// 13: 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute chain 𝑖 secret value


		PRF_OLD(sk, PK_seed, (uint8_t*)&skADRS, SK_seed);
		// 14: ADRS.setChainAddress(𝑖)
		setChainAddress_OLD(adr, (uint32_t)i);
		//15: 𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖],PK.seed,ADRS)▷ compute chain 𝑖 signature value
		chain_OLD(p, sk, 0, msg[i], PK_seed, adr);
		//chain_with_predcalc(uint8_t * res, int i, int s, void* pk_, uint8_t * adr, uint8_t * sk)
		p += FIPS205_N;

	}
//#ifdef _GETTIME
//	//uint64_t tacts;
//	tacts = __rdtsc() - tacts;
//	//printf("wots_sign time = %I64d\n", tacts);
//	if (tacts < wots_signTime )
//		wots_signTime = tacts;
//#endif
}

void wots_sign__OLD(
	uint8_t* WOTS_SIG,
	const uint8_t* Msg,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* pk,
#else
	const void* pk,
	const void* pk_seed_n,
#endif
	uint8_t *adr)
{
	// 1: 𝑐𝑠𝑢𝑚 ← 0

//#ifdef _GETTIME
//	uint64_t tacts;
//	tacts = __rdtsc();
//#endif

	uint8_t* p = WOTS_SIG;
	size_t csum = 0; 
	uint32_t msg[FIPS205_LEN1 + 10];
	int i;
	//omp_set_num_threads(8);
	// 𝑚𝑠𝑔 ← base_2b(𝑀,𝑙𝑔𝑤,𝑙𝑒𝑛1) ▷ convert message to base 𝑤
	//csum = base_2b_(msg, Msg, LOGW, LEN1);
	//// 	3: for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum

	////for (i = 0; i < LEN1; ++i)
	////{
	////	// 4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
	////	csum += W - 1 - msg[i];

	////}
	//// 6: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8) ▷ for 𝑙𝑔𝑤 = 4, left shift by 4
	//csum <<= ((8 - ((LEN2 * LOGW) % 8)) % 8);
	//// 7: 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈𝑙𝑒𝑛2⋅𝑙𝑔𝑤 ⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2) ▷ convert to base 𝑤
	//uint8_t temp[10];
	//toByte32(temp, (uint32_t)csum, (LEN2 * LOGW + 7) / 8);
	//base_2b(msg + LEN1, temp, LOGW, LEN2);

	uint32_t len = base_2b_(msg, Msg, FIPS205_LEN);
	
	// 11: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
	uint8_t sk[FIPS205_LEN][FIPS205_N];
#pragma omp parallel
	{
#pragma omp for
		for (i = 0; i < FIPS205_LEN; ++i)
		{
		

#ifdef SHAKE
			uint32_t value;
			uint8_t l_adr[32];
			memcpy(l_adr, adr, 32);
			SetAddress4_OLD(l_adr, TypeAndClearOFFSET, WOTS_PRF);
			GetAddress4_OLD(adr, KeyPairAddressOFFSET, value);
			SetAddress4_OLD(l_adr, KeyPairAddressOFFSET, value);
			SetAddress4_OLD(l_adr, ChainAddressOFFSET, (uint32_t)i);
			*(uint32_t*)(l_adr + 28) = 0;
			//uint8_t* pk = (uint8_t*)pk_;
#else
			uint8_t l_adr[22];
			memcpy(l_adr, adr, 22);
			ShortSetAddressType1_OLD(l_adr, WOTS_PRF);
						
			ShortSetFromGet4_OLD(l_adr, adr, ShortKeyPairAddressOFFSET_OLD);
			ShortSetAddress4_OLD(l_adr, ShortChainAddressOFFSET_OLD, (uint32_t)i);
			
#endif

		

		// 13: 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute chain 𝑖 secret value

#ifdef SHAKE
			PRF_with_predcalc(sk[i], pk, l_adr, SK_seed);
#else
			PRF_with_predcalc_OLD(sk[i], pk, l_adr, SK_seed);

#endif
		}
	
		// 14: ADRS.setChainAddress(𝑖)

#pragma omp for
		for (i = 0; i < FIPS205_LEN; ++i)
		{
			uint8_t l_adr[32];

#ifdef SHAKE
			memcpy(l_adr, adr, 32);
			SetAddress4(l_adr, ChainAddressOFFSET, (uint32_t)i);
			chain_with_predcalc(WOTS_SIG + (uint64_t)i * FIPS205_N, 0, msg[i], pk, l_adr, sk[i]);
#else

			memcpy(l_adr, adr, 22);
			ShortSetAddress4_OLD(l_adr, ShortChainAddressOFFSET_OLD, i);
			chain_with_predcalc_OLD(WOTS_SIG + (uint64_t)i * FIPS205_N, 0, msg[i], pk, l_adr, sk [i]);
#endif

		}
	}
//#ifdef _GETTIME
//	//uint64_t tacts;
//	tacts = __rdtsc() - tacts;
//	//printf("wots_sign time = %I64d\n", tacts);
//	if (tacts < wots_signTime)
//		wots_signTime = tacts;
//#endif
}



/*
Algorithm 8 wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
Computes a WOTS+ public key from a message and its signature.
	Input:
		WOTS+ signature 𝑠𝑖𝑔,
		message 𝑀,
		public seed PK.seed,
		address ADRS.
	Output:
		WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔.
*/
//void wots_pkFromSig_(
//#if 1
//	uint8_t* pksig,
//#else
//	uint8_t tmp[][FIPS205_N],
//#endif
//	const uint8_t* sig,
//	const uint8_t* Msg,
//	const uint8_t* PK_seed,
//	PADR_OLD adr)
//{
//	// 1: 𝑐𝑠𝑢𝑚 ← 0
////#ifdef _GETTIME
////	uint64_t tacts;
////	tacts = __rdtsc();
////	
////#endif
//	uint32_t csum = 0;
//	uint32_t msg[FIPS205_LEN1 + FIPS205_LEN2];
//	const uint8_t* psig = sig;
//	// 2: 𝑚𝑠𝑔 ← base_2b(𝑀,𝑙𝑔𝑤,𝑙𝑒𝑛1) ▷ convert message to base 𝑤
//	base_2b(msg, Msg, FIPS205_LOGW, FIPS205_LEN1);
//	// 3: for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
//	size_t i;
//	for (i = 0; i < FIPS205_LEN1; ++i)
//	{
//		//4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
//		csum += FIPS205_W - 1 - msg[i];
//
//	}
//	// 6: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8) ▷ 
//	csum <<= ((8 - ((FIPS205_LEN2 * FIPS205_LOGW) % 8)) % 8);
//	// 7: 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈𝑙𝑒𝑛2⋅𝑙𝑔𝑤 ⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2) ▷ convert to base 𝑤
//	uint8_t temp[FIPS205_N];
//	toByte32(temp, csum, (FIPS205_LEN2 * FIPS205_LOGW + 7) / 8);
//	base_2b(msg + FIPS205_LEN1, temp, FIPS205_LOGW, FIPS205_LEN2);
//	// 8: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
//	//uint32_t i;
//#if 1
//	uint8_t tmp[FIPS205_LEN][FIPS205_N];
//#endif
//	for (i = 0; i < FIPS205_LEN; ++i)
//	{
//		// 9: ADRS.setChainAddress(𝑖)
//		setChainAddress_OLD(adr, (uint32_t)i);
//		// 10: 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑖𝑔[𝑖], 𝑚𝑠𝑔[𝑖], 𝑤 − 1 − 𝑚𝑠𝑔[𝑖],PK.seed,ADRS)
//		// void chain(uint8_t* Y, uint8_t* X, size_t i, size_t s, const uint8_t* PK_seed, PADR ADRS)
//		chain_OLD(tmp[i], psig, msg[i], FIPS205_W - 1 - msg[i], PK_seed, adr);
//		psig += FIPS205_N;		// ????????????????
//		// 11: end for
//	}
//
//	ADR_OLD wotspkADRS;
//	memcpy(&wotspkADRS, adr, 32);
//	// 13: wotspkADRS.setTypeAndClear(WOTS_PK)
//	setTypeAndClear_OLD(&wotspkADRS, WOTS_PK);
//	// 14: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
//	setKeyPairAddress_OLD(&wotspkADRS, getKeyPairAddress_OLD(adr));
//
////#ifdef _GETTIME
////
////	tacts = __rdtsc() - tacts;
////	//printf("wots_pkFromSig time = %I64d\n", tacts);
////	if (tacts < wots_pkFromSigTime)
////		wots_pkFromSigTime = tacts;
////#endif
//#if 1
//	Tl(pksig, PK_seed, (uint8_t*)&wotspkADRS, tmp, FIPS205_LEN);
//#endif
////#ifdef _GETTIME
////	
////	tacts = __rdtsc() - tacts;
////	//printf("wots_pkFromSig time = %I64d\n", tacts);
////	if (tacts < wots_pkFromSigTime)
////		wots_pkFromSigTime = tacts;
////#endif
//}

/*
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
	uint8_t* adr)
*/
void wots_pkFromSig_(

	uint8_t* pksig,
	const uint8_t* sig,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void * PK_seed,
	const void*  PK_seed_n,
#endif

	uint8_t *adr)
{
	// 1: 𝑐𝑠𝑢𝑚 ← 0
//#ifdef _GETTIME
//	uint64_t tacts;
//	tacts = __rdtsc();
//
//#endif
	//uint32_t csum = 0;
	uint32_t msg[FIPS205_LEN];
	//const uint8_t* psig = sig;
	// 2: 𝑚𝑠𝑔 ← base_2b(𝑀,𝑙𝑔𝑤,𝑙𝑒𝑛1) ▷ convert message to base 𝑤
	base_2b_(msg, Msg, /*LOGW, */FIPS205_LEN);
	// 3: for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
	//int i;
	//for (i = 0; i < LEN1; ++i)
	//{
	//	//4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
	//	csum += W - 1 - msg[i];
	//	/*



	//	5: end for
	//	*/

	//}
	//// 6: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8) ▷ 
	//csum <<= ((8 - ((LEN2 * LOGW) % 8)) % 8);
	//// 7: 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈𝑙𝑒𝑛2⋅𝑙𝑔𝑤 ⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2) ▷ convert to base 𝑤
	//uint8_t temp[N];
	//toByte32(temp, csum, (LEN2 * LOGW + 7) / 8);
	//base_2b(msg + LEN1, temp, LOGW, LEN2);
	//// 8: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
	////uint32_t i;
#if 1
	uint8_t tmp[FIPS205_LEN][FIPS205_N];
#endif
	int i;
	//omp_set_num_threads(8);

#pragma omp parallel for
	for (i = 0; i < FIPS205_LEN; ++i)
	{
#ifdef SHAKE
		uint8_t local_adr[32];
		memcpy(local_adr, adr, 32);
		SetAddress4(local_adr, ChainAddressOFFSET, i);
#else
		uint8_t local_adr[22];
		memcpy(local_adr, adr, 22);
		ShortSetAddress4_OLD(local_adr, ShortChainAddressOFFSET_OLD, i);
#endif

		// 9: ADRS.setChainAddress(𝑖)
		//setChainAddress(adr, (uint32_t)i);
		
		
		// 10: 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑖𝑔[𝑖], 𝑚𝑠𝑔[𝑖], 𝑤 − 1 − 𝑚𝑠𝑔[𝑖],PK.seed,ADRS)
		// void chain(uint8_t* Y, uint8_t* X, size_t i, size_t s, const uint8_t* PK_seed, PADR ADRS)
		//chain_(tmp[i], psig, msg[i], W - 1 - msg[i], PK_seed, adr);
		// chain_with_predcalc(uint8_t* res, int i, int s, void* pk_, uint8_t* adr, uint8_t* sk)

		chain_with_predcalc_OLD(tmp[i], msg[i], FIPS205_W - 1 - msg[i], PK_seed, local_adr, sig + i * FIPS205_N);
		
		//psig += N;		// ????????????????
		// 11: end for
	}

	// 12: wotspkADRS ← ADRS ▷ copy address to create WOTS+ public key address
#if 1
#ifdef SHAKE
	uint32_t value;
	uint8_t local_adr[32];
	memcpy(local_adr, adr, 32);
	SetAddress4_OLD(local_adr, TypeAndClearOFFSET, WOTS_PK);
	memset(local_adr + 24, 0, 8);
	// //setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adr));
	GetAddress4_OLD((uint8_t*)adr, KeyPairAddressOFFSET, value);
	SetAddress4_OLD(local_adr, KeyPairAddressOFFSET, value);
	
#else
	uint8_t local_adr[22];
	memcpy(local_adr, adr, 22);
	ShortSetAddressType1_OLD(local_adr, WOTS_PK);
	//ShortGetAddress4(adr, ShortKeyPairAddressOFFSET, value);
	//ShortSetAddress4(local_adr, ShortKeyPairAddressOFFSET, value);
	ShortSetFromGet4_OLD(local_adr, adr, ShortKeyPairAddressOFFSET_OLD);
#endif
	// 13: wotspkADRS.setTypeAndClear(WOTS_PK)
	//setTypeAndClear(&wotspkADRS, WOTS_PK);
	
	// 14: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	
	// 15: 𝑝𝑘𝑠𝑖𝑔 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝)
//#ifdef _GETTIME
//
//	tacts = __rdtsc() - tacts;
//	//printf("wots_pkFromSig time = %I64d\n", tacts);
//	if (tacts < wots_pkFromSigTime)
//		wots_pkFromSigTime = tacts;
//#endif


#ifdef SHAKE
	Tl_with_predcalc_OLD(pksig, PK_seed, local_adr, tmp, LEN);
#else
	Tl_with_predcalc_OLD(pksig, PK_seed, PK_seed_n, local_adr, tmp, FIPS205_LEN);
#endif
#endif

}


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

	uint8_t* adr)
{
	// 1: 𝑐𝑠𝑢𝑚 ← 0
//#ifdef _GETTIME
//	uint64_t tacts;
//	tacts = __rdtsc();
//
//#endif
	//uint32_t csum = 0;
	uint32_t msg[FIPS205_LEN];
	//const uint8_t* psig = sig;
	// 2: 𝑚𝑠𝑔 ← base_2b(𝑀,𝑙𝑔𝑤,𝑙𝑒𝑛1) ▷ convert message to base 𝑤
	base_2b_(msg, Msg, /*LOGW, */FIPS205_LEN);
	
#if 0
	uint8_t tmp[FIPS205_LEN][FIPS205_N];
#endif
	int i;
	//omp_set_num_threads(8);

#pragma omp parallel for
	for (i = 0; i < FIPS205_LEN; ++i)
	{
#ifdef SHAKE
		uint8_t local_adr[32];
		memcpy(local_adr, adr, 32);
		SetAddress4(local_adr, ChainAddressOFFSET, i);
#else
		uint8_t local_adr[22];
		memcpy(local_adr, adr, 22);
		ShortSetAddress4_OLD(local_adr, ShortChainAddressOFFSET_OLD, i);
#endif

		// 9: ADRS.setChainAddress(𝑖)
		//setChainAddress(adr, (uint32_t)i);
		
		chain_with_predcalc_OLD(tmp[i], msg[i], FIPS205_W - 1 - msg[i], PK_seed, local_adr, sig + i * FIPS205_N);

		
	}

	// 12: wotspkADRS ← ADRS ▷ copy address to create WOTS+ public key address
#if 0
#ifdef SHAKE
	uint32_t value;
	uint8_t local_adr[32];
	memcpy(local_adr, adr, 32);
	SetAddress4_OLD(local_adr, TypeAndClearOFFSET, WOTS_PK);
	memset(local_adr + 24, 0, 8);
	// //setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adr));
	GetAddress4_OLD((uint8_t*)adr, KeyPairAddressOFFSET, value);
	SetAddress4_OLD(local_adr, KeyPairAddressOFFSET, value);

#else
	uint8_t local_adr[22];
	memcpy(local_adr, adr, 22);
	ShortSetAddressType1_OLD(local_adr, WOTS_PK);
	//ShortGetAddress4(adr, ShortKeyPairAddressOFFSET, value);
	//ShortSetAddress4(local_adr, ShortKeyPairAddressOFFSET, value);
	ShortSetFromGet4_OLD(local_adr, adr, ShortKeyPairAddressOFFSET_OLD);
#endif
//#ifdef _GETTIME
//
//	tacts = __rdtsc() - tacts;
//	//printf("wots_pkFromSig time = %I64d\n", tacts);
//	if (tacts < wots_pkFromSigTime)
//		wots_pkFromSigTime = tacts;
//#endif



#ifdef SHAKE
	Tl_with_predcalc_OLD(pksig, PK_seed, local_adr, tmp, LEN);
#else
	Tl_with_predcalc_OLD(pksig, PK_seed, PK_seed_n, local_adr, tmp, FIPS205_LEN);
#endif
#endif

}

//void wots_pkFromSig_ (
// wots_pkFromSig_Full
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

	uint8_t* adr)
{
	// 1: 𝑐𝑠𝑢𝑚 ← 0
//#ifdef _GETTIME
//	uint64_t tacts;
//	tacts = __rdtsc();
//
//#endif
	//uint32_t csum = 0;
	uint32_t msg[FIPS205_LEN];
	//const uint8_t* psig = sig;
	// 2: 𝑚𝑠𝑔 ← base_2b(𝑀,𝑙𝑔𝑤,𝑙𝑒𝑛1) ▷ convert message to base 𝑤
	base_2b_(msg, Msg, /*LOGW, */FIPS205_LEN);

#if 1
	uint8_t tmp[FIPS205_LEN][FIPS205_N];
#endif
	int i;
	//omp_set_num_threads(8);

#pragma omp parallel for
	for (i = 0; i < FIPS205_LEN; ++i)
	{
#ifdef SHAKE
		uint8_t local_adr[32];
		memcpy(local_adr, adr, 32);
		SetAddress4(local_adr, ChainAddressOFFSET, i);
#else
		uint8_t local_adr[22];
		memcpy(local_adr, adr, 22);
		ShortSetAddress4_OLD(local_adr, ShortChainAddressOFFSET_OLD, i);
#endif

		// 9: ADRS.setChainAddress(𝑖)
		//setChainAddress(adr, (uint32_t)i);

		chain_with_predcalc_OLD(tmp[i], msg[i], FIPS205_W - 1 - msg[i], PK_seed, local_adr, sig + i * FIPS205_N);


	}

	// 12: wotspkADRS ← ADRS ▷ copy address to create WOTS+ public key address
#if 1
#ifdef SHAKE
	uint32_t value;
	uint8_t local_adr[32];
	memcpy(local_adr, adr, 32);
	SetAddress4_OLD(local_adr, TypeAndClearOFFSET, WOTS_PK);
	memset(local_adr + 24, 0, 8);
	// //setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adr));
	GetAddress4_OLD((uint8_t*)adr, KeyPairAddressOFFSET, value);
	SetAddress4_OLD(local_adr, KeyPairAddressOFFSET, value);

#else
	uint8_t local_adr[22];
	memcpy(local_adr, adr, 22);
	ShortSetAddressType1_OLD(local_adr, WOTS_PK);
	//ShortGetAddress4(adr, ShortKeyPairAddressOFFSET, value);
	//ShortSetAddress4(local_adr, ShortKeyPairAddressOFFSET, value);
	ShortSetFromGet4_OLD(local_adr, adr, ShortKeyPairAddressOFFSET_OLD);
#endif
	//#ifdef _GETTIME
	//
	//	tacts = __rdtsc() - tacts;
	//	//printf("wots_pkFromSig time = %I64d\n", tacts);
	//	if (tacts < wots_pkFromSigTime)
	//		wots_pkFromSigTime = tacts;
	//#endif



#ifdef SHAKE
	Tl_with_predcalc_OLD(pksig, PK_seed, local_adr, tmp, LEN);
#else
	Tl_with_predcalc_OLD(pksig, PK_seed, PK_seed_n, local_adr, tmp, FIPS205_LEN);
#endif
#endif

}




////Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS)
////Generates a WOTS + public key.
//void wots_pkGen(uint8_t* pk, const uint8_t* SK_seed, const uint8_t* PK_seed, PADR_OLD adr)
//{
//	size_t i;
////#ifdef _GETTIME
////	uint64_t tacts;
////	tacts = __rdtsc();
////	
////#endif
//	//1: skADRS ← ADRS ▷ copy address to create key generation key address
//	ADR_OLD skADRS, wotspkADRS;
//	uint8_t sk[FIPS205_N], tmp[FIPS205_LEN][FIPS205_N];
//	memcpy(&skADRS, adr, sizeof(ADR_OLD));
//	//2: skADRS.setTypeAndClear(WOTS_PRF)
//	setTypeAndClear_OLD(&skADRS, WOTS_PRF);
//	//3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
//	setKeyPairAddress_OLD(&skADRS, getKeyPairAddress_OLD(adr));
//	//4: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
//
//
//	for (i = 0; i < FIPS205_LEN; ++i)
//	{
//		//5: skADRS.setChainAddress(𝑖)
//		setChainAddress_OLD(&skADRS, (uint32_t)i);
//		//6 : 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute secret value for chain 𝑖
////#ifndef _PREDCALC 
//
//		PRF_OLD(sk, PK_seed, (uint8_t*)&skADRS, SK_seed);
//		/*for (int j = 0; j < N; ++j)
//			fprintf(file, "%2.2x ", sk[j]);
//		fprintf(file, "\n");*/
//
//	//7 : ADRS.setChainAddress(𝑖)
//		setChainAddress_OLD(adr, (uint32_t)i);
//		//8 : 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑘, 0, 𝑤 − 1, PK.seed, ADRS)▷ compute public value for chain 𝑖
//		chain_OLD(tmp[i], sk, 0, FIPS205_W - 1, PK_seed, adr);
//		//9 : end for
//	}
//	
//
//	// 10: wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
//	memcpy(&wotspkADRS, adr, sizeof(ADR_OLD));
//	//11: wotspkADRS.setTypeAndClear(WOTS_PK)
//	setTypeAndClear_OLD(&wotspkADRS, WOTS_PK);
//	//12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
//	setKeyPairAddress_OLD(&wotspkADRS, getKeyPairAddress_OLD(adr));
//	//13: 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝) ▷ compress public key
////#ifdef _GETTIME
////
////	tacts = __rdtsc() - tacts;
////	//printf("wots_pkFromSig time = %I64d\n", tacts);
////	if (tacts < wots_pkFromSigTime)
////		wots_pkFromSigTime = tacts;
////#endif
//
//
//
//	Tl(pk, PK_seed, (uint8_t*)&wotspkADRS, tmp, FIPS205_LEN);
//
//
//}

/*
void wots_pkGen_(
	uint8_t* pk,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const uint32_t* PK_seed,
	const uint64_t* PK_seed_n,
#endif
	uint8_t *adr);
*/

//void wots_pkGen_(
//	uint8_t *pk, 
//	//uint8_*pk, 
//	const uint8_t* SK_seed, 
//#ifdef SHAKE
//	const uint8_t* PK_seed,
//#else
//	const void* PK_seed,
//	const void* PK_seed_n,
//#endif
//	uint8_t* adr)
//{
//	
////#ifdef _GETTIME
////	uint64_t tacts;
////	tacts = __rdtsc();
////
////#endif
//	//1: skADRS ← ADRS ▷ copy address to create key generation key address
//	
//	uint8_t /*sk[N],*/ tmp[FIPS205_LEN][FIPS205_N], sk [FIPS205_LEN][FIPS205_N];
//	
//
//	int i;
//#pragma omp parallel
//	{
//#pragma omp for
//		for (i = 0; i < FIPS205_LEN; ++i)
//		{
//			//uint8_t sk[N];
//#ifdef SHAKE	
//			uint8_t TADRS_l[32];
//			memcpy(TADRS_l, adr, 32);
//			SetAddressType4_0(TADRS_l, WOTS_PRF);
//			//3: TADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
//			SetFromGet4(TADRS_l, adr, KeyPairAddressOFFSET);
//
//
//			//5: TADRS.setChainAddress(𝑖)
//			//setChainAddress(&TADRS, (uint32_t)i);
//
//			SetAddress4(TADRS_l, ChainAddressOFFSET, i);
//			//PRF_with_predcalc(sk, PK_seed, TADRS_l, SK_seed);
//
//			//SetAddress4(adr_l, ChainAddressOFFSET, i);
//
//#else
//			uint8_t TADRS_l[22];
//			//uint8_t adr_l[22];
//			memcpy(TADRS_l, adr, 22);
//			//memcpy(adr_l, adr, 22);
//			ShortSetAddressType1_OLD(TADRS_l, WOTS_PRF);
//			ShortSetFromGet4_OLD(TADRS_l, adr, ShortKeyPairAddressOFFSET_OLD);
//
//			//5: TADRS.setChainAddress(𝑖)
//			//setChainAddress(&TADRS, (uint32_t)i);
//			ShortSetAddress4_OLD(TADRS_l, ShortChainAddressOFFSET_OLD, i);
//			//PRF_with_predcalc(sk, PK_seed, TADRS_l, SK_seed);
//			//ShortSetAddress4(adr_l, ShortChainAddressOFFSET, i);
//
//#endif
//#ifdef SHAKE
//			//SetAddress4(TADRS_l, ChainAddressOFFSET, i);
//
//			PRF_with_predcalc(sk[i], PK_seed, TADRS_l, SK_seed);
//			//SetAddress4(adr_l, ChainAddressOFFSET, i);
//			//chain_with_predcalc(tmp[i], 0, W - 1, PK_seed, adr_l, sk);
//#else
//			//ShortSetAddress4(TADRS_l, ShortChainAddressOFFSET, i);
//			PRF_with_predcalc_OLD(sk [i], PK_seed, TADRS_l, SK_seed);
//			//ShortSetAddress4(adr_l, ShortChainAddressOFFSET, i);
//			//chain_with_predcalc(tmp[i], 0, W - 1, PK_seed, adr_l, sk);
//#endif
//		}
//		uint8_t tmp[FIPS205_LEN][FIPS205_N];
//#pragma omp for
//		for (i = 0; i < FIPS205_LEN; ++i)
//		{
//#ifdef SHAKE
//			uint8_t TADRS_l[32];
//#else
//			uint8_t TADRS_l[22];
//#endif
//			memcpy(TADRS_l, adr, sizeof (TADRS_l));
//#ifdef SHAKE
//			SetAddress4(TADRS_l, ChainAddressOFFSET, i);
//#else
//			ShortSetAddress4_OLD(TADRS_l, ShortChainAddressOFFSET_OLD, i);
//#endif
//			//chain_with_predcalc_OLD(tmp[i], 0, FIPS205_W - 1, PK_seed, TADRS_l, sk[i]);
//			chain_with_predcalc_OLD(tmp[i], 0, FIPS205_W - 1, PK_seed, TADRS_l, sk[i]);
//		}
//	}
//
//
//
//
//		
////		//6 : 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute secret value for chain 𝑖
////#ifndef _PREDCALC 
////		PRF(sk, PK_seed, (uint8_t*)&skADRS, SK_seed);
////		//#ifdef _DEBUG
////#else
////
////
////#ifdef SHAKE
////		PRF_with_predcalc(sk, PK_seed, (uint8_t*)&skADRS, SK_seed);
////#else
////
////		toShort((PADR_C)short_addr, &skADRS);
////		PRF_with_predcalc(sk, predcalc_pk_256, short_addr, SK_seed);
////#endif
////		/*if (memcmp(sk, temp, N))
////			printf("WOTS PRF_with_predcalc line = %d\n", __LINE__);*/
////#endif
////			//7 : ADRS.setChainAddress(𝑖)
////		setChainAddress(adr, (uint32_t)i);
////		//8 : 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑘, 0, 𝑤 − 1, PK.seed, ADRS)▷ compute public value for chain 𝑖
////		chain(tmp[i], sk, 0, W - 1, PK_seed, adr);
////		//9 : end for
//	
//
//	/*FILE* file = fopen("pk_.txt", "wt");
//	for (i = 0; i < LEN; ++i)
//	{
//		for (int j = 0; j < N; ++j)
//			fprintf(file, "%2.2x ", sk[i][j]);
//		fprintf(file, "\n");
//	}
//	for (i = 0; i < LEN; ++i)
//	{
//		for (int j = 0; j < N; ++j)
//			fprintf(file,"%2.2x ", tmp[i][j]);
//		fprintf(file, "\n");
//	}
//	fclose(file);*/
//#ifdef SHAKE
//	uint8_t wotspkADRS[32];
//	// 10: wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
//	memcpy(wotspkADRS, adr, 32);
//	//11: wotspkADRS.setTypeAndClear(WOTS_PK)
//	//setTypeAndClear(&wotspkADRS, WOTS_PK);
//	SetAddressType4_0_OLD(wotspkADRS, WOTS_PK);
//	//12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
//	//setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adr));
//	SetFromGet4_OLD(wotspkADRS, adr, KeyPairAddressOFFSET_OLD);
//	//13: 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝) ▷ compress public key
//	Tl_with_predcalc(pk, PK_seed, wotspkADRS, tmp, LEN);
//	
//#else
//	uint8_t wotspkADRS[22];
//	// 10: wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
//	memcpy(wotspkADRS, adr, 22);
//	//11: wotspkADRS.setTypeAndClear(WOTS_PK)
//	//setTypeAndClear(&wotspkADRS, WOTS_PK);
//	ShortSetAddressType1_OLD(wotspkADRS, WOTS_PK);
//	//12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
//	//setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adr));
//	ShortSetFromGet4_OLD(wotspkADRS, adr, ShortKeyPairAddressOFFSET_OLD);
//	//13: 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝) ▷ compress public key
////#ifdef _GETTIME
////
////	tacts = __rdtsc() - tacts;
////	//printf("wots_pkFromSig time = %I64d\n", tacts);
////	if (tacts < wots_pkFromSigTime)
////		wots_pkFromSigTime = tacts;
////#endif
//
//	Tl_with_predcalc_OLD(pk, PK_seed, PK_seed_n, wotspkADRS, tmp, FIPS205_LEN);
//
//#endif
////#ifdef _GETTIME
////
////	tacts = __rdtsc() - tacts;
////	//printf("wots_pkGen time = %I64d\n", tacts);
////	if (tacts < wots_pkGenTime)
////		wots_pkGenTime = tacts;
////#endif
//}


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
{

	uint8_t /*sk[N],*/ sk[FIPS205_LEN][FIPS205_N];


	int i;

	//omp_set_num_threads(2);
#pragma omp parallel
	{

//#pragma omp critical
//		printf("Thread %d", omp_get_thread_num());
//		printf(" of %d \n", omp_get_num_threads());
#pragma omp for nowait
		for (i = 0; i < FIPS205_LEN; ++i)
		{
#ifdef SHAKE
			uint8_t TADRS_l[32];
			memcpy(TADRS_l, adr, 32);
			SetAddressType4_0(TADRS_l, WOTS_PRF);
			SetFromGet4(TADRS_l, adr, KeyPairAddressOFFSET);

			SetAddress4(TADRS_l, ChainAddressOFFSET, i);
#else
			uint8_t TADRS_l[22];
			memcpy(TADRS_l, adr, 22);
			ShortSetAddressType1_OLD(TADRS_l, WOTS_PRF);
			ShortSetFromGet4_OLD(TADRS_l, adr, ShortKeyPairAddressOFFSET_OLD);

			ShortSetAddress4_OLD(TADRS_l, ShortChainAddressOFFSET_OLD, i);
#endif
#ifdef SHAKE
			PRF_with_predcalc(sk[i], PK_seed, TADRS_l, SK_seed);
#else
			PRF_with_predcalc_OLD(sk[i], PK_seed, TADRS_l, SK_seed);
#endif
		}
#pragma omp for nowait
		for (i = 0; i < FIPS205_LEN; ++i)
		{
#ifdef SHAKE
			uint8_t TADRS_l[32];
#else
			uint8_t TADRS_l[22];
#endif
			memcpy(TADRS_l, adr, sizeof(TADRS_l));
#ifdef SHAKE
			SetAddress4(TADRS_l, ChainAddressOFFSET, i);
#else
			ShortSetAddress4_OLD(TADRS_l, ShortChainAddressOFFSET_OLD, i);
#endif
			chain_with_predcalc_OLD(pk[i], 0, FIPS205_W - 1, PK_seed, TADRS_l, sk[i]);
		}
	}

#if 0


#ifdef SHAKE
	uint8_t wotspkADRS[32];
	memcpy(wotspkADRS, adr, 32);
	SetAddressType4_0_OLD(wotspkADRS, WOTS_PK);
	SetFromGet4_OLD(wotspkADRS, adr, KeyPairAddressOFFSET_OLD);
	Tl_with_predcalc(pk, PK_seed, wotspkADRS, tmp, LEN);

#else
	uint8_t wotspkADRS[22];
	memcpy(wotspkADRS, adr, 22);
	ShortSetAddressType1_OLD(wotspkADRS, WOTS_PK);
	ShortSetFromGet4_OLD(wotspkADRS, adr, ShortKeyPairAddressOFFSET_OLD);
#endif

#endif
}


void wots_pkGenFull__(
	uint8_t *pk,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr)
{
	uint8_t tmp[FIPS205_LEN][FIPS205_N];
	wots_pkGen__(
		tmp,
		SK_seed,
#ifdef SHAKE
		PK_seed,
#else
		PK_seed,
		PK_seed_n,
#endif
		adr);
	

#if 1

#ifdef SHAKE
	uint8_t wotspkADRS[32];
	// 10: wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
	memcpy(wotspkADRS, adr, 32);
	//11: wotspkADRS.setTypeAndClear(WOTS_PK)
	//setTypeAndClear(&wotspkADRS, WOTS_PK);
	SetAddressType4_0_OLD(wotspkADRS, WOTS_PK);
	//12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	//setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adr));
	SetFromGet4_OLD(wotspkADRS, adr, KeyPairAddressOFFSET_OLD);
	//13: 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝) ▷ compress public key
	Tl_with_predcalc(pk, PK_seed, wotspkADRS, tmp, LEN);

#else
	uint8_t wotspkADRS[22];
	// 10: wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
	memcpy(wotspkADRS, adr, 22);
	//11: wotspkADRS.setTypeAndClear(WOTS_PK)
	//setTypeAndClear(&wotspkADRS, WOTS_PK);
	ShortSetAddressType1_OLD(wotspkADRS, WOTS_PK);
	//12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	//setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adr));
	ShortSetFromGet4_OLD(wotspkADRS, adr, ShortKeyPairAddressOFFSET_OLD);
	//13: 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝) ▷ compress public key
//#ifdef _GETTIME
//
//	tacts = __rdtsc() - tacts;
//	//printf("wots_pkFromSig time = %I64d\n", tacts);
//	if (tacts < wots_pkFromSigTime)
//		wots_pkFromSigTime = tacts;
//#endif

	Tl_with_predcalc_OLD(pk, PK_seed, PK_seed_n, wotspkADRS, tmp, FIPS205_LEN);

#endif
//#ifdef _GETTIME
//
//	tacts = __rdtsc() - tacts;
//	//printf("wots_pkGen time = %I64d\n", tacts);
//	if (tacts < wots_pkGenTime)
//		wots_pkGenTime = tacts;
//#endif
#endif
}


//int test_wots()
//{
//	/*void wots_sign_(
//		uint8_t * WOTS_SIG,
//		const uint8_t * Msg,
//		const uint8_t * SK_seed,
//		const uint8_t * PK_seed,
//		PADR adr)*/
//	uint8_t WOTS_SIG1[N * LEN], WOTS_SIG2[N * LEN];
//	uint8_t SK_seed[N], PK_seed_[N], Msg[N];
//	uint8_t adr[32] = { 0 };
//#ifndef SHAKE
//	uint8_t adr_c[22];
//#endif
//#ifndef _DEBUG
//	uint64_t tacts, tacts1_min = 0xFFFFFFFFFFFFFFFF, tacts2_min = 0xFFFFFFFFFFFFFFFF;
//#endif
//	int i;
//	srand(0);
//	for (i = 0; i < N; ++i)
//	{
//		SK_seed[i] = rand() % 256;
//		PK_seed_[i] = rand() % 256;
//		Msg[i] = rand() % 256;
//	}
//	/*for (i = 0; i < 24; ++i)
//		adr[i] = rand () %256;*/
//#ifdef SHAKE
//	uint8_t* PK_seed = PK_seed_;
//#else
//	uint32_t PK_seed[8];
//#if N == 16
//	uint32_t PK_seed_n[8];
//#else
//	uint64_t PK_seed_n[8];
//#endif
//	predcalcs_pk(PK_seed, PK_seed_n, PK_seed_);
//#endif
//
//#ifndef SHAKE
//	toShort((PADR_C)adr_c, (PADR)adr);
//	/*uint32_t predcalc_pk_256[8];
//	predcalc_pk_sha256(predcalc_pk_256, PK_seed);
//#if N == 16
//	uint32_t* predcalc_pk_n = predcalc_pk_256;
//#else
//	uint64_t predcalc_pk_n[8];
//
//#if N == 24
//	predcalc_pk_sha384(predcalc_pk_n, PK_seed);
//#else
//	predcalc_pk_sha512(predcalc_pk, PK_seed);
//#endif
//#endif*/
//#endif
//
//
//	uint8_t local_adr[32];
//#ifndef SHAKE
//	uint8_t local_adr_c[22];
//#endif
//
//#ifndef _DEBUG
//
//	for (i = 0; i < 16; ++i)
//	{
//#endif
//		memcpy(local_adr, adr, 32);
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//
//		wots_sign(
//			WOTS_SIG1,
//			Msg,
//			SK_seed,
//			PK_seed_,
//			(PADR)local_adr);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < tacts1_min)
//			tacts1_min = tacts;
//	}
//	printf("wots_sign time = %I64d\n", tacts1_min);
//#endif
//
//
//#ifndef _DEBUG
//
//	for (i = 0; i < 16; ++i)
//	{
//#endif
//
//#ifdef SHAKE
//		memcpy(local_adr, adr, 32);
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//		wots_sign_(
//			WOTS_SIG2,
//			Msg,
//			SK_seed,
//			PK_seed_,
//			local_adr);
//#else
//		memcpy(local_adr_c, adr_c, 22);
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//		wots_sign_(
//			WOTS_SIG2,
//			Msg,
//			SK_seed,
//			PK_seed,
//			PK_seed_n,
//			local_adr_c);
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < tacts2_min)
//			tacts2_min = tacts;
//	}
//	printf("wots_sign_ time = %I64d\n", tacts2_min);
//#endif
//	int res = 0;
//	for (i = 0; i < N * LEN; ++i)
//	{
//		if (WOTS_SIG1[i] != WOTS_SIG2[i])
//			res = 1;
//	}
//	printf("wots_sign and wots_sign_ %s\n", res == 0 ? "OK" : "ERROR");
//	uint8_t pksig1[N], pksig2[N];
//#ifndef _DEBUG
//	uint64_t tacts_min = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//	{
//#endif
//		memcpy(local_adr, adr, 32);
//#ifndef _DEBUG 
//		tacts = __rdtsc();
//#endif
//
//		wots_pkFromSig(
//			pksig1,
//			WOTS_SIG1,
//			Msg,
//			PK_seed_,
//			(PADR)local_adr);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < tacts_min)
//			tacts_min = tacts;
//	}
//	printf("wots_pkFromSig time = %I64d\n", tacts_min);
//#endif
//
//
//#ifndef _DEBUG
//	tacts_min = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//	{
//#endif
//#ifdef SHAKE
//		memcpy(local_adr, adr, 32);
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//		wots_pkFromSig_(
//			pksig2,
//			WOTS_SIG1,
//			Msg,
//			PK_seed_,
//			local_adr);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < tacts_min)
//			tacts_min = tacts;
//		//printf("wots_pkFromSig_ i = %d %s\n", i, memcmp(pksig1, pksig2, N) == 0 ? "YES" : "NO");
//#endif
//
//
//#else
//
//		memcpy(local_adr_c, adr_c, 22);
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//		wots_pkFromSig_(
//			pksig2,
//			WOTS_SIG1,
//			Msg,
//			PK_seed,
//			PK_seed_n,
//			local_adr_c);
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < tacts_min)
//			tacts_min = tacts;
//
//#endif
//
//#ifndef _DEBUG
//	}
//	printf("wots_pkFromSig_ tacts = %I64d\n", tacts_min);
//#endif
//
//	res = 0;
//	for (i = 0; i < N; ++i)
//	{
//		if (pksig1[i] != pksig2[i])
//			res = 1;
//	}
//	printf("wots_pkFromSig and wots_pkFromSig_ %s\n", res == 0 ? "OK" : "ERROR");
//
//#ifdef SHAKE
//	memcpy(local_adr, adr, 32);
//#else
//	memcpy(local_adr_c, adr_c, 22);
//#endif
//
//	uint8_t pk1[N], pk2[N];
//
//#ifndef _DEBUG
//	tacts_min = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		wots_pkGen(
//			pk1,
//			SK_seed,
//			PK_seed_,
//			(PADR)local_adr);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < tacts_min)
//			tacts_min = tacts;
//	}
//	printf("wots_pkGen time = %I64d\n", tacts_min);
//#endif
//
//#ifdef SHAKE
//	memcpy(local_adr, adr, 32);
//#else
//	memcpy(local_adr_c, adr_c, 22);
//#endif
//#ifndef _DEBUG
//	tacts_min = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//	{
//
//		tacts = __rdtsc();
//#endif
//		wots_pkGen_(
//			pk2,
//			SK_seed,
//#ifdef SHAKE
//			PK_seed_,
//			local_adr
//#else
//			PK_seed,
//			PK_seed_n,
//			local_adr_c
//#endif
//		
//
//
//			);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < tacts_min)
//			tacts_min = tacts;
//	}
//
//	printf("wots_pkGen_ time = %I64d\n", tacts_min);
//#endif
//	res = 0;
//	for (i = 0; i < N; ++i)
//	{
//		if (pk1[i] != pk2[i])
//			res = 1;
//	}
//	printf("wots_pkGen and wots_pkGen_ %s\n", res == 0? "OK" : "ERROR");
//	return res;
//}