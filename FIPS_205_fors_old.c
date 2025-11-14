
#include <stdlib.h>
#include <omp.h>
#ifdef _DEBUG
#include <stdio.h>
#endif
#include "FIPS_205_Adr_old.h"
#include "FIPS_205_Fors_old.h"





void fors_skGen__OLD(uint8_t* pFORS, const uint8_t* SK_seed, const void* PK_seed_,
	uint8_t *adr, uint32_t ind)
{
	
	
// 1: skADRS ← ADRS ▷ copy address to create key generation address

// 2: skADRS.setTypeAndClear(FORS_PRF)

// 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

	
#ifdef SHAKE
	uint32_t pa;
	uint8_t skADRS[32];
	memcpy(skADRS, adr, 16);
	memset(skADRS + 16, 0, 16);
	SetAddress4(skADRS, TypeAndClearOFFSET, FORS_PRF);
	GetAddress4(adr, KeyPairAddressOFFSET, pa);
	SetAddress4(skADRS, KeyPairAddressOFFSET, pa);
	SetAddress4(skADRS, TreeIndexOFFSET, ind);
#else 
	uint8_t skADRS[22];
	memcpy(skADRS, adr, 10);
	memset(skADRS + 10, 0, 12);
	ShortSetAddressType1_OLD(skADRS, FORS_PRF_OLD);
	//ShortGetAddress4(adr, ShortKeyPairAddressOFFSET, pa);
	//ShortSetAddress4(skADRS, ShortKeyPairAddressOFFSET, pa);
	ShortSetFromGet4_OLD(skADRS, adr, ShortKeyPairAddressOFFSET_OLD);
	ShortSetAddress4_OLD(skADRS, ShortTreeIndexOFFSET_OLD, ind);

#endif

	
//#ifdef _PREDCALC
#ifdef SHAKE
	//uint8_t* PK_seed = (uint8_t*)PK_seed_;
	PRF_with_predcalc(pFORS, (uint8_t*)PK_seed_, skADRS, SK_seed);
#else
	//uint8_t short_adr[22];
	//toShort((PADR_C)short_adr, &skADRS);
	// void PRF_with_predcalc(uint8_t* dest, void*pk, uint8_t* adr_short, uint8_t* SK_seed);
	//uint32_t* PK_seed = (uint32_t*)PK_seed_;
	PRF_with_predcalc_OLD(pFORS, (uint32_t*)PK_seed_, skADRS, SK_seed);
#endif

//#ifdef _GETTIME
//	tacts = __rdtsc() - tacts;
//	//printf("fors_skGen time = %I64d\n", tacts);
//	if (tacts < fors_skGenTime)
//		fors_skGenTime = tacts;
//#endif

}

/*
Algorithm 15
fors_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
Computes the root of a Merkle subtree of FORS public values.
Input:
	Secret seed SK.seed,
	target node index 𝑖,
	target node height 𝑧,
	public seed PK.seed,
	address ADRS.
Output:
	𝑛-byte root 𝑛𝑜𝑑𝑒.
*/

void fors_node__OLD(uint8_t* pFORS, const uint8_t* SK_seed, uint32_t i, uint32_t z,
	const void* PK_seed_, 
#ifndef SHAKE
	const void *PK_seed_n,
#endif
	uint8_t* adr)
{
	uint8_t sk[FIPS205_N], lnode[2][FIPS205_N];

	// 1: if 𝑧 = 0 then
	if (z == 0)
	{
		// 2: 𝑠𝑘 ← fors_skGen(SK.seed,PK.seed,ADRS, 𝑖) 
		fors_skGen__OLD(sk, SK_seed, PK_seed_, adr, i);
		// 3: ADRS.setTreeHeight(0)
		//setTreeHeight(adr, 0);
#ifdef SHAKE
		SetAddress4_0(adr, TreeHeightOFFSET);
		// 4: ADRS.setTreeIndex(𝑖)
		//setTreeIndex(adr, (uint32_t)i);
		SetAddress4(adr, TreeIndexOFFSET, i);
#else
		ShortSetAddress4_0_OLD(adr, ShortTreeHeightOFFSET_OLD);
		ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, i);

#endif // SHAKE

		

		// 5: 𝑛𝑜𝑑𝑒 ← F(PK.seed,ADRS, 𝑠𝑘)

#ifdef SHAKE
		//uint8_t* PK_seed = (uint8_t*)PK_seed_;
		F_with_predcalc(pFORS, (uint8_t*)PK_seed_, adr, sk);
#else
		//uint32_t* PK_seed = (uint32_t*)PK_seed_;
		F_with_predcalc_OLD(pFORS, (uint32_t*)PK_seed_, adr, sk);
#endif
		
	}
	else
	{
		// 7: 𝑙𝑛𝑜𝑑𝑒 ← fors_node(SK.seed, 2𝑖, 𝑧 − 1,PK.seed,ADRS)
#ifdef SHAKE
		fors_node_(lnode[0], SK_seed, 2 * i, z - 1, PK_seed_, adr);
		fors_node_(lnode[1], SK_seed, 2 * i + 1, z - 1, PK_seed_, adr);
#else
		fors_node__OLD(lnode[0], SK_seed, 2 * i, z - 1, PK_seed_, PK_seed_n, adr);
		fors_node__OLD(lnode[1], SK_seed, 2 * i + 1, z - 1, PK_seed_, PK_seed_n, adr);
#endif
		// 8: 𝑟𝑛𝑜𝑑𝑒 ← fors_node(SK.seed,2𝑖+1,𝑧 −1,PK.seed,ADRS)
		
		// 9: ADRS.setTreeHeight(𝑧)
		//setTreeHeight(adr, (uint32_t)z);
		// 10: ADRS.setTreeIndex(𝑖)
#ifdef SHAKE

		SetAddress4(adr, TreeHeightOFFSET, z);
		SetAddress4(adr, TreeIndexOFFSET, i);
#else
		ShortSetAddress4_OLD(adr, ShortTreeHeightOFFSET_OLD, z);
		ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, i);
#endif
				
		// 11: 𝑛𝑜𝑑𝑒 ← H(PK.seed,ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)

#ifdef SHAKE
		HASH_with_predcalc(pFORS, PK_seed_, (uint8_t*)adr, lnode);
#else
		
//#if FIPS205_N == 16
		HASH_with_predcalc_OLD(pFORS, PK_seed_n, adr, lnode);
//#endif
//#if FIPS205_N == 24
//		HASH_with_predcalc(pFORS, PK_seed_n, adr, lnode);
//#endif
//#if FIPS205_N == 32
//		HASH_with_predcalc(pFORS, , PK_seed_n, lnode);
//#endif
#endif
	}
}



uint8_t* fors_sign__OLD(
	uint8_t* FORS, 
	const uint8_t* md, 
	const uint8_t* SK_seed, 
	const void* PK_seed,
#ifndef SHAKE
	const void* PK_seed_n, 
#endif
	uint8_t* adr)
{
	// Algorithm 16 fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
	// Input: 
	//			Message digest 𝑚𝑑, 
	//			secret seed SK.seed, 
	//			address ADRS, 
	//			public seed PK.seed. 
	// Output: 
	// FORS - SIGfors - .
	// 1: SIG𝐹 𝑂𝑅𝑆 = NULL ▷ initialize SIG𝐹 𝑂𝑅𝑆 as a zero-length byte string
	// 2: 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)

	
	uint32_t indices[FIPS205_K];
	base_2b(indices, md, FIPS205_A, FIPS205_K);
	// 3: for 𝑖 from 0 to 𝑘 − 1 do ▷ compute signature elements
	uint32_t i, j; 
	uint8_t *pFORS = FORS;
	uint8_t* pAuth = FORS + FIPS205_N * FIPS205_K;

	/*char fn[FIPS205_A][256];
	FILE* file;*/
	/*for (j = 0; j < FIPS205_A; ++j)
	{
		sprintf(fn[j], "fors_sign_%d.txt", j);
		file = fopen(fn[j], "wt");
		fclose(file);
	}*/
	for (i = 0; i < FIPS205_K; ++i)
	{
#ifdef SHAKE 
		uint8_t l_adr[32];
#else
		uint8_t l_adr[22];
#endif
		memcpy(l_adr, adr, sizeof(l_adr));
		
		uint8_t* pFORS = FORS + i * FIPS205_N * (1 + FIPS205_A);
		//uint8_t* pFORS = FORS + i * FIPS205_N ;
		uint8_t* pAuth = pFORS + FIPS205_N;
		uint32_t s;
		//uint64_t intacts = __rdtsc();
		// 4: fors_skGen(SK.seed,PK.seed,ADRS, 𝑖 ⋅ 2𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		fors_skGen__OLD(pFORS, SK_seed, PK_seed, l_adr, i * (1 << FIPS205_A) + indices[i]);
		
		//pFORS += FIPS205_N;
		// 5: for 𝑗 from 0 to 𝑎 − 1 do ▷ compute auth path		
		//uint8_t AUTH[A][FIPS205_N];
		

		for (j = 0; j < FIPS205_A; ++j)
		{
			//file = fopen(fn[j], "at");
			
			// 6: 𝑠 ← ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2𝑗⌋ ⊕ 1
			s = (indices[i] / (1 << j)) ^ 1;
			//fprintf(file, "i = %x s=%x\n", i, s);
			// 7: AUTH[𝑗] ← fors_node(SK.seed, 𝑖 ⋅ 2𝑎−𝑗 + 𝑠, 𝑗,PK.seed,ADRS)
			//fors_node(AUTH [j], SK_seed, i * (1 << (A - j)) + s, j, PK_seed, adr);
#ifdef SHAKE
			fors_node_(pAuth, SK_seed, i * ((uint64_t)1 << (A - j)) + s, j, PK_seed, l_adr);
#else
			/*fprintf(file, "Params");
			fprintf(file, "i + s = %llx\n", i * ((uint64_t)1 << (FIPS205_A - j)) + s);*/
			fors_node__OLD(pAuth, SK_seed, i * ((uint64_t)1 << (FIPS205_A - j)) + s, j, PK_seed, PK_seed_n, l_adr);
			/*fprintf(file, "pAuth\n");
			for (int k = 0; k < FIPS205_N; ++k)
				fprintf(file, "%x ", pAuth[k]);
			fprintf(file, "\n");*/
#endif
			pAuth += FIPS205_N;
			//pFORS += FIPS205_N;
			// 8: end for 9:
			//fclose(file);
		}
		
	}

	return FORS + FIPS205_K * FIPS205_N * (1 + FIPS205_A);
}

uint8_t* fors_sign___OLD(
	uint8_t* FORS,
	const uint8_t* md,
	const uint8_t* SK_seed,
	const void* PK_seed,
#ifndef SHAKE
	const void* PK_seed_n, 
#endif
	uint8_t* adr)
{
	// Algorithm 16 fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
	// Input: 
	//			Message digest 𝑚𝑑, 
	//			secret seed SK.seed, 
	//			address ADRS, 
	//			public seed PK.seed. 
	// Output: 
	// FORS - SIGfors - .
	// 1: SIG𝐹 𝑂𝑅𝑆 = NULL ▷ initialize SIG𝐹 𝑂𝑅𝑆 as a zero-length byte string
	// 2: 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)


	uint32_t indices[FIPS205_K];
	base_2b(indices, md, FIPS205_A, FIPS205_K);
	// 3: for 𝑖 from 0 to 𝑘 − 1 do ▷ compute signature elements
	int32_t i;
	//omp_set_num_threads(8);
#pragma omp parallel for
	for (i = 0; i < FIPS205_K; ++i)
	{
#ifdef SHAKE 
		uint8_t l_adr[32];
#else
		uint8_t l_adr[22];
#endif
		memcpy(l_adr, adr, sizeof(l_adr));

		uint8_t* pFORS = FORS + i *  (1 + FIPS205_A) * FIPS205_N;
		//uint8_t* pFORS = FORS + i * FIPS205_N ;
		uint8_t* pAuth = pFORS + FIPS205_N;
		uint32_t j, s;
		//uint64_t intacts = __rdtsc();
		// 4: fors_skGen(SK.seed,PK.seed,ADRS, 𝑖 ⋅ 2𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		fors_skGen__OLD(pFORS, SK_seed, PK_seed, l_adr, i * (1 << FIPS205_A) + indices[i]);

		//pFORS += FIPS205_N;
		// 5: for 𝑗 from 0 to 𝑎 − 1 do ▷ compute auth path		
		//uint8_t AUTH[A][FIPS205_N];
		for (j = 0; j < FIPS205_A; ++j)
		{
			// 6: 𝑠 ← ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2𝑗⌋ ⊕ 1
			s = (indices[i] / (1 << j)) ^ 1;
			// 7: AUTH[𝑗] ← fors_node(SK.seed, 𝑖 ⋅ 2𝑎−𝑗 + 𝑠, 𝑗,PK.seed,ADRS)
			//fors_node(AUTH [j], SK_seed, i * (1 << (A - j)) + s, j, PK_seed, adr);
#ifdef SHAKE
			fors_node_(pAuth, SK_seed, i * ((uint64_t)1 << (A - j)) + s, j, PK_seed, l_adr);
#else
			fors_node__OLD(pAuth, SK_seed, i * ((uint64_t)1 << (FIPS205_A - j)) + s, j, PK_seed, PK_seed_n, l_adr);
#endif
			pAuth += FIPS205_N;
			//pFORS += FIPS205_N;
			// 8: end for 9:
		}

	}

	return FORS + FIPS205_K * FIPS205_N * (1 + FIPS205_A);
}


//#ifdef _PARALLEL
//
//uint8_t* parallel_fors_sign1(uint8_t* FORS, const uint8_t* md, const uint8_t* SK_seed, const uint8_t* PK_seed, PADR adr)
//{
//	// Algorithm 16 fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
//	// Input: 
//	//			Message digest 𝑚𝑑, 
//	//			secret seed SK.seed, 
//	//			address ADRS, 
//	//			public seed PK.seed. 
//	// Output: 
//	// FORS - SIGfors - .
//	// 1: SIG𝐹 𝑂𝑅𝑆 = NULL ▷ initialize SIG𝐹 𝑂𝑅𝑆 as a zero-length byte string
//	// 2: 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)
////#ifdef _GETTIME
////	uint64_t tacts = __rdtsc();
////#endif
//	uint8_t* pFORS = FORS;
//	uint32_t indices[K];
//	base_2b(indices, md, A, K);
//	// 3: for 𝑖 from 0 to 𝑘 − 1 do ▷ compute signature elements
//	int i;
//#pragma omp parallel for
//	for (i = 0; i < K; ++i)
//	{
//		size_t j, s;
//		ADR local_adr = *adr;
//		uint8_t* local_pFORS = pFORS + i * (A + 1) * FIPS205_N;
//		
//		//uint64_t intacts = __rdtsc();
//		// 4: fors_skGen(SK.seed,PK.seed,ADRS, 𝑖 ⋅ 2𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
//		fors_skGen(local_pFORS, SK_seed, PK_seed, adr, i * (1 << A) + indices[i]);
//		local_pFORS += FIPS205_N;
//		// 5: for 𝑗 from 0 to 𝑎 − 1 do ▷ compute auth path		
//		//uint8_t AUTH[A][FIPS205_N];
//		for (j = 0; j < A; ++j)
//		{
//			// 6: 𝑠 ← ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2𝑗⌋ ⊕ 1
//			s = (indices[i] / (1 << j)) ^ 1;
//			// 7: AUTH[𝑗] ← fors_node(SK.seed, 𝑖 ⋅ 2𝑎−𝑗 + 𝑠, 𝑗,PK.seed,ADRS)
//			//fors_node(AUTH [j], SK_seed, i * (1 << (A - j)) + s, j, PK_seed, adr);
//			fors_node(local_pFORS, SK_seed, i * ((uint64_t)1 << (A - j)) + s, j, PK_seed, &local_adr);
//			local_pFORS += FIPS205_N;
//			// 8: end for 9:
//		}
//		//SIG𝐹 𝑂𝑅𝑆 ← SIG𝐹 𝑂𝑅𝑆 ∥ AUTH
//		// 10: end for
//		//intacts = __rdtsc() - intacts;
//		//printf("***** i = %I64d\t time = %I64d\n", i, intacts);
//	}
//
//	return FORS + K * (1 + A) * FIPS205_N;
//}
//
//uint8_t* parallel_fors_sign1_(uint8_t* FORS, const uint8_t* md, const uint8_t* SK_seed, const uint8_t* PK_seed, uint8_t* adr)
//{
//	// Algorithm 16 fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
//	// Input: 
//	//			Message digest 𝑚𝑑, 
//	//			secret seed SK.seed, 
//	//			address ADRS, 
//	//			public seed PK.seed. 
//	// Output: 
//	// FORS - SIGfors - .
//	// 1: SIG𝐹 𝑂𝑅𝑆 = NULL ▷ initialize SIG𝐹 𝑂𝑅𝑆 as a zero-length byte string
//	// 2: 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)
//
//	uint8_t* pFORS = FORS;
//	uint32_t indices[K];
//	base_2b(indices, md, A, K);
//	// 3: for 𝑖 from 0 to 𝑘 − 1 do ▷ compute signature elements
//	int i;
//#pragma omp parallel for
//	for (i = 0; i < K; ++i)
//	{
//		uint32_t j, s;
//		
//#ifdef SHAKE
//		uint8_t local_adr[32];
//		memcpy(local_adr, adr, 32);
//#else
//		uint8_t local_adr[22];
//		memcpy(local_adr, adr, 22);
//#endif
//		uint8_t* local_pFORS = pFORS + i * (A + 1) * FIPS205_N;
//
//		//uint64_t intacts = __rdtsc();
//		// 4: fors_skGen(SK.seed,PK.seed,ADRS, 𝑖 ⋅ 2𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
//		fors_skGen_(local_pFORS, SK_seed, PK_seed, local_adr, i * (1 << A) + indices[i]);
//		local_pFORS += FIPS205_N;
//		// 5: for 𝑗 from 0 to 𝑎 − 1 do ▷ compute auth path		
//		//uint8_t AUTH[A][FIPS205_N];
//		for (j = 0; j < A; ++j)
//		{
//			// 6: 𝑠 ← ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2𝑗⌋ ⊕ 1
//			s = (indices[i] / (1 << j)) ^ 1;
//			// 7: AUTH[𝑗] ← fors_node(SK.seed, 𝑖 ⋅ 2𝑎−𝑗 + 𝑠, 𝑗,PK.seed,ADRS)
//			//fors_node(AUTH [j], SK_seed, i * (1 << (A - j)) + s, j, PK_seed, adr);
//			fors_node_(local_pFORS, SK_seed, i * ((uint64_t)1 << (A - j)) + s, j, PK_seed, local_adr);
//			local_pFORS += FIPS205_N;
//			// 8: end for 9:
//		}
//		//SIG𝐹 𝑂𝑅𝑆 ← SIG𝐹 𝑂𝑅𝑆 ∥ AUTH
//		// 10: end for
//		//intacts = __rdtsc() - intacts;
//		//printf("***** i = %I64d\t time = %I64d\n", i, intacts);
//	}
//
//	return FORS + K * (1 + A) * FIPS205_N;
//}
//#endif

void fors_pkFromSig__OLD(uint8_t* PK_fors, const uint8_t* SIGfors, const uint8_t* md, 
	const void* PK_seed_, 
#ifndef SHAKE
	const void* PK_seed_n,
#endif
	uint8_t* adr)
{
	// Algorithm 17 fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	// Computes a FORS public key from a FORS signature.
	// Input: 
	//		FORS signature SIG𝐹 𝑂𝑅𝑆, 
	//		message digest 𝑚𝑑, 
	//		public seed PK.seed, 
	//		address ADRS. 
	// Output: 
	//		FORS public key.
	// 1: 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)




	uint32_t indices[FIPS205_K];
	size_t i, j;

	base_2b(indices, md, FIPS205_A, FIPS205_K);
	
	uint8_t sk[FIPS205_N], pnode0[FIPS205_N], pnode1[FIPS205_N];
	// 2: for 𝑖 from 0 to 𝑘 − 1 do
	uint8_t p[2][FIPS205_N];
	uint8_t root[FIPS205_K][FIPS205_N];
	uint8_t auth[FIPS205_N];
#ifdef SHAKE
	uint8_t* PK_seed = (uint8_t*)PK_seed_;
#else
	uint32_t* PK_seed = (uint32_t*)PK_seed_;
#endif

	
	for (i = 0; i < FIPS205_K; ++i)
	{
	/*	if (i == 13)
			printf("");*/
		// 3: 𝑠𝑘 ← SIG𝐹 𝑂𝑅𝑆.getSK(𝑖) ▷ SIG𝐹𝑂𝑅𝑆[𝑖⋅(𝑎+1)⋅𝑛 ∶ (𝑖⋅(𝑎+1)+1)⋅𝑛]
		memcpy(sk, SIGfors + (i * (FIPS205_A + 1) * FIPS205_N), FIPS205_N);
		//memcpy(sk, curSIGfors, FIPS205_N);
		//curSIGfors += (A + 1) * FIPS205_N;
		

		// 4: ADRS.setTreeHeight(0) ▷ compute leaf
#ifdef SHAKE
		//setTreeHeight(adr, 0);
		SetAddress4_0(adr, TreeHeightOFFSET);
		// 5: ADRS.setTreeIndex(𝑖 * 2^𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		//setTreeIndex(adr, (uint32_t)(i * (1 << A) + indices[i]));
		SetAddress4(adr, TreeIndexOFFSET, (uint32_t)(i * (1 << A) + indices[i]));
#else
		ShortSetAddress4_0_OLD(adr, ShortTreeHeightOFFSET_OLD);
		ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, (uint32_t)(i * (1 << FIPS205_A) + indices[i]));
#endif
		
		// 6: 𝑛𝑜𝑑𝑒[0] ← F(PK.seed,ADRS, 𝑠𝑘)


#ifdef SHAKE
		//uint8_t* PK_seed = (uint8_t*)PK_seed_;
		F_with_predcalc(pnode0, PK_seed, (uint8_t*)adr, sk);
#else
		//uint32_t* PK_seed = (uint32_t*)PK_seed_;
		F_with_predcalc_OLD(pnode0, PK_seed, adr, sk);
#endif

		
		
		// 7: 𝑎𝑢𝑡ℎ ← SIG𝐹 𝑂𝑅𝑆.getAUTH(𝑖) ▷ SIG𝐹𝑂𝑅𝑆[(𝑖⋅(𝑎+1)+1)⋅𝑛 ∶ (𝑖+1)⋅(𝑎+1)⋅𝑛]
		const uint8_t* pauth = SIGfors + ((i * (FIPS205_A + 1) + 1) * FIPS205_N);
		//const uint8_t* pauth = curSIGfors + FIPS205_N;

		//memcpy(auth[0], SIGfors + ((i * (A + 1) + 1) * FIPS205_N), FIPS205_N);
		// 8: for 𝑗 from 0 to 𝑎 − 1 do ▷ compute root from leaf and AUTH

		for (j = 0; j < FIPS205_A; ++j)
		{
			memcpy(auth, pauth, FIPS205_N);
		
			pauth += FIPS205_N;
			// 9: ADRS.setTreeHeight(𝑗 + 1)
			//setTreeHeight(adr, (uint32_t)(j + 1));
#ifdef SHAKE
			SetAddress4(adr, TreeHeightOFFSET, (uint32_t)(j + 1));
#else
			ShortSetAddress4_OLD(adr, ShortTreeHeightOFFSET_OLD, (uint32_t)(j + 1));
#endif
		
			// 10: if ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2𝑗⌋ is even then 
			uint32_t ti;

			if (((indices[i] / (1 << j)) & 1) == 0)		// even
			{
				// 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
				//setTreeIndex(adr, getTreeIndex(adr) / 2);

#ifdef SHAKE
				
				GetAddress4(adr, TreeIndexOFFSET, ti);
				SetAddress4(adr, TreeIndexOFFSET, ti / 2);
#else
				ShortGetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, ti);
				ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, ti / 2);
#endif
				// 12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, 𝑛𝑜𝑑𝑒[0] ∥ 𝑎𝑢𝑡ℎ[𝑗])
				memcpy(p[0], pnode0, FIPS205_N);
				memcpy(p[1], auth, FIPS205_N);
				

#ifdef SHAKE
				HASH_with_predcalc(pnode1, PK_seed, (uint8_t*)adr, p);
#else
				//toShort((PADR_C)adr_short, adr);
				HASH_with_predcalc_OLD(pnode1, PK_seed_n, (uint8_t*)adr, p);
//#if FIPS205_N == 16
//				HASH_with_predcalc(pnode1, predcalc_pk_256, /*predcalc_pk_256, */adr, p);
//#endif
//#if FIPS205_N == 24
//				HASH_with_predcalc(pnode1, /*predcalc_pk_256, */predcalc_pk_384, adr, p);
//#endif
//#if FIPS205_N == 32
//				HASH_with_predcalc(pnode1, /*predcalc_pk_256, */predcalc_pk_512, adr, p);
//#endif
#endif

			}
			// 13: else
			else
			{
				// 14: ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
#ifdef SHAKE
				//setTreeIndex(adr, (getTreeIndex(adr) - 1) / 2);
				GetAddress4(adr, TreeIndexOFFSET, ti);
				SetAddress4(adr, TreeIndexOFFSET, (ti - 1) / 2);
#else
				ShortGetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, ti);
				ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, (ti - 1) / 2);
#endif
				// 15: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, 𝑎𝑢𝑡ℎ[𝑗] ∥ 𝑛𝑜𝑑𝑒[0])
				memcpy(p[0], auth, FIPS205_N);
				memcpy(p[1], pnode0, FIPS205_N);

#ifdef SHAKE
				HASH_with_predcalc(pnode1, PK_seed, adr, p);
#else
				HASH_with_predcalc_OLD(pnode1, PK_seed_n, adr, p);
//#if FIPS205_N == 16
//				HASH_with_predcalc(pnode1, /*predcalc_pk_256,*/ predcalc_pk_256, adr, p);
//#endif
//#if FIPS205_N == 24
//				HASH_with_predcalc(pnode1, /*predcalc_pk_256, */predcalc_pk_384, adr, p);
//#endif
//#if FIPS205_N == 32
//				HASH_with_predcalc(pnode1, /*predcalc_pk_256, */predcalc_pk_512, adr, p);
//#endif
#endif
				/*if (memcmp(pnode1, temp, FIPS205_N) != 0)
				{
					printf("FORS HASH_with_predcalc _LINE_ = %d ERROR\n", __LINE__);
				}*/


				//16: end

			}
			// 17: 𝑛𝑜𝑑𝑒[0] ← 𝑛𝑜𝑑𝑒[1]
			memcpy(pnode0, pnode1, FIPS205_N);
	
		}
		// 19: 𝑟𝑜𝑜𝑡[𝑖] ← 𝑛𝑜𝑑𝑒[0]
		memcpy(root[i], pnode0, FIPS205_N);
		
		

	}
	/*



24: 𝑝𝑘 ← T𝑘(PK.seed, forspkADRS, 𝑟𝑜𝑜𝑡) ▷ compute the FORS public key
25: return 𝑝𝑘
	*/
	// 21: forspkADRS ← ADRS ▷ copy address to create a FORS public-key address
	//uint32_t kp;
	// 22: forspkADRS.setTypeAndClear(FORS_ROOTS)
	// 23: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
#ifdef SHAKE
	uint8_t forspkADRS[32] = { 0 };
	memcpy(forspkADRS, adr, 16);
	// setTypeAndClear(&forspkADRS, FORS_ROOTS);
	SetAddress4(forspkADRS, TypeAndClearOFFSET, FORS_ROOTS);
	// setKeyPairAddress(&forspkADRS, getKeyPairAddress(adr));
	//GetAddress4(adr, KeyPairAddressOFFSET, kp);
	//SetAddress4(forspkADRS, KeyPairAddressOFFSET, kp);
	SetFromGet4(forspkADRS, adr, KeyPairAddressOFFSET);
#else
	uint8_t forspkADRS[22] = { 0 };
	memcpy(forspkADRS, adr, 10);
	// setTypeAndClear(&forspkADRS, FORS_ROOTS);
	ShortSetAddress1_OLD (forspkADRS, ShortTypeAndClearOFFSET_OLD, FORS_ROOTS_OLD);
	// setKeyPairAddress(&forspkADRS, getKeyPairAddress(adr));
	//ShortGetAddress4(adr, ShortKeyPairAddressOFFSET, kp);
	//ShortSetAddress4(forspkADRS, ShortKeyPairAddressOFFSET, kp);
	ShortSetFromGet4_OLD(forspkADRS, adr, ShortKeyPairAddressOFFSET_OLD);
#endif
	
	
	// 24: 𝑝𝑘 ← T𝑘(PK.seed, forspkADRS, 𝑟𝑜𝑜𝑡)

#ifdef SHAKE
	//Tl_with_predcalc(PK_fors, PK_seed, forspkADRS, root, K);
	Tl_with_predcalc(PK_fors, PK_seed, forspkADRS, root, K);
#else
	Tl_with_predcalc_OLD(PK_fors, PK_seed, PK_seed_n, forspkADRS, root, FIPS205_K);
//#if FIPS205_N == 16
//	Tl_with_predcalc(PK_fors, predcalc_pk_256, predcalc_pk_256, forspkADRS, root, K);
//#endif
//#if FIPS205_N == 24
//	Tl_with_predcalc(PK_fors, predcalc_pk_256, predcalc_pk_384, forspkADRS, root, K);
//#endif
//#if FIPS205_N == 32
//	Tl_with_predcalc(PK_fors, predcalc_pk_256, predcalc_pk_512, forspkADRS, root, K);
//#endif
#endif

}

void fors_pkFromSig___OLD(uint8_t* PK_fors, const uint8_t* SIGfors, const uint8_t* md, const

	void* PK_seed_,
#ifndef SHAKE
	void* PK_seed_n,
#endif
	uint8_t* adr)
{
	// Algorithm 17 fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	// Computes a FORS public key from a FORS signature.
	// Input: 
	//		FORS signature SIG𝐹 𝑂𝑅𝑆, 
	//		message digest 𝑚𝑑, 
	//		public seed PK.seed, 
	//		address ADRS. 
	// Output: 
	//		FORS public key.
	// 1: 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)




	uint32_t indices[FIPS205_K];
	
	base_2b(indices, md, FIPS205_A, FIPS205_K);

	//uint8_t /*sk[FIPS205_N], */pnode1[FIPS205_N], pnode0[FIPS205_N];
	// 2: for 𝑖 from 0 to 𝑘 − 1 do
	
	uint8_t root[FIPS205_K][FIPS205_N];
	
	//uint8_t pnode0_[K][FIPS205_N];

#ifdef SHAKE
	uint8_t* PK_seed = (uint8_t*)PK_seed_;
	//F_with_predcalc(pnode0, PK_seed, (uint8_t*)adr, sk);
#else
	uint32_t* PK_seed = (uint32_t*)PK_seed_;
	//F_with_predcalc(pnode0, PK_seed, adr, sk);
#endif
	int i;
	//omp_set_num_threads(8);
#pragma omp parallel for
	for (i = 0; i < FIPS205_K; ++i)
	{
#ifdef SHAKE
		uint8_t adr_l[32];
#else
		uint8_t adr_l[22];
#endif
		//uint8_t auth[FIPS205_N];
		uint8_t sk[FIPS205_N];
		uint8_t pnode0[FIPS205_N]/*, pnode1[FIPS205_N]*/;
		//uint8_t  p[2][FIPS205_N];
		uint8_t  *p[2];
		uint8_t* cur_address = SIGfors + (i * (FIPS205_A + 1) * FIPS205_N);
		//uint32_t ind = indices[i];
		memcpy(adr_l, adr, sizeof(adr_l));
		//memcpy(sk, SIGfors + (i * (A + 1) * FIPS205_N), FIPS205_N);
		memcpy(sk, cur_address, FIPS205_N);
		//memcpy(sk, curSIGfors, FIPS205_N);
		//curSIGfors += (A + 1) * FIPS205_N;

		uint32_t ind = indices[i];
		// 4: ADRS.setTreeHeight(0) ▷ compute leaf
#ifdef SHAKE
		//setTreeHeight(adr, 0);
		SetAddress4_0(adr_l, TreeHeightOFFSET);
		// 5: ADRS.setTreeIndex(𝑖 * 2^𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		//setTreeIndex(adr, (uint32_t)(i * (1 << A) + indices[i]));
		SetAddress4(adr_l, TreeIndexOFFSET, (uint32_t)(i * (1 << A) + ind));
#else
		ShortSetAddress4_0_OLD(adr_l, ShortTreeHeightOFFSET_OLD);
		//ShortSetAddress4(adr_l, ShortTreeIndexOFFSET, (uint32_t)(i * (1 << A) + indices[i]));
		ShortSetAddress4_OLD(adr_l, ShortTreeIndexOFFSET_OLD, (uint32_t)(i * (1 << FIPS205_A) + ind));
#endif

		// 6: 𝑛𝑜𝑑𝑒[0] ← F(PK.seed,ADRS, 𝑠𝑘)


#ifdef SHAKE
		//uint8_t* PK_seed = (uint8_t*)PK_seed_;
		F_with_predcalc(pnode0 , PK_seed, adr_l, sk);
#else
		//uint32_t* PK_seed = (uint32_t*)PK_seed_;
		F_with_predcalc_OLD(pnode0 , PK_seed, adr_l, sk);
#endif
	

	//for (i = 0; i < K; ++i)
	//{
		//memcpy(pnode0, pnode0_[i], FIPS205_N);
		// 7: 𝑎𝑢𝑡ℎ ← SIG𝐹 𝑂𝑅𝑆.getAUTH(𝑖) ▷ SIG𝐹𝑂𝑅𝑆[(𝑖⋅(𝑎+1)+1)⋅𝑛 ∶ (𝑖+1)⋅(𝑎+1)⋅𝑛]
		uint8_t* pauth = cur_address + FIPS205_N; //SIGfors + ((i * (A + 1) + 1) * FIPS205_N);
		//const uint8_t* pauth = curSIGfors + FIPS205_N;

		//memcpy(auth[0], SIGfors + ((i * (A + 1) + 1) * FIPS205_N), FIPS205_N);
		// 8: for 𝑗 from 0 to 𝑎 − 1 do ▷ compute root from leaf and AUTH
		
		int j;
		for (j = 0; j < FIPS205_A; ++j)
		{
			//////////////////////////////////////////////
			//memcpy(auth, pauth, FIPS205_N);

			//pauth += FIPS205_N;
			// 9: ADRS.setTreeHeight(𝑗 + 1)
			//setTreeHeight(adr, (uint32_t)(j + 1));
#ifdef SHAKE
			SetAddress4(adr_l, TreeHeightOFFSET, (uint32_t)(j + 1));
#else
			ShortSetAddress4_OLD(adr_l, ShortTreeHeightOFFSET_OLD, (uint32_t)(j + 1));
#endif

			// 10: if ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2𝑗⌋ is even then 
			uint32_t ti;
#ifdef SHAKE
			GetAddress4(adr_l, TreeIndexOFFSET, ti);

#else
			ShortGetAddress4_OLD(adr_l, ShortTreeIndexOFFSET_OLD, ti);

#endif

			if (((ind / (1 << j)) & 1) == 0)		// even
			{
				// 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
				//setTreeIndex(adr, getTreeIndex(adr) / 2);

#ifdef SHAKE

				//GetAddress4(adr_l, TreeIndexOFFSET, ti);
				SetAddress4(adr_l, TreeIndexOFFSET, ti / 2);
#else
				//ShortGetAddress4(adr, ShortTreeIndexOFFSET, ti);
				ShortSetAddress4_OLD(adr_l, ShortTreeIndexOFFSET_OLD, ti / 2);
#endif
				// 12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, 𝑛𝑜𝑑𝑒[0] ∥ 𝑎𝑢𝑡ℎ[𝑗])
				//memcpy(p[0], pnode0, FIPS205_N);
				//memcpy(p[1], auth, FIPS205_N);
				p[0] = pnode0;
				//memcpy(p[0], pnode0, FIPS205_N);
				//memcpy(p[1], auth, FIPS205_N);
				//memcpy(p[1], pauth, FIPS205_N);
				p[1] = pauth;


				//#ifdef SHAKE
				//				HASH_with_predcalc(pnode1, PK_seed, (uint8_t*)adr, p);
				//#else
				//				//toShort((PADR_C)adr_short, adr);
				//#if FIPS205_N == 16
				//				HASH_with_predcalc(pnode1, predcalc_pk_256, predcalc_pk_256, adr, p);
				//#endif
				//#if FIPS205_N == 24
				//				HASH_with_predcalc(pnode1, predcalc_pk_256, predcalc_pk_384, adr, p);
				//#endif
				//#if FIPS205_N == 32
				//				HASH_with_predcalc(pnode1, predcalc_pk_256, predcalc_pk_512, adr, p);
				//#endif
				//#endif

			}
			// 13: else
			else
			{
				// 14: ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
#ifdef SHAKE
				//setTreeIndex(adr, (getTreeIndex(adr) - 1) / 2);
				//GetAddress4(adr_l, TreeIndexOFFSET, ti);
				SetAddress4(adr_l, TreeIndexOFFSET, (ti - 1) / 2);
#else
				//ShortGetAddress4(adr, ShortTreeIndexOFFSET, ti);
				ShortSetAddress4_OLD(adr_l, ShortTreeIndexOFFSET_OLD, (ti - 1) / 2);
#endif
				// 15: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, 𝑎𝑢𝑡ℎ[𝑗] ∥ 𝑛𝑜𝑑𝑒[0])
				//memcpy(p[0], auth, FIPS205_N);
				p[0] = pauth;
				
				//memcpy(p[0], pauth, FIPS205_N);
				//memcpy(p[1], pnode0, FIPS205_N);
				p[1] = pnode0;
				
			}
			pauth += FIPS205_N;
#ifdef SHAKE
			
			//HASH_with_predcalc(pnode0, PK_seed, adr_l, p);
			HASH_with_predcalcAdr(pnode0, PK_seed, adr_l, p);
#else
			//HASH_with_predcalc(pnode0, PK_seed_n, adr_l, p);
			HASH_with_predcalcAdr_OLD(pnode0, PK_seed_n, adr_l, p);

#endif

		}
		// 19: 𝑟𝑜𝑜𝑡[𝑖] ← 𝑛𝑜𝑑𝑒[0]
		memcpy(root[i], pnode0, FIPS205_N);

	}
	/*



24: 𝑝𝑘 ← T𝑘(PK.seed, forspkADRS, 𝑟𝑜𝑜𝑡) ▷ compute the FORS public key
25: return 𝑝𝑘
	*/
	// 21: forspkADRS ← ADRS ▷ copy address to create a FORS public-key address
	//uint32_t kp;
	// 22: forspkADRS.setTypeAndClear(FORS_ROOTS)
	// 23: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
#ifdef SHAKE
	uint8_t forspkADRS[32];
	memcpy(forspkADRS, adr, 32);
	// setTypeAndClear(&forspkADRS, FORS_ROOTS);
	SetAddressType4_0(forspkADRS, FORS_ROOTS);
	// setKeyPairAddress(&forspkADRS, getKeyPairAddress(adr));
	//GetAddress4(adr, KeyPairAddressOFFSET, kp);
	//SetAddress4(forspkADRS, KeyPairAddressOFFSET, kp);
	SetFromGet4(forspkADRS, adr, KeyPairAddressOFFSET);
#else
	uint8_t forspkADRS[22] ;
	memcpy(forspkADRS, adr, 22);
	// setTypeAndClear(&forspkADRS, FORS_ROOTS);
	ShortSetAddressType1_OLD(forspkADRS, FORS_ROOTS_OLD);
	// setKeyPairAddress(&forspkADRS, getKeyPairAddress(adr));
	//ShortGetAddress4(adr, ShortKeyPairAddressOFFSET, kp);
	//ShortSetAddress4(forspkADRS, ShortKeyPairAddressOFFSET, kp);
	ShortSetFromGet4_OLD(forspkADRS, adr, ShortKeyPairAddressOFFSET_OLD);
#endif


	// 24: 𝑝𝑘 ← T𝑘(PK.seed, forspkADRS, 𝑟𝑜𝑜𝑡)

#ifdef SHAKE
	// void Tl_with_predcalc(uint8_t* out, void* pk, uint8_t* adr, const uint8_t Msg[][FIPS205_N], size_t len);
	Tl_with_predcalc(PK_fors, PK_seed_, forspkADRS, root, K);
#else
	Tl_with_predcalc_OLD(PK_fors, PK_seed_, PK_seed_n, forspkADRS, root, FIPS205_K);
//#if FIPS205_N == 16
//	Tl_with_predcalc(PK_fors, predcalc_pk_256, predcalc_pk_256, forspkADRS, root, K);
//#endif
//#if FIPS205_N == 24
//	Tl_with_predcalc(PK_fors, predcalc_pk_256, predcalc_pk_384, forspkADRS, root, K);
//#endif
//#if FIPS205_N == 32
//	Tl_with_predcalc(PK_fors, predcalc_pk_256, predcalc_pk_512, forspkADRS, root, K);
//#endif
#endif

}



//int test_fors_sign()
//{
//	uint8_t digest[M];
//	uint8_t md[(K * A + 7) / 8];
//	uint8_t fors_sign1[K * (A + 1) * FIPS205_N], fors_sign2[K * (A + 1) * FIPS205_N];
//	uint8_t SK_seed[FIPS205_N], PK_seed_[FIPS205_N];
//
//	uint8_t adr[32] = {0};
//	uint8_t cur_adr[32] = {0};
//
//#ifndef SHAKE
//	
//	uint8_t short_adr[22] = {0};
//	uint8_t short_cur_adr[22] = {0};
//#endif
//	srand(0);
//	size_t i;
//	for (i = 0; i < FIPS205_N; ++i)
//	{
//		SK_seed[i] = rand() % 256;
//		PK_seed_[i] = rand() % 256;
//	}
//#ifdef SHAKE
//	uint8_t* PK_seed = PK_seed_;
//#else
//	uint32_t PK_seed[8];
//#if FIPS205_N == 16
//	uint32_t PK_seed_n[8];
//#else
//	uint64_t PK_seed_n[8];
//#endif
//	predcalcs_pk(PK_seed, PK_seed_n, PK_seed_);
//#endif
//
//
//	for (i = 0; i < M; ++i)
//	{
//		digest[i] = rand() % 256;
//	}
//	memcpy(md, digest, sizeof(md));
//	
//	uint8_t tmp_idxtree[(H - H / D + 7) / 8];
//	uint8_t tmp_idxleaf[(H + 8 * D - 1) / (8 * D)];
//	
//	memcpy(tmp_idxtree, digest + sizeof(md), sizeof(tmp_idxtree));
//	memcpy(tmp_idxleaf, digest + sizeof(md) + sizeof(tmp_idxtree), sizeof(tmp_idxleaf));
//	
//	
//	uint64_t idxtree = toInt64(tmp_idxtree, (H - H / D + 7) / 8) & (((uint64_t)1 << (H - H / D)) - 1);
//	
//	uint32_t idxleaf = toInt32(tmp_idxleaf, sizeof(tmp_idxleaf)) % ((uint64_t)1 << (H / D));
//	
////#ifdef SHAKE
//	SetAddress8(adr, TreeAddressOFFSET, idxtree);
//	SetAddressType4_0 (adr, FORS_TREE);
//	SetAddress4(adr, KeyPairAddressOFFSET, idxleaf);
//#ifndef SHAKE
//	ShortSetAddress8(short_adr, ShortTreeAddressOFFSET, idxtree);
//	ShortSetAddressType1(short_adr, FORS_TREE);
//	ShortSetAddress4(short_adr, ShortKeyPairAddressOFFSET, idxleaf);
//#endif
//
//
//#ifndef _DEBUG
//	uint64_t tacts;
//	uint64_t ForsMin = 0xFFFFFFFF;
//	for (i = 0; i < 256; ++i)
//	{
//#endif
//
//		memcpy(cur_adr, adr, sizeof (adr));
//#ifndef SHAKE 
//		memcpy(short_cur_adr, short_adr, sizeof(short_adr));
//#endif
//
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//
//		fors_skGen(fors_sign1, SK_seed, PK_seed_, (PADR)cur_adr, md[0]);
//
//
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < ForsMin)
//			ForsMin = tacts;
//	}
//	printf("fors_skGen time = %I64d\n", ForsMin);
//#endif
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFF;
//	for (i = 0; i < 256; ++i)
//	{
//#endif
//
//#ifdef SHAKE
//		memcpy(cur_adr, adr, 32);
//#else
//		memcpy(short_cur_adr, short_adr, 22);
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//		fors_skGen_(fors_sign2, SK_seed, PK_seed, cur_adr, md[0]);
//#else
//		fors_skGen_(fors_sign2, SK_seed, PK_seed, short_cur_adr, md[0]);
//#endif // SHAKE
//
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < ForsMin)
//			ForsMin = tacts;
//	}
//	printf("fors_skGen_ time = %I64d\n", ForsMin);
//#endif
//	printf("fors_skGen and fors_skGen_ : %s\n", memcmp(fors_sign1, fors_sign2, FIPS205_N) ==0 ? "YES" : "NO");
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//#endif
//		memcpy(cur_adr, adr, 32);
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//		fors_node(fors_sign1, SK_seed, 0, 1, PK_seed_, (PADR)cur_adr);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < ForsMin)
//			ForsMin = tacts;
//	}
//	printf("fors_node time = %I64d\n", ForsMin);
//#endif
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFFFFFFFF;
//
//	for (i = 0; i < 4; ++i)
//	{
//#endif
//#ifdef SHAKE 
//		memcpy(cur_adr, adr, 32);
//#else
//		memcpy(short_cur_adr, short_adr, 22);
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//		fors_node_(fors_sign2, SK_seed, 0, 1, PK_seed, cur_adr);
//#else
//		fors_node_(fors_sign2, SK_seed, 0, 1, 
//
//			PK_seed,
//			PK_seed_n,
//			short_cur_adr);
//#endif
//
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < ForsMin)
//			ForsMin = tacts;
//	}
//	printf("fors_node_ time = %I64d\n", ForsMin);
//#endif
//	
//	printf("fors_node and fors_node_ : %s\n", memcmp(fors_sign1, fors_sign2, FIPS205_N) == 0 ? "YES" : "NO");
//
//	uint8_t* p1, * p2;
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//#endif
//		memcpy(cur_adr, adr, 32);
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//		p1 = fors_sign(fors_sign1, md, SK_seed, PK_seed_, (PADR)cur_adr);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < ForsMin)
//			ForsMin = tacts;
//		//printf("fors_sign %x %x\n", fors_sign1[0], fors_sign1[1]);
//	}
//	printf("fors_sign: tacts = %I64d\n", ForsMin);
//#endif
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//#endif
//		#ifdef SHAKE
//			memcpy(cur_adr, adr, 32);
//		#else	
//			memcpy(short_cur_adr, short_adr, 22);
//		#endif
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//		p2 = fors_sign_(fors_sign2, md, SK_seed, PK_seed, cur_adr);
//#else
//		p2 = fors_sign_(fors_sign2, md, SK_seed, 
//			PK_seed,
//			PK_seed_n,
//			short_cur_adr);
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < ForsMin)
//			ForsMin = tacts;
//		//printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
//	}
//	printf("fors_sign_: tacts = %I64d\n", ForsMin);
//#endif
//	
//	int res = 0;
//	if (p1 - fors_sign1 != p2 - fors_sign2)
//		res = 1;
//
//	for (i = 0; res == 0 && (i < K * (A + 1) * FIPS205_N); ++i)
//	{
//		if (fors_sign1[i] != fors_sign2[i])
//			res = 1;
//	}
//	
//	printf("fors_sign and fors_sign_: %s\n", res == 0 ? "OK" : "ERROR");
//
//
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//#endif
//#ifdef SHAKE
//		memcpy(cur_adr, adr, 32);
//#else	
//		memcpy(short_cur_adr, short_adr, 22);
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//		p2 = fors_sign__(fors_sign2, md, SK_seed, PK_seed, cur_adr);
//#else
//		p2 = fors_sign__(fors_sign2, md, SK_seed,
//			PK_seed,
//			PK_seed_n,
//			short_cur_adr);
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < ForsMin)
//			ForsMin = tacts;
//		//printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
//	}
//	printf("fors_sign__: tacts = %I64d\n", ForsMin);
//#endif
//
//	res = 0;
//	if (p1 - fors_sign1 != p2 - fors_sign2)
//		res = 1;
//
//	for (i = 0; res == 0 && (i < K * (A + 1) * FIPS205_N); ++i)
//	{
//		if (fors_sign1[i] != fors_sign2[i])
//			res = 1;
//	}
//
//	printf("fors_sign and fors_sign__: %s\n", res == 0 ? "OK" : "ERROR");
//
//
//		
//	uint8_t PK_fors1[FIPS205_N], PK_fors2[FIPS205_N];
//
//	
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//	{
//#endif
//			memcpy(cur_adr, adr, 32);
//#ifndef _DEBUG
//			tacts = __rdtsc();
//#endif
//			fors_pkFromSig(PK_fors1, (const uint8_t*)fors_sign1, md, PK_seed_, (PADR)cur_adr);
//#ifndef _DEBUG
//			tacts = __rdtsc() - tacts;
//			if (tacts < ForsMin)
//				ForsMin = tacts;
//			//printf("fors_pkFromSig: %x %x\n", PK_fors1[0], PK_fors1[1]);
//	}
//	printf("fors_pkFromSig tacts = %I64d\n", ForsMin);
//#endif
//#ifndef _DEBUG
//	ForsMin = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//		{
//#endif
//#ifdef SHAKE
//			memcpy(cur_adr, adr, 32);
//#else
//			memcpy(short_cur_adr, short_adr, 22);
//#endif
//#ifndef _DEBUG
//			tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//			fors_pkFromSig_(PK_fors2, (const uint8_t*)fors_sign1, md, PK_seed, cur_adr);
//#else
//			fors_pkFromSig_(PK_fors2, (const uint8_t*)fors_sign1, md, 
//				PK_seed,
//				PK_seed_n,
//				short_cur_adr);
//#endif
//#ifndef _DEBUG
//			tacts = __rdtsc() - tacts;
//			if (tacts < ForsMin)
//				ForsMin = tacts;
//			//printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
//		}
//		printf("fors_pkFromSig_ tacts = %I64d\n", ForsMin);
//#endif
//		res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
//		printf("fors_pkFromSig and fors_pkFromSig_: %s\n", res == 0 ? "OK" : "ERROR");
//#ifndef _DEBUG		
//		ForsMin = 0xFFFFFFFFFFFFFFFF;
//
//		for (i = 0; i < 16; ++i)
//		{
//#endif
//#ifdef SHAKE
//			memcpy(cur_adr, adr, 32);
//#else
//			memcpy(short_cur_adr, short_adr, 22);
//#endif
//#ifndef _DEBUG		
//			tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//			fors_pkFromSig__(PK_fors2, (const uint8_t*)fors_sign1, md, PK_seed, cur_adr);
//#else
//			fors_pkFromSig__(PK_fors2, (const uint8_t*)fors_sign1, md, 
//				PK_seed,
//				PK_seed_n,
//				short_cur_adr);
//#endif
//#ifndef _DEBUG		
//			tacts = __rdtsc() - tacts;
//			if (tacts < ForsMin)
//				ForsMin = tacts;
//			//printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
//		}
//		printf("fors_pkFromSig__ tacts = %I64d\n", ForsMin);
//#endif
//
//		res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
//		printf("fors_pkFromSig and fors_pkFromSig__: %s\n", res == 0 ? "OK" : "ERROR");
//	
//	return res;
//
//}
