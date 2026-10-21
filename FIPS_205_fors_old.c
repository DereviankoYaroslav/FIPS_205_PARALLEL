
#include <stdlib.h>
#include <omp.h>
#ifdef _DEBUG
#include <stdio.h>
#endif
#include "FIPS_205_Adr_old.h"
#include "FIPS_205_Fors_old.h"
#include "FIPS_205_Hashs_old.h"

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
	ShortSetFromGet4_OLD(skADRS, adr, ShortKeyPairAddressOFFSET_OLD);
	ShortSetAddress4_OLD(skADRS, ShortTreeIndexOFFSET_OLD, ind);

#endif

	
//#ifdef _PREDCALC
#ifdef SHAKE
	//uint8_t* PK_seed = (uint8_t*)PK_seed_;
	PRF_with_predcalc(pFORS, (uint8_t*)PK_seed_, skADRS, SK_seed);
#else
	PRF_with_predcalc_OLD(pFORS, (uint32_t*)PK_seed_, skADRS, SK_seed);
#endif

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
		HASH_with_predcalc_OLD(pFORS, PK_seed_n, adr, lnode);
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

	for (i = 0; i < FIPS205_K; ++i)
	{
#ifdef SHAKE 
		uint8_t l_adr[32];
#else
		uint8_t l_adr[22];
#endif
		memcpy(l_adr, adr, sizeof(l_adr));
		
		uint8_t* pFORS = FORS + i * FIPS205_N * (1 + FIPS205_A);
		uint8_t* pAuth = pFORS + FIPS205_N;
		uint32_t s;
		// 4: fors_skGen(SK.seed,PK.seed,ADRS, 𝑖 ⋅ 2𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		fors_skGen__OLD(pFORS, SK_seed, PK_seed, l_adr, i * (1 << FIPS205_A) + indices[i]);
		
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

#endif

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
				p[0] = pnode0;
				p[1] = pauth;


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
#endif

}