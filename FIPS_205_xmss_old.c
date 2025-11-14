#include <stdio.h>
#include <stdlib.h>


#ifdef _GETTIME
#include <intrin.h>
#endif

#include "FIPS_205_xmss_old.h"

// Algorithm 9 xmss_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS
// Computes the root of a Merkle subtree of WOTS+ public keys.
//Вхід: 
// SK.seed - компонент секретного ключа, 
// 𝑖 - індекс вузла дерева, 
// 𝑧 - висота вузла, 
// PK.seed - компонет відкритого ключа
// adr - структура з інформацією.
// Вихід:
// PK_root - корень дерева, компонент відкритого ключа

//void xmss_node_OLD(
//	uint8_t* PK_root, 
//	const uint8_t* SK_seed, 
//	size_t i, 
//	size_t z,
//	const uint8_t* PK_seed, 
//	uint8_t *adr)
//{
//	uint8_t lnode[FIPS205_N], rnode[FIPS205_N];
//	uint8_t temp[2][FIPS205_N];
//#ifdef SHAKE
//	PADR_OLD* padr = (PADR_OLD*)adr;
//#else
//	PADR_C_OLD padr = (PADR_C_OLD)adr;
//#endif
//	//1: if 𝑧 = 0 then
//	if (z == 0)
//	{
//		//2: ADRS.setTypeAndClear(WOTS_HASH)
//#ifdef SHAKE
//		setTypeAndClear_OLD (padr, WOTS_HASH_OLD);
//		//3: ADRS.setKeyPairAddress(𝑖)
//		setKeyPairAddress_OLD(padr, (uint32_t)i);
//#else
//		setTypeAndClear_c_OLD(padr, WOTS_HASH_OLD);
//		//3: ADRS.setKeyPairAddress(𝑖)
//		setKeyPairAddress_c_OLD(padr, (uint32_t)i);
//#endif
//		// 4: 𝑛𝑜𝑑𝑒 ← wots_pkGen(SK.seed, PK.seed, ADRS)
//		/*
//		void wots_pkGenFull__(
//	uint8_t *pk,
//	const uint8_t* SK_seed,
//#ifdef SHAKE
//	const uint8_t* PK_seed,
//#else
//	const void* PK_seed,
//	const void* PK_seed_n,
//#endif
//	uint8_t* adr)
//	*/
//		wots_pkGenFull__(PK_root, SK_seed, PK_seed, PK_seed_n, adr);
//	}
//	//5: else
//	else
//	{
//		//6: 𝑙𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
//		xmss_node_OLD(lnode, SK_seed, 2 * i, z - 1, PK_seed, adr);
//
//		//	7 : 𝑟𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖 + 1, 𝑧 −1, PK.seed, ADRS)
//		xmss_node_OLD(rnode, SK_seed, 2 * i + 1, z - 1, PK_seed, adr);
//
//		//	8 : ADRS.setTypeAndClear(TREE)
//#ifdef SHAKE
//		setTypeAndClear_OLD(padr, TREE_OLD);
//		// 9 : ADRS.setTreeHeight(𝑧)
//		setTreeHeight_OLD(padr, (uint32_t)z);
//		//10 : ADRS.setTreeIndex(𝑖)
//		setTreeIndex_OLD(padr, (uint32_t)i);
//#else
//		setTypeAndClear_c_OLD(padr, TREE_OLD);
//		// 9 : ADRS.setTreeHeight(𝑧)
//		setTreeHeight_c_OLD(padr, (uint32_t)z);
//		//10 : ADRS.setTreeIndex(𝑖)
//		setTreeIndex_c_OLD(padr, (uint32_t)i);
//#endif
//		memcpy(temp[0], lnode, FIPS205_N);
//		memcpy(temp[1], rnode, FIPS205_N);
//
//		//11 : 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
////#ifndef _PREDCALC
//
//		HASH(PK_root, PK_seed, (uint8_t*)adr, temp);
//
//			//12 : end if
//	}
//	//13: return 𝑛𝑜𝑑𝑒
//
//}



void xmss_node__OLD(
	uint8_t* PK_root,
	const uint8_t* SK_seed,
	size_t  i,
	size_t z,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t *adr)
{
	uint8_t lnode[FIPS205_N], rnode[FIPS205_N];
	uint8_t temp[2][FIPS205_N];
#ifdef SHAKE
	PADR_OLD padr = (PADR_OLD)adr;
#else
	PADR_C_OLD padr = (PADR_C_OLD)adr;
#endif
	//1: if 𝑧 = 0 then
	if (z == 0)
	{
#ifdef SHAKE
		//2: ADRS.setTypeAndClear(WOTS_HASH)
		//setTypeAndClear(adr, WOTS_HASH);
		SetAddressType4_0(adr, WOTS_HASH);
		//3: ADRS.setKeyPairAddress(𝑖)
		//setKeyPairAddress(adr, (uint32_t)i);
		SetAddress4(adr, KeyPairAddressOFFSET, (uint32_t)i);
		//uint8_t pk[FIPS205_N];

		wots_pkGen_(
			PK_root,
			SK_seed,
			PK_seed,
			adr);

#else
		//2: ADRS.setTypeAndClear(WOTS_HASH)

		ShortSetAddressType1_OLD(adr, WOTS_HASH)
		//3: ADRS.setKeyPairAddress(𝑖)
		//setKeyPairAddress(adr, (uint32_t)i);
		ShortSetAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, (uint32_t)i);
		
		
		wots_pkGenFull__(
			PK_root,
			//uint8_*pk, 
			SK_seed,
#ifdef SHAKE
			PK_seed,
#else
			PK_seed,
			PK_seed_n,
#endif
			adr
			);

		


#endif


	}
	//5: else
	else
	{
		//6: 𝑙𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
#ifdef SHAKE
		xmss_node__OLD(lnode, SK_seed, 2 * i, z - 1, PK_seed, adr);

		//	7 : 𝑟𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖 + 1, 𝑧 −1, PK.seed, ADRS)
		xmss_node__OLD(rnode, SK_seed, 2 * i + 1, z - 1, PK_seed, adr);

		//	8 : ADRS.setTypeAndClear(TREE)
		//setTypeAndClear(adr, TREE);
		SetAddressType4_0_OLD(adr, TREE);
		// 9 : ADRS.setTreeHeight(𝑧)
		//setTreeHeight(adr, (uint32_t)z);
		SetAddress4_OLD(adr, TreeHeightOFFSET, (uint32_t)z);
		//10 : ADRS.setTreeIndex(𝑖)
		//setTreeIndex(adr, (uint32_t)i);
		SetAddress4_OLD(adr, TreeIndexOFFSET, (uint32_t)i);
		memcpy(temp[0], lnode, FIPS205_N);
		memcpy(temp[1], rnode, FIPS205_N);
#else
		xmss_node__OLD(lnode, SK_seed, 2 * i, z - 1, PK_seed, PK_seed_n, adr);

		//	7 : 𝑟𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖 + 1, 𝑧 −1, PK.seed, ADRS)
		xmss_node__OLD(rnode, SK_seed, 2 * i + 1, z - 1, PK_seed, PK_seed_n, adr);

		//	8 : ADRS.setTypeAndClear(TREE)
		//setTypeAndClear(adr, TREE);
		ShortSetAddressType1_OLD((uint8_t*)adr, TREE);
		// 9 : ADRS.setTreeHeight(𝑧)
		//setTreeHeight(adr, (uint32_t)z);
		ShortSetAddress4_OLD((uint8_t*)adr, ShortTreeHeightOFFSET_OLD, (uint32_t)z);
		//10 : ADRS.setTreeIndex(𝑖)
		//setTreeIndex(adr, (uint32_t)i);
		ShortSetAddress4_OLD((uint8_t*)adr, ShortTreeIndexOFFSET_OLD, (uint32_t)i);
		memcpy(temp[0], lnode, FIPS205_N);
		memcpy(temp[1], rnode, FIPS205_N);
#endif
		//11 : 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)

#ifdef SHAKE
		HASH_with_predcalc_OLD(PK_root, PK_seed, (uint8_t*)adr, temp);
#else
		HASH_with_predcalc_OLD(PK_root, PK_seed_n, (uint8_t*)adr, temp);
#endif

		//12 : end if
	}
	//13: return 𝑛𝑜𝑑𝑒

}





#if 0
void xmss_node_not_recurse_OLD(
	uint8_t* PK_root,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	PADR_OLD  adr
)
{
	uint8_t temp[1 << FIPS205_H_][FIPS205_N];
	//uint8_t node[2][FIPS205_N];
	int i, j, pz = 1 << FIPS205_H_;

	//#ifdef SHAKE
	//	setTypeAndClear(adr, WOTS_HASH);
	//#else
	//	ShortSetAddressType1(l_adr, WOTS_HASH);
	//#endif
#pragma omp parallel
	for (i = 0; i < pz; ++i)
	{


		//setTypeAndClear(adr, WOTS_HASH);
#ifdef SHAKE
		uint8_t l_adr[32];
		memcpy(l_adr, adr, 32);
		SetAddressType4_0(l_adr, WOTS_HASH);
		//SetAddress4(l_adr, LayerAddressOFFSET, D - 1);


		//setKeyPairAddress(adr, (uint32_t)i);
		SetAddress4(l_adr, KeyPairAddressOFFSET, (uint32_t)i);
		wots_pkGen_(temp[i], SK_seed, PK_seed, l_adr);
#else
		uint8_t l_adr[22];
		memcpy(l_adr, (uint8_t*)adr, 22);

		ShortSetAddressType1_OLD(l_adr, WOTS_HASH_OLD);
		ShortSetAddress4_OLD(l_adr, ShortKeyPairAddressOFFSET_OLD , (uint32_t)i);

		wots_pkGen__((uint8_t(*)[16])temp[i], SK_seed, PK_seed, PK_seed_n, (uint8_t*)adr);
#endif
	}

	i = 1 << (FIPS205_H_ - 1);

	int z = 0;
#ifdef SHAKE
	//setTypeAndClear(adr, TREE);
	SetAddressType4_0(adr, TREE);
#else
	ShortSetAddressType1_OLD((uint8_t*)adr, TREE_OLD);
#endif

	while (i != 2)
	{
		++z;
#ifdef SHAKE
		//setTreeHeight(adr, (uint32_t)z);
		SetAddress4(adr, TreeHeightOFFSET, (uint32_t)z);
#else
		ShortSetAddress4_OLD((uint8_t*)adr, ShortTreeHeightOFFSET_OLD, (uint32_t)z);
#endif
		for (j = 0; j < i; ++j)
		{

			//setTreeIndex(adr, (uint32_t)j);
#ifdef SHAKE
			SetAddress4(adr, TreeIndexOFFSET, (uint32_t)j);
#else
			ShortSetAddress4_OLD((uint8_t*)adr, ShortTreeIndexOFFSET_OLD, (uint32_t)j);
#endif

			//HASH(temp[j], PK_seed, (uint8_t*)adr, temp + 2 * j);
			// HASH_with_predcalc_256_OLD(uint8_t* hash_value, const void* pk, uint8_t* Adr, const uint8_t Msg[2][FIPS205_N]);
			HASH_with_predcalc_256_OLD(temp[j], PK_seed, (uint8_t*)adr, temp + 2 * j);

		}
		i = i / 2;

	}
	++z;
#ifdef SHAKE
	//setTreeHeight(adr, (uint32_t)z);
	SetAddress4(adr, TreeHeightOFFSET, (uint32_t)z);
	SetAddress4_0(adr, TreeIndexOFFSET);
#else
	ShortSetAddress4_OLD((uint8_t*)adr, ShortTreeHeightOFFSET_OLD, (uint32_t)z);
	ShortSetAddress4_0_OLD((uint8_t*)adr, ShortTreeIndexOFFSET_OLD);
#endif
	HASH_with_predcalc_256_OLD(PK_root, PK_seed, (uint8_t*)adr, temp);

	//memcpy(PK_root, temp[0], FIPS205_N);
}
#endif

#if 0
void xmss_sign_OLD(uint8_t* SIGtmp, const uint8_t* Msg, const uint8_t* SK_seed,
	size_t idx,
	const uint8_t* PK_seed,
	uint8_t*  adr)
{
	//Algorithm 10 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
	//Generates an XMSS signature.
	//  Input: 
	//		𝑛 - byte message 𝑀, 
	//		secret seed SK.seed, 
	//		index 𝑖𝑑𝑥, 
	//		public seed PK.seed, 
	//		address ADRS.
	//	Output : 
			//XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH).
	// 1: for 𝑗 from 0 to ℎ′ −1 do ▷ build authentication path
//#ifdef _GETTIME
//	uint64_t tacts = __rdtsc();
//#endif
	uint8_t* p = SIGtmp;
	size_t j;
	uint8_t auth[FIPS205_H_][FIPS205_N];
	//uint8_t sig[FIPS205_N];
	for (j = 0; j < FIPS205_H_; ++j)
	{
		// 2: 𝑘 ← ⌊𝑖𝑑𝑥/2𝑗⌋ ⊕ 1
		size_t k = (idx / ((uint64_t)1 << j)) ^ 1;
		// 3: AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗,PK.seed,ADRS)
		/*
		void xmss_node_(uint8_t* PK_root, const uint8_t* SK_seed, size_t i, size_t z,
#ifdef SHAKE
			const uint8_t* PK_seed,
#else
			const uint32_t* PK_seed,
			const uint64_t* PK_seed_n,
#endif
			uint8_t* adr)
		*/
		//#ifdef SHAKE
		xmss_node_OLD(auth[j], SK_seed, k, j, PK_seed, adr);
		//#else
		//		xmss_node_(auth[j], SK_seed, k, j, PK_seed, PK_seed_n, adr);
		//#endif
				/*
					4: end for
				*/
	}

	// 5: ADRS.setTypeAndClear(WOTS_HASH)
	setTypeAndClear_OLD(adr, WOTS_HASH_OLD);
	setKeyPairAddress_OLD(adr, (uint32_t)idx);

	// 7: 𝑠𝑖𝑔 ← wots_sign(𝑀,SK.seed,PK.seed,ADRS)

	wots_sign_OLD(p, Msg, SK_seed, PK_seed, adr);

	// 8: SIG𝑋𝑀𝑆𝑆 ← 𝑠𝑖𝑔 ∥ AUTH
	p += FIPS205_N * FIPS205_LEN;

	for (j = 0; j < FIPS205_H_; ++j) {

		memcpy(p, auth[j], FIPS205_N);
		p += FIPS205_N;
	}


	/*



9: return SIG𝑋𝑀𝑆𝑆
	*/
}
#endif

#if 1
void xmss_sign__OLD(uint8_t* SIGtmp, const uint8_t* Msg, const uint8_t* SK_seed,
	size_t idx,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t*  adr)
{
	//Algorithm 10 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
	//Generates an XMSS signature.
	//  Input: 
	//		𝑛 - byte message 𝑀, 
	//		secret seed SK.seed, 
	//		index 𝑖𝑑𝑥, 
	//		public seed PK.seed, 
	//		address ADRS.
	//	Output : 
			//XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH).
	// 1: for 𝑗 from 0 to ℎ′ −1 do ▷ build authentication path

	uint8_t* p = SIGtmp;
	uint8_t* auth = p + FIPS205_N * FIPS205_LEN;
	size_t j;
	//uint8_t auth[H_][FIPS205_N];

	for (j = 0; j < FIPS205_H_; ++j)
	{
		// 2: 𝑘 ← ⌊𝑖𝑑𝑥/2𝑗⌋ ⊕ 1
		size_t k = (idx / ((uint64_t)1 << j)) ^ 1;
		// 3: AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗,PK.seed,ADRS)
		/*
		xmss_node_(uint8_t* PK_root, const uint8_t* SK_seed, size_t i, size_t z,
#ifdef SHAKE
			const uint8_t* PK_seed,
#else
			const uint32_t* PK_seed,
			const uint64_t* PK_seed_n,
#endif
			uint8_t* adr)
		*/
#ifdef SHAKE
		//xmss_node_(auth[j], SK_seed, k, j, PK_seed, adr);
		xmss_node_(auth, SK_seed, k, j, PK_seed, adr);
		//xmss_node(auth, SK_seed, k, j, PK_seed, adr);
		auth += FIPS205_N;
		//xmss_node_not_recurse_(auth[j], SK_seed, k, j, PK_seed, adr);
#else
		xmss_node__OLD(auth, SK_seed, k, j, PK_seed, PK_seed_n, adr);
		auth += FIPS205_N;
		//xmss_node_not_recurse_(auth[j], SK_seed, k, j, PK_seed, PK_seed_n, adr);
#endif

		/*
			4: end for
		*/
	}
	// 5: ADRS.setTypeAndClear(WOTS_HASH)

#ifdef SHAKE
	SetAddressType4_0(adr, WOTS_HASH);
	//setTypeAndClear(adr, WOTS_HASH);
	//6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	SetAddress4(adr, KeyPairAddressOFFSET, (uint32_t)idx);
	//setKeyPairAddress(adr, (uint32_t)idx);
	wots_sign_(p, Msg, SK_seed, PK_seed, adr);
#else
	ShortSetAddressType1_OLD(adr, WOTS_HASH_OLD);
	//setTypeAndClear(adr, WOTS_HASH);
	//6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	ShortSetAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, (uint32_t)idx);
	wots_sign__OLD(p, Msg, SK_seed, PK_seed, PK_seed_n, (uint8_t*)adr);
#endif

	// 7: 𝑠𝑖𝑔 ← wots_sign(𝑀,SK.seed,PK.seed,ADRS)

	// 8: SIG𝑋𝑀𝑆𝑆 ← 𝑠𝑖𝑔 ∥ AUTH
	/*p += FIPS205_N * LEN;

	for (j = 0; j < H_; ++j) {

		memcpy(p, auth[j], FIPS205_N);
		p += FIPS205_N;
	}*/
	//#ifdef _GETTIME
	//	tacts = __rdtsc() - tacts;
	//	//printf("xmss_sign time = %I64d\n", tacts);
	//	if (tacts < xmss_signTime)
	//		xmss_signTime = tacts;
	//#endif
		/*



	9: return SIG𝑋𝑀𝑆𝑆
		*/
}


//Algorithm 11 xmss_pkFromSig(𝑖𝑑𝑥, SIG𝑋𝑀𝑆𝑆, 𝑀, PK.seed, ADRS)
//Computes an XMSS public key from an XMSS signature.
//Input: Index 𝑖𝑑𝑥, XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH), 𝑛 - byte message 𝑀, public seed PK.seed, address ADRS.
//Output : 𝑛 - byte root value 𝑛𝑜𝑑𝑒[0].

//void xmss_pkFromSig_OLD(
//	uint8_t* root,
//	size_t idx,
//	const uint8_t* SIGtmp,
//	const uint8_t* Msg,
//	const uint8_t* PK_seed,
//	uint8_t*  adr)
//{
//	// 1: ADRS.setTypeAndClear(WOTS_HASH) ▷ compute WOTS+ pk from WOTS+ 𝑠𝑖𝑔
//
//#ifdef SHAKE
//	SetAddressType4_0_OLD((uint8_t*)adr, WOTS_HASH_OLD);
//#else
//	ShortSetAddressType1_OLD((uint8_t*)adr, WOTS_HASH_OLD);
//#endif
//	
//	// 	2: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
//#ifdef SHAKE
//	SetAddress4_OLD(adr, KeyPairAddressOFFSET_OLD, (uint32_t)idx);
//#else
//	//setKeyPairAddress_c_OLD(adr, (uint32_t)idx);
//	ShortSetAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, (uint32_t)idx);
//#endif
//	// 3: 𝑠𝑖𝑔 ← SIG𝑋𝑀𝑆𝑆.getWOTSSig() ▷ SIG𝑋𝑀𝑆𝑆[0 ∶ 𝑙𝑒𝑛 ⋅ 𝑛]
//	// 4: AUTH ← SIG𝑋𝑀𝑆𝑆.getXMSSAUTH() ▷ SIG𝑋𝑀𝑆𝑆[𝑙𝑒𝑛 ⋅ 𝑛 ∶ (𝑙𝑒𝑛 + ℎ′) ⋅ 𝑛]
//	//size_t i;
//	//uint8_t auth[H_][FIPS205_N];
//	//uint8_t sig [LEN * FIPS205_N];
//	const uint8_t* sig = SIGtmp;
//	const uint8_t* auth = SIGtmp + FIPS205_LEN * FIPS205_N;
//	/*
//	memcpy(sig, p, LEN * FIPS205_N);
//	p += LEN * FIPS205_N;
//	for (i = 0; i < H_; ++i)
//	{
//		memcpy(auth[i], p, FIPS205_N);
//		p += FIPS205_N;
//	}*/
//
//
//	uint8_t node[2][FIPS205_N], temp[2][FIPS205_N];
//	// 5: 𝑛𝑜𝑑𝑒[0] ← wots_pkFromSig(𝑠𝑖𝑔, 𝑀,PK.seed,ADRS)
//	//wots_pkFromSig(node[0], sig, Msg, PK_seed, adr);
//	wots_pkFromSig_(
//
//		node[0],
//		sig,
//		Msg,
//#ifdef SHAKE
//		const uint8_t * PK_seed,
//#else
//		PK_seed,
//		PK_seed_n,
//#endif
//
//		uint8_t * adr)
//	// 6: ADRS.setTypeAndClear(TREE) ▷ compute root from WOTS+ pk and AUTH
//	setTypeAndClear(adr, TREE_OLD);
//	// 7: ADRS.setTreeIndex(𝑖𝑑𝑥)
//	setTreeIndex(adr, (uint32_t)idx);
//	//8: for 𝑘 from 0 to ℎ′ −1 do
//	uint32_t k;
//	//#ifdef _DEBUG
//	//	uint8_t HASHTemp[FIPS205_N];
//	//	uint8_t short_adr[22];
//	//#endif
////#ifndef SHAKE
////	uint8_t short_adr[22];
////#endif
//
//	for (k = 0; k < FIPS205_H_; ++k)
//	{
//		// 9: ADRS.setTreeHeight(𝑘 + 1)
//		setTreeHeight(adr, k + 1);
//		// 10: if ⌊𝑖𝑑𝑥/2𝑘⌋ is even then 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
//		if (((idx / ((uint64_t)1 << k)) & 1) == 0)
//		{
//			// 11 ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
//			setTreeIndex(adr, getTreeIndex(adr) / 2);
//			// 12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, 𝑛𝑜𝑑𝑒[0] ∥ AUTH[𝑘])
//
//			memcpy(temp[0], node[0], FIPS205_N);
//			memcpy(temp[1], auth + k * FIPS205_N, FIPS205_N);
//#if 1
//			HASH(node[1], PK_seed, (uint8_t*)adr, temp);
//			//#ifdef _DEBUG
//#else
//			//uint8_t short_adr[22];
//
//#ifdef SHAKE
//			HASH_with_predcalc(node[1], PK_seed, (uint8_t*)adr, temp);
//#else
//
//			toShort((PADR_C)short_adr, (PADR)adr);
//#if FIPS205_N==16
//			HASH_with_predcalc(node[1], predcalc_pk_256, short_adr, temp);
//#endif
//#if FIPS205_N==24
//			HASH_with_predcalc(node[1], predcalc_pk_384, short_adr, temp);
//#endif
//#if FIPS205_N==32
//			HASH_with_predcalc(node[1], predcalc_pk_512, short_adr, temp);
//#endif
//#endif
//			/*if (memcmp(node[1], HASHTemp, FIPS205_N))
//				printf("XMSS HASH_with_predcalc LINE = %d\n", __LINE__);*/
//#endif
//		}
//		// 13: else
//		else
//		{
//			//14: ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
//			setTreeIndex(adr, (getTreeIndex(adr) - 1) / 2);
//			//15: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, AUTH[𝑘] ∥ 𝑛𝑜𝑑𝑒[0])0
//			memcpy(temp[0], auth + k * FIPS205_N, FIPS205_N);
//			memcpy(temp[1], node[0], FIPS205_N);
//#if 1
//			HASH(node[1], PK_seed, (uint8_t*)adr, temp);
//#else
//#ifdef SHAKE
//			HASH_with_predcalc(node[1], PK_seed, (uint8_t*)adr, temp);
//#else
//			toShort((PADR_C)short_adr, adr);
//#if FIPS205_N == 16
//			HASH_with_predcalc(node[1], predcalc_pk_256, short_adr, temp);
//#endif
//#if FIPS205_N == 24
//			HASH_with_predcalc(node[1], predcalc_pk_384, short_adr, temp);
//#endif
//#if FIPS205_N == 32
//			HASH_with_predcalc(node[1], predcalc_pk_512, short_adr, temp);
//#endif
//#endif // SHAKE
//
//#endif // _PREDCALC
//			//16: end if 
//		}
//		//17: 𝑛𝑜𝑑𝑒[0] ← 𝑛𝑜𝑑𝑒[1]
//		memcpy(node[0], node[1], FIPS205_N);
//		//18: end for 
//
//	}
//	memcpy(root, node[0], FIPS205_N);
//	//#ifdef _GETTIME
//	//	tacts = __rdtsc() - tacts;
//	//	//printf("xmss_pkFromSig time = %I64d\n", tacts);
//	//	if (tacts < xmss_pkFromSigTime)
//	//		xmss_pkFromSigTime = tacts;
//	//#endif
//}

void xmss_pkFromSig__OLD(
	uint8_t* root,
	size_t idx,
	const uint8_t* SIGtmp,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t*  adr)


{
	// 1: ADRS.setTypeAndClear(WOTS_HASH) ▷ compute WOTS+ pk from WOTS+ 𝑠𝑖𝑔

//#ifdef _GETTIME
//	uint64_t tacts = __rdtsc();
//	//printf("xmss_sign time = %I64d\n", tacts);
//#endif
#ifdef SHAKE
	//setTypeAndClear(adr, WOTS_HASH);
	SetAddressType4_0(adr, WOTS_HASH);
	// 	2: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	//setKeyPairAddress(adr, (uint32_t)idx);
	SetAddress4(adr, KeyPairAddressOFFSET, (uint32_t)idx);
#else
	ShortSetAddressType1_OLD(adr, WOTS_HASH_OLD);
	ShortSetAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, (uint32_t)idx);
#endif
	// 3: 𝑠𝑖𝑔 ← SIG𝑋𝑀𝑆𝑆.getWOTSSig() ▷ SIG𝑋𝑀𝑆𝑆[0 ∶ 𝑙𝑒𝑛 ⋅ 𝑛]
	// 4: AUTH ← SIG𝑋𝑀𝑆𝑆.getXMSSAUTH() ▷ SIG𝑋𝑀𝑆𝑆[𝑙𝑒𝑛 ⋅ 𝑛 ∶ (𝑙𝑒𝑛 + ℎ′) ⋅ 𝑛]
	//size_t i;
	//uint8_t auth[H_][FIPS205_N];
	//uint8_t sig [LEN * FIPS205_N];
	const uint8_t* sig = SIGtmp;
	const uint8_t* auth = SIGtmp + FIPS205_LEN * FIPS205_N, * pauth = auth;
	/*
	memcpy(sig, p, LEN * FIPS205_N);
	p += LEN * FIPS205_N;
	for (i = 0; i < H_; ++i)
	{
		memcpy(auth[i], p, FIPS205_N);
		p += FIPS205_N;
	}*/


	//uint8_t temp[2][FIPS205_N];
	//uint8_t node[2][FIPS205_N];
	uint8_t node[FIPS205_N];
	// 5: 𝑛𝑜𝑑𝑒[0] ← wots_pkFromSig(𝑠𝑖𝑔, 𝑀,PK.seed,ADRS)

	/*wots_pkFromSig_(
		node[0], sig, Msg,
#ifdef SHAKE
		PK_seed,
#else
		PK_seed,
		PK_seed_n,
#endif
		adr);*/

	wots_pkFromSig_(
		node, sig, Msg,
#ifdef SHAKE
		PK_seed,
#else
		PK_seed,
		PK_seed_n,
#endif
		adr);


	// 6: ADRS.setTypeAndClear(TREE) ▷ compute root from WOTS+ pk and AUTH
	//setTypeAndClear(adr, TREE);
#ifdef SHAKE
	SetAddressType4_0(adr, TREE);
	SetAddress4(adr, TreeIndexOFFSET, (uint32_t)idx);
#else
	ShortSetAddressType1_OLD(adr, TREE_OLD);
	ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, (uint32_t)idx);
#endif
	// 7: ADRS.setTreeIndex(𝑖𝑑𝑥)

	//8: for 𝑘 from 0 to ℎ′ −1 do
	uint32_t k;
	//#ifdef _DEBUG
	//	uint8_t HASHTemp[FIPS205_N];
	//	uint8_t short_adr[22];
	//#endif
	//#ifndef SHAKE
	//	uint8_t short_adr[22];
	//#endif

	for (k = 0; k < FIPS205_H_; ++k)
	{
		uint32_t value;
		// 9: ADRS.setTreeHeight(𝑘 + 1)
#ifdef SHAKE
		//setTreeHeight(adr, k + 1);
		SetAddress4(adr, TreeHeightOFFSET, k + 1);
#else
		ShortSetAddress4_OLD(adr, ShortTreeHeightOFFSET_OLD, k + 1);
#endif
		// 10: if ⌊𝑖𝑑𝑥/2𝑘⌋ is even then 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
		if (((idx / ((uint64_t)1 << k)) & 1) == 0)
		{
			// 11 ADRS.setTreeIndex(ADRS.getTreeIndex()/2)

#ifdef SHAKE

			//setTreeIndex(adr, getTreeIndex(adr) / 2);
			GetAddress4(adr, TreeIndexOFFSET, value);
			SetAddress4(adr, TreeIndexOFFSET, value / 2);
#else
			ShortGetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, value);
			ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, value / 2);
#endif
			// 12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, 𝑛𝑜𝑑𝑒[0] ∥ AUTH[𝑘])


			//memcpy(temp[0], node, FIPS205_N);
			//memcpy(temp[1], auth + k * FIPS205_N, FIPS205_N);
//#ifndef _PREDCALC
//			HASH(node[1], PK_seed, (uint8_t*)adr, temp);
////#ifdef _DEBUG
//#else
//			//uint8_t short_adr[22];

#ifdef SHAKE
			//HASH_with_predcalc(node, PK_seed, (uint8_t*)adr, temp);
			HASH_with_predcalc2(node, PK_seed, (uint8_t*)adr, node, pauth/*auth + k * FIPS205_N*/);
#else

			//toShort((PADR_C)short_adr, (PADR)adr);
//#if FIPS205_N==16
			HASH_with_predcalc2_OLD(node, PK_seed_n, adr, node, (uint8_t*)pauth);

#endif
			/*if (memcmp(node[1], HASHTemp, FIPS205_N))
				printf("XMSS HASH_with_predcalc LINE = %d\n", __LINE__);*/
				//#endif
		}
		// 13: else
		else
		{
			//14: ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
			//setTreeIndex(adr, (getTreeIndex(adr) - 1) / 2);
#ifdef SHAKE
			GetAddress4(adr, TreeIndexOFFSET, value);
			//setTreeIndex(adr, (getTreeIndex(adr) - 1) / 2);
			SetAddress4(adr, TreeIndexOFFSET, (value - 1) / 2);
#else
			ShortGetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, value);
			//setTreeIndex(adr, (getTreeIndex(adr) - 1) / 2);
			ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, (value - 1) / 2);
#endif
			//15: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed,ADRS, AUTH[𝑘] ∥ 𝑛𝑜𝑑𝑒[0])
			//memcpy(temp[0], auth + k * FIPS205_N, FIPS205_N);
			//memcpy(temp[1], node[0], FIPS205_N);
			//memcpy(temp[1], node, FIPS205_N);

#ifdef SHAKE
			//HASH_with_predcalc(node[1], PK_seed, (uint8_t*)adr, temp);
			HASH_with_predcalc2(node, PK_seed, (uint8_t*)adr, pauth/*auth + k * FIPS205_N*/, node);
#else


			HASH_with_predcalc2_OLD(node, PK_seed_n, adr, pauth, node);
#endif



			//16: end if 
		}
		pauth += FIPS205_N;
		//17: 𝑛𝑜𝑑𝑒[0] ← 𝑛𝑜𝑑𝑒[1]
		//memcpy(node[0], node[1], FIPS205_N);
		//18: end for 

	}
	//memcpy(root, node[0], FIPS205_N);
	memcpy(root, node, FIPS205_N);
	//#ifdef _GETTIME
	//	tacts = __rdtsc() - tacts;
	//	//printf("xmss_pkFromSig time = %I64d\n", tacts);
	//	if (tacts < xmss_pkFromSigTime)
	//		xmss_pkFromSigTime = tacts;
	//#endif
}

#if 0
int test_xmss()
{
	srand(0);
	uint8_t SK_seed[FIPS205_N], PK_seed_[FIPS205_N];
	uint8_t msg[FIPS205_N];
	uint8_t adr32[32] = { 0 };
#ifdef SHAKE
	uint8_t adr[32] = { 0 };
#else
	uint8_t adr[22] = { 0 };
#endif
	int i;
	for (i = 0; i < FIPS205_N; ++i)
	{
		SK_seed[i] = rand() % 256;
		PK_seed_[i] = rand() % 256;
		msg[i] = rand() % 256;
	}

#ifdef SHAKE
	uint8_t* PK_seed = PK_seed_;
#else
	uint32_t PK_seed[8];
#if FIPS205_N == 16
	uint32_t PK_seed_n[8];
#else
	uint64_t PK_seed_n[8];
#endif
	predcalcs_pk(PK_seed, PK_seed_n, PK_seed_);
#endif


	uint8_t PK_root1[FIPS205_N], PK_root2[FIPS205_N];

#ifdef SHAKE
	uint8_t l_adr[32];

#else
	uint8_t l_adr[22];

#endif
	uint8_t l_adr32[32];
#ifndef _DEBUG
	uint64_t tacts, min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif
		memcpy(l_adr, adr, sizeof(adr));
		memcpy(l_adr32, adr32, 32);
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		xmss_node(PK_root1, SK_seed, 0, H_ - 1, PK_seed_, (PADR)l_adr32);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;

		if (tacts < min_tacts)
			min_tacts = tacts;
	}
	printf("xmss_node time- %I64d\n", min_tacts);
#endif

#ifndef _DEBUG
	min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif
		memcpy(l_adr, adr, sizeof(adr));
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		xmss_node_(PK_root2,
			SK_seed, 0, H_ - 1,
			PK_seed,
#ifndef SHAKE
			PK_seed_n,
#endif
			l_adr);


#ifndef _DEBUG
		tacts = __rdtsc() - tacts;

		if (tacts < min_tacts)
			min_tacts = tacts;
	}
	printf("xmss_node_ time = %I64d\n", min_tacts);
#endif
	int res = 0;
	for (i = 0; i < FIPS205_N; ++i)
	{
		if (PK_root1[i] != PK_root2[i])
			res = 1;

	}
	printf("xmss_node and xmss_node_ %s\n", res == 0 ? "OK" : "ERROR");


	//#ifndef _DEBUG
	//	min_tacts = 0xFFFFFFFFFFFFFFFF;
	//	for (i = 0; i < 16; ++i)
	//	{
	//#endif
	//		memcpy(l_adr, adr, sizeof(adr));
	//#ifndef _DEBUG
	//		tacts = __rdtsc();
	//#endif
	//		/*
	//		void xmss_node_not_recurse__(
	//	uint8_t* PK_root,
	//	const uint8_t* SK_seed,
	//	#ifdef SHAKE
	//		const uint8_t* PK_seed,
	//	#else
	//		const void* PK_seed,
	//		const void* PK_seed_n,
	//	#endif
	//	uint8_t* adr
	//		*/
	//		xmss_node_not_recurse__(PK_root2,
	//			SK_seed, /*H_ - 1,*/
	//			PK_seed,
	//#ifndef SHAKE
	//			PK_seed_n,
	//#endif
	//			l_adr);
	//
	//
	//#ifndef _DEBUG
	//		tacts = __rdtsc() - tacts;
	//
	//		if (tacts < min_tacts)
	//			min_tacts = tacts;
	//	}
	//	printf("xmss_node_not_recurse__ time = %I64d\n", min_tacts);
	//#endif
	//	//int res = 0;
	//	for (i = 0; i < FIPS205_N; ++i)
	//	{
	//		if (PK_root1[i] != PK_root2[i])
	//			res = 1;
	//
	//	}
	//	printf("xmss_node and xmss_node_not_recurse__ %s\n", res == 0 ? "OK" : "ERROR");
	//


		//////////////////////////////////////////////////////////////////
	/*static */uint8_t SIGtmp1[FIPS205_N * (H_ + LEN)], SIGtmp2[FIPS205_N * (H_ + LEN)];
#ifndef _DEBUG
	min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif
		memcpy(l_adr, adr, sizeof(adr));
		memcpy(l_adr32, adr32, 32);
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		//xmss_node(PK_root1, SK_seed, 0, 7, PK_seed, (PADR)l_adr);
		xmss_sign(SIGtmp1, msg, SK_seed, 6, PK_seed_, (PADR)l_adr32);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;

		if (tacts < min_tacts)
			min_tacts = tacts;
	}
	printf("xmss_sign time- %I64d\n", min_tacts);
#endif

#ifndef _DEBUG
	min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif
		memcpy(l_adr, adr, sizeof(adr));
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		xmss_sign_(SIGtmp2, msg, SK_seed, 6,
			PK_seed,
#ifndef SHAKE
			PK_seed_n,
#endif
			l_adr);


#ifndef _DEBUG
		tacts = __rdtsc() - tacts;

		if (tacts < min_tacts)
			min_tacts = tacts;
	}
	printf("xmss_sign_ time = %I64d\n", min_tacts);
#endif
	res = 0;
	for (i = 0; i < sizeof(SIGtmp2); ++i)
	{
		if (SIGtmp1[i] != SIGtmp2[i])
			res = 1;

	}
	printf("xmss_sign and xmss_sign_ %s\n", res == 0 ? "OK" : "ERROR");




	//xmss_pkFromSig_
	uint8_t pk1[FIPS205_N], pk2[FIPS205_N];
#ifndef _DEBUG

	min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif
		memcpy(l_adr, adr, sizeof(adr));
		// l_adr32
		memcpy(l_adr32, adr32, 32);

#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		//xmss_node(PK_root1, SK_seed, 0, 7, PK_seed, (PADR)l_adr);

		xmss_pkFromSig(pk1, 0, SIGtmp1, msg, PK_seed_, (PADR)l_adr32);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;

		if (tacts < min_tacts)
			min_tacts = tacts;
	}
	printf("xmss_pkFromSig time- %I64d\n", min_tacts);
#endif

#ifndef _DEBUG
	min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif
		memcpy(l_adr, adr, sizeof(adr));
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		xmss_pkFromSig_(pk2, 0, SIGtmp1, msg,

			PK_seed,
#ifndef SHAKE
			PK_seed_n,
#endif
			l_adr);


#ifndef _DEBUG
		tacts = __rdtsc() - tacts;

		if (tacts < min_tacts)
			min_tacts = tacts;
	}
	printf("xmss_pkFromSig_ time = %I64d\n", min_tacts);
#endif
	res = 0;
	for (i = 0; i < FIPS205_N; ++i)
	{
		if (pk1[i] != pk2[i])
			res = 1;

	}
	printf("xmss_pkFromSig and xmss_pkFromSig_ %s\n", res == 0 ? "OK" : "ERROR");
	return res;

}
#endif
#endif

