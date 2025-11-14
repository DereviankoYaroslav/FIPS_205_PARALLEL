
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include <stdio.h>


#include <stdlib.h>
#include "FIPS_205_ht_old.h"


//uint8_t* ht_sign(uint8_t* pSig, const uint8_t* PK_fors, const uint8_t* SK_seed, const uint8_t* PK_seed,
//	uint64_t idxtree, uint32_t idxleaf)
//{
//	// Algorithm 12 ht_sign(𝑀, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//	// Input: 
//		// Message 𝑀, 
//		// private seed SK.seed, 
//		// public seed PK.seed, 
//		// tree index idxtree, 
//		// leaf index idxleaf.
//	//Output: HT signature SIG𝐻𝑇.
//	// 1: ADRS ← toByte(0, 32)
////#ifdef _GETTIME
////	uint64_t tacts = __rdtsc();
////#endif
//#ifdef SHAKE
//	uint32_t adr[8] = {0};
//#else
//	uint8_t adr[ADR_SIZE] = {0};
//#endif
//	uint8_t* p = pSig;
//	uint8_t root[FIPS205_N];
//	uint8_t SIGtmp[FIPS205_N * (H_ + FIPS205_LEN)];
//	// 2: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
//	setTreeAddress(&adr, idxtree);
//	// 3: SIG𝑡𝑚𝑝 ← xmss_sign(𝑀,SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓,PK.seed,ADRS) 
//	xmss_sign(SIGtmp, PK_fors, SK_seed, idxleaf, PK_seed, &adr);
//	// 4: SIG𝐻𝑇 ← SIG𝑡𝑚𝑝
//	//memcpy(p, SIGtmp, FIPS205_N);
//	//p += FIPS205_N;
//	memcpy(p, SIGtmp, sizeof(SIGtmp));
//	p += sizeof(SIGtmp);
//
//	// 5: 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀,PK.seed,ADRS)
//	xmss_pkFromSig(root, idxleaf, SIGtmp, PK_fors, PK_seed, &adr);
//	// 6: for 𝑗 from 1 to 𝑑 − 1 
//	size_t j;
//	for (j = 1; j < FIPS205_D; ++j)
//	{
//		// 7: 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2ℎ′ ▷ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
//		idxleaf = idxtree % ((uint64_t)1 << FIPS205_H_);
//		//8: 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′ ▷ remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
//		idxtree >>= FIPS205_H_;
//		// 9: ADRS.setLayerAddress(𝑗)
//		setLayerAddress(&adr, (uint32_t)j);
//		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
//		setTreeAddress(&adr, idxtree);
//		// 11: SIG𝑡𝑚𝑝 ← xmss_sign(𝑟𝑜𝑜𝑡,SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓,PK.seed,ADRS) 12:
//		xmss_sign(SIGtmp, root, SK_seed, idxleaf, PK_seed, &adr);
//		//12:
//		memcpy(p, SIGtmp, sizeof(SIGtmp));
//		p += sizeof(SIGtmp);
//		/*
//		13: if 𝑗 < 𝑑 −1 then
//14: 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑟𝑜𝑜𝑡,PK.seed,ADRS)
//15: end if
//		*/
//		if (j < FIPS205_D - 1)
//		{
//			xmss_pkFromSig(root, idxleaf, SIGtmp, root, PK_seed, &adr);
//		}
//
//
//	}
////#ifdef _GETTIME
////	tacts = __rdtsc() - tacts;
////	if (tacts < ht_signTime)
////		ht_signTime = tacts;
////	//printf("ht_sign time = %I64d\n", tacts);
////#endif
//	return p;
//}


uint8_t* ht_sign__OLD(uint8_t* pSig, const uint8_t* PK_fors, const uint8_t* SK_seed, 
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint64_t idxtree, 
	uint32_t idxleaf)
{
	// Algorithm 12 ht_sign(𝑀, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	// Input: 
		// Message 𝑀, 
		// private seed SK.seed, 
		// public seed PK.seed, 
		// tree index idxtree, 
		// leaf index idxleaf.
	//Output: HT signature SIG𝐻𝑇.
	// 1: ADRS ← toByte(0, 32)
//#ifdef _GETTIME
//	uint64_t tacts = __rdtsc();
//#endif

	uint8_t adr[ADR_SIZE] = { 0 };

	uint8_t* p = pSig;
	uint8_t root[FIPS205_N];
	uint8_t SIGtmp[FIPS205_N * (FIPS205_H_ + FIPS205_LEN)];
	// 2: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	//setTreeAddress(&adr, idxtree);
#ifdef SHAKE
	SetAddress8(adr, TreeAddressOFFSET, idxtree);
	// xmss_sign(SIGtmp, PK_fors, SK_seed, idxleaf, PK_seed, &adr);
	xmss_sign_(SIGtmp, PK_fors, SK_seed, idxleaf, PK_seed, adr);
	
#else
	ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET_OLD, idxtree);
	// xmss_sign(SIGtmp, PK_fors, SK_seed, idxleaf, PK_seed, &adr);
	xmss_sign__OLD(SIGtmp, PK_fors, SK_seed, idxleaf, PK_seed, PK_seed_n, 
		adr);
	
#endif
	// 3: SIG𝑡𝑚𝑝 ← xmss_sign(𝑀,SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓,PK.seed,ADRS) 
	
	// 4: SIG𝐻𝑇 ← SIG𝑡𝑚𝑝
	//memcpy(p, SIGtmp, FIPS205_N);
	//p += FIPS205_N;
	memcpy(p, SIGtmp, sizeof(SIGtmp));
	p += sizeof(SIGtmp);



	// 5: 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀,PK.seed,ADRS)
#ifdef SHAKE
	xmss_pkFromSig_(root, idxleaf, SIGtmp, PK_fors, PK_seed, adr);
#else
	xmss_pkFromSig__OLD(root, idxleaf, SIGtmp, PK_fors, PK_seed, PK_seed_n, adr);
#endif
	// 6: for 𝑗 from 1 to 𝑑 − 1 
	size_t j;
	for (j = 1; j < FIPS205_D; ++j)
	{
		// 7: 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2ℎ′ ▷ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
		idxleaf = idxtree % ((uint64_t)1 << FIPS205_H_);
		//8: 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′ ▷ remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
		idxtree >>= FIPS205_H_;
		// 9: ADRS.setLayerAddress(𝑗)
#ifdef SHAKE
		//setLayerAddress(&adr, (uint32_t)j);
		SetAddress4(adr, LayerAddressOFFSET, (uint32_t)j);
		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		//setTreeAddress(&adr, idxtree);
		SetAddress8(adr, TreeAddressOFFSET, (uint64_t)idxtree);
		// 11: SIG𝑡𝑚𝑝 ← xmss_sign(𝑟𝑜𝑜𝑡,SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓,PK.seed,ADRS) 12:
		xmss_sign_(SIGtmp, root, SK_seed, idxleaf, PK_seed, adr);
#else
		ShortSetAddress1_OLD(adr, ShortLayerAddressOFFSET_OLD, (uint8_t)j);
		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		//setTreeAddress(&adr, idxtree);
		ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET_OLD, (uint64_t)idxtree);
		// 11: SIG𝑡𝑚𝑝 ← xmss_sign(𝑟𝑜𝑜𝑡,SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓,PK.seed,ADRS) 12:
		xmss_sign__OLD(SIGtmp, root, SK_seed, idxleaf, PK_seed, PK_seed_n, adr);
#endif

		//12:
		memcpy(p, SIGtmp, sizeof(SIGtmp));
		p += sizeof(SIGtmp);
		/*
		13: if 𝑗 < 𝑑 −1 then
14: 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑟𝑜𝑜𝑡,PK.seed,ADRS)
15: end if
		*/
		if (j < FIPS205_D - 1)
		{
#ifdef SHAKE
			xmss_pkFromSig_(root, idxleaf, SIGtmp, root, PK_seed, adr);
#else
			xmss_pkFromSig__OLD(root, idxleaf, SIGtmp, root, PK_seed, PK_seed_n, adr);
#endif
		}


	}
//#ifdef _GETTIME
//	tacts = __rdtsc() - tacts;
//	if (tacts < ht_signTime)
//		ht_signTime = tacts;
//	//printf("ht_sign time = %I64d\n", tacts);
//#endif
	return p;
}



///*
//Algorithm 13 ht_verify(𝑀, SIG𝐻𝑇, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.root)
//Verifies a hypertree signature.
//	Input: 
//		Message 𝑀, 
//		signature SIG𝐻𝑇, 
//		public seedPK.seed, 
//		tree index 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 
//		leaf index 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, 
//		HT public key 
//		PK.root. 
//	Output: 
//		Boolean.
//*/
//SUCCESS ht_verify(const uint8_t* MSG, const uint8_t* SIGHT, const uint8_t* PK_seed, uint64_t idxtree, uint32_t idxleaf, const uint8_t* PK_root)
//{
//#ifdef _GETTIME
//	uint64_t tacts = __rdtsc();
//	//printf("ht_sign time = %I64d\n", tacts);
//#endif
//
//	SUCCESS success = OK;
//	// 1: ADRS ← toByte(0, 32)
//	ADR_SIZE adr = { 0 };
//	// 2: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
//	setTreeAddress(&adr, idxtree);
//	// 3: SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(0) ▷ SIG𝐻𝑇[0 ∶ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
//	uint8_t SIGtmp[(FIPS205_H_ + FIPS205_LEN) * FIPS205_N];
//	const uint8_t* p = SIGHT;
//	memcpy(SIGtmp, p, sizeof(SIGtmp));
//	p += sizeof(SIGtmp);
//	// 3: SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(0) ▷ SIG𝐻𝑇[0 ∶ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
//	uint8_t node[FIPS205_N];
//	// 4: 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀,PK.seed,ADRS)
//	xmss_pkFromSig_OLD(node, idxleaf, SIGtmp, MSG, PK_seed, &adr);
//
//	// 5: for 𝑗 from 1 to 𝑑 − 1 do
//	size_t j;
//	for (j = 1; j < D; ++j)
//	{
//		// 6: 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2ℎ′ ▷ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
//		idxleaf = idxtree % ((uint64_t)1 << H_);
//		// 7: 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′ ▷ remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
//		idxtree >>= H_;
//		// 8: ADRS.setLayerAddress(𝑗)
//		setLayerAddress(&adr, (uint32_t)j);
//		// 9: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
//		setTreeAddress(&adr, idxtree);
//		// 10: SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(𝑗) ▷ SIG𝐻𝑇[𝑗 ⋅ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛 ∶ (𝑗 + 1)(ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
//		memcpy(SIGtmp, p, sizeof(SIGtmp));
//		p += sizeof(SIGtmp);
//		// 11: 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑛𝑜𝑑𝑒,PK.seed,ADRS)
//		xmss_pkFromSig_OLD(node, idxleaf, SIGtmp, node, PK_seed, &adr);
//		//memcpy(node[0], node[1], FIPS205_N);
//		//12: end for
//
//	}
//	/*
//13: if 𝑛𝑜𝑑𝑒 = PK.root then
//14: return true
//15: else
//16: return false
//17: end if
//	*/
//	success = memcmp(node, PK_root, FIPS205_N)!= 0;
//#ifdef _GETTIME
//	tacts = __rdtsc() - tacts;
////	printf("ht_verify time = %I64d\n", tacts);
//	if (tacts < ht_verifyTime)
//		ht_verifyTime = tacts;
//#endif
//	return success;
//}

SUCCESS ht_verify__OLD(
	const uint8_t* MSG, const uint8_t* SIGHT,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint64_t idxtree, uint32_t idxleaf, const uint8_t* PK_root)
{
//#ifdef _GETTIME
//	uint64_t tacts = __rdtsc();
//	//printf("ht_sign time = %I64d\n", tacts);
//#endif

	SUCCESS success = OK;
	// 1: ADRS ← toByte(0, 32)
	uint8_t adr[ADR_SIZE] = { 0 };
#ifdef SHAKE
	
	// setTreeAddress(&adr, idxtree);
	SetAddress8(adr, TreeAddressOFFSET, idxtree);
#else
	
	// setTreeAddress(&adr, idxtree);
	ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET_OLD, idxtree);
#endif
	// 2: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	
	// 3: SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(0) ▷ SIG𝐻𝑇[0 ∶ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
	//uint8_t SIGtmp[(H_ + LEN) * FIPS205_N];
	uint8_t* SIGtmp = SIGHT;
	//const uint8_t* p = SIGHT;
	//memcpy(SIGtmp, p, sizeof(SIGtmp));
	//p += sizeof(SIGtmp);
	//p += (H_ + LEN) * FIPS205_N;
	// 3: SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(0) ▷ SIG𝐻𝑇[0 ∶ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
	uint8_t node[FIPS205_N];
	// 4: 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀,PK.seed,ADRS)
/*#ifndef _DEBUG
	uint64_t tacts, mintacts;
	mintacts = 0xFFFFFFFFFFFFFFFF;
	for (int i = 0; i < 5; ++i)
	{
		memset(adr, 0, sizeof(adr));
*/
//#ifdef SHAKE
//		SetAddress8(adr, TreeAddressOFFSET, idxtree);
//#else
//		ShortSetAddress8(adr, ShortTreeAddressOFFSET, idxtree);
//#endif
//		tacts = __rdtsc();
//#endif
#ifdef SHAKE
		xmss_pkFromSig__OLD(node, idxleaf, SIGtmp, MSG, PK_seed, adr);
#else
		xmss_pkFromSig__OLD(node, idxleaf, SIGtmp, MSG,
			PK_seed, PK_seed_n, adr);
////#if FIPS205_N == 16
////			predcalc_pk_256,
////#endif
////#if FIPS205_N == 24
////			predcalc_pk_384,
////#endif
////#if FIPS205_N == 32
////			predcalc_pk_512,
////#endif
//
//			adr);
#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < mintacts)
//			mintacts = tacts;
//	}
//	printf("xmss_pkFromSig_ type = %I64d\n", mintacts);
//#endif

	// 5: for 𝑗 from 1 to 𝑑 − 1 do
	size_t j;
	for (j = 1; j < FIPS205_D; ++j)
	{
		// 6: 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2ℎ′ ▷ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
		idxleaf = idxtree % ((uint64_t)1 << FIPS205_H_);
		// 7: 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′ ▷ remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
		idxtree >>= FIPS205_H_;
		// 8: ADRS.setLayerAddress(𝑗)
#ifdef SHAKE
		//setLayerAddress(&adr, (uint32_t)j);
		SetAddress4(adr, LayerAddressOFFSET, (uint32_t)j);
		//setTreeAddress(&adr, idxtree);
		SetAddress8(adr, TreeAddressOFFSET, idxtree);
#else
		//setLayerAddress(&adr, (uint32_t)j);
		ShortSetAddress1_OLD(adr, ShortLayerAddressOFFSET_OLD, (uint32_t)j);
		//setTreeAddress(&adr, idxtree);
		ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET_OLD, idxtree);
#endif
		// 10: SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(𝑗) ▷ SIG𝐻𝑇[𝑗 ⋅ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛 ∶ (𝑗 + 1)(ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
		//memcpy(SIGtmp, p, sizeof(SIGtmp));
		//SIGtmp = p; ///////////////////////////
		SIGtmp += (FIPS205_H_ + FIPS205_LEN) * FIPS205_N;
		//p += sizeof(SIGtmp);
		// 11: 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑛𝑜𝑑𝑒,PK.seed,ADRS)
//#ifndef _DEBUG
//		tacts = __rdtsc();
//#endif
#ifdef SHAKE
		xmss_pkFromSig_(node, idxleaf, SIGtmp, node, PK_seed, adr);
#else
		xmss_pkFromSig__OLD(node, idxleaf, SIGtmp, node, PK_seed, PK_seed_n, adr);
		
#endif 
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		printf("xmss_pkFromSig_ j = %I64d time = %I64d\n", j, tacts);
//#endif
		//memcpy(node[0], node[1], FIPS205_N);
		//12: end for

	}
	/*
13: if 𝑛𝑜𝑑𝑒 = PK.root then
14: return true
15: else
16: return false
17: end if
	*/
	success = memcmp(node, PK_root, FIPS205_N) != 0;
	return success;
}

//int testHT()
//{
//	uint64_t idx_tree;
//	uint32_t idx_leaf;
//	uint8_t SK_seed[FIPS205_N], PK_seed_[FIPS205_N], PK_root [FIPS205_N];
//	uint8_t fors[K * (A + 1) * FIPS205_N];
//#if 1
//	uint8_t digest[M], *md = digest;
//
//#else
//	uint8_t md[(K * A + 7) / 8];
//	
//#endif
//	
//	// uint8_t* fors_sign(uint8_t* FORS, const uint8_t* md, const uint8_t* SK_seed, const uint8_t* PK_seed, PADR adr);
//	/*
//	uint8_t* ht_sign(uint8_t* pSig, const uint8_t* PK_fors, const uint8_t* SK_seed, const uint8_t* PK_seed,
//	uint64_t idxtree, uint32_t idxleaf);
//	*/
//	srand(0);
//	for (int i = 0; i < FIPS205_N; ++i)
//	{
//		SK_seed[i] = rand() % 256;
//		PK_seed_[i] = rand() % 256;
//	}
//	for (int i = 0; i < M; ++i)
//		digest[i] = rand() % 256;
//
//#ifdef SHAKE
//	uint8_t adr[32] = { 0 };
//	uint8_t* PK_seed = PK_seed_;
//#else
//	uint8_t adr[22] = { 0 };
//	uint32_t PK_seed[8];
//#if FIPS205_N == 16
//	uint32_t PK_seed_n[8];
//#else
//	uint64_t PK_seed_n[8];
//#endif
//
//	predcalc_pk_sha256(PK_seed, PK_seed_);
//#if FIPS205_N == 16
//	memcpy(PK_seed_n, PK_seed, 4 * 8);
//#endif
//#if FIPS205_N == 24
//	predcalc_pk_sha512(PK_seed_n, PK_seed_);
//#endif
//#if FIPS205_N == 32
//	predcalc_pk_sha512(PK_seed_n, PK_seed_);
//#endif
//#endif
//		
//	// 2: ADRS.setLayerAddress(𝑑 −1)
//
//	
//	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′,PK.seed,ADRS)
//#ifdef SHAKE
//	SetAddress4(adr, LayerAddressOFFSET, D - 1);
//	xmss_node_(PK_root, SK_seed, 0, H_, PK_seed, adr);
//#else
//	ShortSetAddress1(adr, LayerAddressOFFSET, D - 1);
//	xmss_node_(PK_root, SK_seed, 0, H_, PK_seed, PK_seed_n, adr);
//////#if FIPS205_N == 16
////	xmss_node_(PK_root, SK_seed, 0, H_, predcalc_pk_256, predcalc_pk_256, adr);
////#endif
////#if FIPS205_N == 24
////	xmss_node_(PK_root, SK_seed, 0, H_, predcalc_pk_256, predcalc_pk_384, adr);
////#endif
////#if FIPS205_N == 32
////	xmss_node_(PK_root, SK_seed, 0, H_, predcalc_pk_256, predcalc_pk_512, adr);
////#endif
//#endif
//#if 1
//	idx_tree = DigestParse(&idx_leaf, digest);
//#else
//	idx_tree = DigestParse(md, &idx_leaf, digest);
//#endif
//#ifdef SHAKE
//
//	//setTreeAddress(adr, idx_tree);
//	// 12 : ADRS.setTypeAndClear(FORS_TREE)
//	SetAddress8(adr, TreeAddressOFFSET, idx_tree);
//	//setTypeAndClear(adr, FORS_TREE);
//	SetAddressType4_0(adr, FORS_TREE);
//	// 13 : ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//	//setKeyPairAddress(adr, idx_leaf);
//	SetAddress4(adr, KeyPairAddressOFFSET, idx_leaf);
//#else
//	ShortSetAddress8(adr, ShortTreeAddressOFFSET, idx_tree);
//	//setTypeAndClear(adr, FORS_TREE);
//	ShortSetAddressType1(adr, FORS_TREE);
//	// 13 : ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//	//setKeyPairAddress(adr, idx_leaf);
//	ShortSetAddress4(adr, ShortKeyPairAddressOFFSET, idx_leaf);
//#endif
//	uint8_t PK_fors[FIPS205_N];
//#ifdef SHAKE
//
//	fors_sign_(fors, md, SK_seed, PK_seed, adr);
//	
//	fors_pkFromSig_ (PK_fors, fors, md, PK_seed, adr);
//#else
//	fors_sign_(fors, md, SK_seed, PK_seed, PK_seed_n, adr);
//
//	fors_pkFromSig_(PK_fors, fors, md, PK_seed, PK_seed_n, adr);
//
////#if FIPS205_N == 16
////	fors_sign_(fors, md, SK_seed, predcalc_pk_256, predcalc_pk_256, adr);
////	fors_pkFromSig_(PK_fors, fors, md, predcalc_pk_256, predcalc_pk_256, adr);
////#endif
////#if FIPS205_N == 24
////	fors_sign_(fors, md, SK_seed, predcalc_pk_256, predcalc_pk_384, adr);
////	fors_pkFromSig_(PK_fors, fors, md, predcalc_pk_256, predcalc_pk_384, adr);
////#endif
////#if FIPS205_N == 32
////	fors_sign_(fors, md, SK_seed, predcalc_pk_256, predcalc_pk_512, adr);
////	fors_pkFromSig_(PK_fors, fors, md, predcalc_pk_256, predcalc_pk_512, adr);
////#endif
//#endif
//
//#ifndef _DEBUG
//	uint64_t tacts, mintacts;
//#endif
//	
//	uint8_t SIGHT1[(H + D * LEN) * FIPS205_N], SIGHT2[(H + D * LEN) * FIPS205_N];
//	
//	int i;
//#ifndef _DEBUG
//
//	mintacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		ht_sign(SIGHT1, PK_fors, SK_seed, PK_seed_, idx_tree, idx_leaf);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < mintacts)
//			mintacts = tacts;
//	}
//	printf("ht_sign time = %I64d\n", mintacts);
//
//#endif
//#ifndef _DEBUG
//
//	mintacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//		ht_sign_(SIGHT2, PK_fors, SK_seed, PK_seed, idx_tree, idx_leaf);
//#else
//		ht_sign_(SIGHT2, PK_fors, SK_seed, PK_seed, PK_seed_n, idx_tree, idx_leaf);
////#if FIPS205_N == 16
////		ht_sign_(SIGHT2, PK_fors, SK_seed, 
////			predcalc_pk_256, predcalc_pk_256, idx_tree, idx_leaf);
////
////#endif
////#if FIPS205_N == 24
////		ht_sign_(SIGHT2, PK_fors, SK_seed,
////			predcalc_pk_256, predcalc_pk_384, idx_tree, idx_leaf);
////
////#endif
////#if FIPS205_N == 32
////		ht_sign_(SIGHT2, PK_fors, SK_seed,
////			predcalc_pk_256, predcalc_pk_512, idx_tree, idx_leaf);
////
////#endif
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < mintacts)
//			mintacts = tacts;
//	}
//	printf("ht_sign_ time = %I64d\n", mintacts);
//
//
//#endif
//	int res = 0;
//	for (i = 0; i < sizeof(SIGHT2); ++i)
//	{
//		if (SIGHT1[i] != SIGHT2[i])
//			res = 1;
//	}
//
//	printf("ht_sign and ht_sign_ %s\n", res == 0 ? "OK" : "ERROR");
//
//#ifndef _DEBUG
//
//	
//	mintacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		// SUCCESS ht_verify(const uint8_t* MSG, const uint8_t* SIGHT, const uint8_t* PK_seed, uint64_t idxtree, uint32_t idxleaf, const uint8_t* PK_root)
//		res |= ht_verify(PK_fors, SIGHT2, PK_seed_, idx_tree, idx_leaf, PK_root);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < mintacts)
//			mintacts = tacts;
//	}
//	printf("ht_verify_ time = %I64d\n", mintacts);
//
//#endif
//
//#ifndef _DEBUG
//
//	res = 0;
//	mintacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 4; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//		res |= ht_verify_(PK_fors, SIGHT2, PK_seed, idx_tree, idx_leaf, PK_root);
//#else
//		res |= ht_verify_(PK_fors, SIGHT2, PK_seed, PK_seed_n, idx_tree, idx_leaf, PK_root);
////#if FIPS205_N == 16
////		res |= ht_verify_(PK_fors, SIGHT2, 
////			predcalc_pk_256, predcalc_pk_256, idx_tree, idx_leaf, PK_root);
////#endif
////
////#if FIPS205_N == 24
////		res |= ht_verify_(PK_fors, SIGHT2,
////			predcalc_pk_256, predcalc_pk_384, idx_tree, idx_leaf, PK_root);
////#endif
////#if FIPS205_N == 32
////		res |= ht_verify_(PK_fors, SIGHT2,
////			predcalc_pk_256, predcalc_pk_512, idx_tree, idx_leaf, PK_root);
////#endif
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < mintacts)
//			mintacts = tacts;
//	}
//	printf("ht_verify_ time = %I64d\n", mintacts);
//
//#endif
//
//	printf("ht_verify and ht_verify_ %s\n", res == 0 ? "OK" : "ERROR");
//	return res;
//}
