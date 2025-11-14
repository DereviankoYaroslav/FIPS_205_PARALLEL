#include "FIPS205_ht.h"
uint64_t DigestParse(uint32_t* idxleaf, const uint8_t* digest);

uint8_t* FIPS205_AVX_ht_sign(uint8_t* pSig, const uint8_t* M, const uint8_t* SK_seed,
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
	//ShortSetAddress8(adr, ShortTreeAddressOFFSET_OLD, idxtree);
	setTreeAddress(adr, idxtree);
	
	FIPS205_AVX_xmss_sign_(SIGtmp, M, SK_seed, idxleaf, PK_seed, PK_seed_n,
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
	FIPS205_AVX_xmss_pkFromSig(root, idxleaf, SIGtmp, M, PK_seed, PK_seed_n, adr);
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
		setLayerAddress(adr, (uint8_t)j);
		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		//setTreeAddress(&adr, idxtree);
		setTreeAddress(adr, (uint64_t)idxtree);
		// 11: SIG𝑡𝑚𝑝 ← xmss_sign(𝑟𝑜𝑜𝑡,SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓,PK.seed,ADRS) 12:
		FIPS205_AVX_xmss_sign_(SIGtmp, root, SK_seed, idxleaf, PK_seed, PK_seed_n, adr);
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
			FIPS205_AVX_xmss_pkFromSig(root, idxleaf, SIGtmp, root, PK_seed, PK_seed_n, adr);
#endif
		}


	}
	
	return p;
}

SUCCESS FIPS205_AVX_ht_verify(
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
	setTreeAddress(adr, idxtree);
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
	FIPS205_AVX_xmss_pkFromSig(node, idxleaf, SIGtmp, MSG,
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
		setLayerAddress(adr, (uint32_t)j);
		//setTreeAddress(&adr, idxtree);
		setTreeAddress(adr, idxtree);
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
		FIPS205_AVX_xmss_pkFromSig(node, idxleaf, SIGtmp, node, PK_seed, PK_seed_n, adr);

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
