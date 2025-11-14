#include <stdlib.h>
#include <malloc.h>
#include "FIPS_205_internal_old.h"
#include "FIPS_205_Fors_old.h"
#include "FIPS_205_ht_old.h"
#include "FIPS_205_Hashs_old.h"

uint32_t is_predcalc_pk_256_OLD = 0;
uint32_t predcalc_pk_256_OLD[8];
#if FIPS205_N != 16
uint32_t is_predcalc_pk_512_OLD = 0;
uint64_t predcalc_pk_512_OLD[8];
#endif

void slh_keygen_internal__OLD(uint8_t* PK_root, const uint8_t* SK_seed, const uint8_t* SK_prf, const uint8_t* PK_seed_)
{
	// 1: ADRS ← toByte(0, 32) ▷ generate the public key for the top-level XMSS tree
#ifdef SHAKE
	uint8_t adr[32] = {0};
#else
	uint8_t adr[22] = { 0 };
#endif

	
	//memcpy(PK + 0, PK_seed_, FIPS205_N);

	//predcalcs_pk(PK_seed);
#ifdef SHAKE
	uint8_t* PK_seed = PK_seed_;
#else
	
	sha256_predcalc_pk(predcalc_pk_256_OLD, PK_seed_);
	
#if FIPS205_N != 16
	sha512_predcalc_pk(predcalc_pk_512_OLD, PK_seed_);
	
#endif
#endif



#ifdef SHAKE
	// 2: ADRS.setLayerAddress(𝑑 −1)
	//setLayerAddress(&adr, D - 1);
	SetAddress4(adr, LayerAddressOFFSET, D - 1);
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′,PK.seed,ADRS)
	memcpy(PK, PK_seed_, FIPS205_N);
	xmss_node_(PK + FIPS205_N, SK_seed, 0, H_, 
		PK_seed, 
		adr);
#else
	ShortSetAddress1_OLD(adr, ShortLayerAddressOFFSET_OLD, FIPS205_D - 1);
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′,PK.seed,ADRS)
	xmss_node__OLD(PK_root, SK_seed, 0, FIPS205_H_,
		predcalc_pk_256_OLD,
#if FIPS205_N == 16
		predcalc_pk_256_OLD,
#else
		predcalc_pk_512_OLD,
#endif
		adr);
#endif
		
	
	//1: ADRS ← toByte(0, 32) ▷ generate the public key for the top - level XMSS tree

		
	is_predcalc_pk_256_OLD = 1;
#if FIPS205_N != 16
	is_predcalc_pk_512_OLD = 1;
#endif

	
}

SUCCESS slh_sign_internal__OLD(uint8_t* SIG, const uint8_t* MSG, size_t MSG_len,
	const uint8_t* SK, const uint8_t* ADRand)
{
	SUCCESS success = ERROR;
	uint8_t opt_rand[FIPS205_N];
	//uint8_t R[FIPS205_N];
	uint8_t digest[FIPS205_M];
	uint8_t PK_fors[FIPS205_N];
	//uint8_t md[(K * A + 7) / 8];
	//uint8_t tmp_idxtree[(H - H / D + 7) / 8];
	//uint8_t tmp_idxleaf[(H + 8 * D - 1) / (8 * D)];
	/*uint64_t idxtree;
	uint32_t idxleaf;*/
	const uint8_t* SK_seed = SK, * SK_prf = SK + FIPS205_N;
	const uint8_t* PK_seed_ = SK + 2 * FIPS205_N, * PK_root = SK + 3 * FIPS205_N;
	const uint8_t* PK = SK + 2 * FIPS205_N;
	uint8_t* pSIG = SIG;
#ifndef SHAKE
	if (is_predcalc_pk_256_OLD == 0)
	{
		sha256_predcalc_pk(predcalc_pk_256_OLD, PK_seed_);
		is_predcalc_pk_256_OLD = 1;
	}
#if (FIPS205_N != 16) 
	if (is_predcalc_pk_512_OLD == 0)
	{
		sha512_predcalc_pk(predcalc_pk_512_OLD, PK_seed_);
		is_predcalc_pk_512_OLD = 1;
	}
#endif
#endif

	//ADR adr = { 0 };
// 1 : ADRS ← toByte(0, 32)
#ifdef SHAKE
	uint8_t adr[32] = { 0 };
#else
	uint8_t adr[22] = { 0 };
#endif

#ifdef SHAKE
	uint8_t* PK_seed = PK_seed_;
#else
	uint32_t* PK_seed = predcalc_pk_256_OLD;
#if FIPS205_N == 16
	uint32_t* PK_seed_n = predcalc_pk_256_OLD;
#else
	uint64_t* PK_seed_n = predcalc_pk_512_OLD;
#endif
#endif


	// 2 : 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛𝑑 ▷ substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant
	if (ADRand)
		memcpy(opt_rand, ADRand, FIPS205_N);
	else
		memcpy(opt_rand, SK + 2 * FIPS205_N, FIPS205_N);
	// 	3 : 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀) ▷ generate randomizer
	
	//PRFmsg(R, SK + FIPS205_N, opt_rand, MSG, MSG_len);
	// 4 : SIG ← 𝑅
	size_t buf_len = 3 * FIPS205_N + MSG_len + 64;
	if (buf_len < 128)
		buf_len = 128;
	
	uint8_t* buf = malloc(buf_len);
	if (buf)
	{
		success = OK;
		PRFmsg__OLD(pSIG, SK + FIPS205_N, opt_rand, MSG, MSG_len, buf);

		//memcpy(SIG, R, FIPS205_N);
		pSIG += FIPS205_N;

		// 5 : 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀) ▷ compute message digest
		
		HMsg__OLD(digest, SIG, 
#if 0
			PK_seed_, PK_root, 
#else
			PK, 
#endif
			MSG, MSG_len, buf);
		free(buf);
		
#if 0
		uint8_t* md = digest, * tmp_idxtree = digest + (K * A + 7) / 8,
			* tmp_idxleaf = tmp_idxtree + (H - H / D + 7) / 8;
		uint64_t idxtree = toInt64(tmp_idxtree, (H - H / D + 7) / 8) & (((uint64_t)1 << (H - H / D)) - 1);
		uint32_t idxleaf = toInt32(tmp_idxleaf, ((H + 8 * D - 1) / (8 * D))) % ((uint64_t)1 << (H / D));
#else
		//uint8_t md[(K * A + 7) / 8];
		uint8_t *md = digest;
		uint32_t idxleaf;
		uint64_t idxtree = DigestParse(/*md, */&idxleaf, digest);
#endif
		
		
		// 6 : 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡[0 ∶ ⌈𝑘⋅𝑎 8 ⌉ bytes
		//11: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		//setTreeAddress(&adr, idxtree);
		// 12 : ADRS.setTypeAndClear(FORS_TREE)
		// 13 : ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
		
#ifdef SHAKE
		SetAddress8(adr, TreeAddressOFFSET, idxtree);
		SetAddressType4_0(adr, FORS_TREE);
		SetAddress4 (adr, KeyPairAddressOFFSET, idxleaf);
#else
		ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET_OLD, idxtree);
		ShortSetAddressType1_OLD(adr, FORS_TREE);
		ShortSetAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, idxleaf);
#endif
		// 14 :SIGfors ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS) 
		// 15: SIG ← SIG || SIG𝐹 𝑂𝑅𝑆	
				
		uint8_t* SIGFORS = pSIG;
		//pSIG = fors_sign(pSIG, md, SK_seed, PK_seed, &adr);
		pSIG = fors_sign___OLD(pSIG, md, SK_seed, 
			PK_seed, 
#ifndef SHAKE
			PK_seed_n,
#endif
			adr);
		//pSIG += FIPS205_N; // ????
		// 16 : PK𝐹 𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)▷ get FORS key
		fors_pkFromSig___OLD(PK_fors, SIGFORS, md, 
			PK_seed, 
#ifndef SHAKE
			PK_seed_n,
#endif

			adr);
		// 17: SIG𝐻𝑇 ← ht_sign(PK𝐹 𝑂𝑅𝑆, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
		pSIG = ht_sign__OLD(pSIG, PK_fors, SK_seed, PK_seed,
#ifndef SHAKE
			PK_seed_n,
#endif
			idxtree, 
			idxleaf);
		if (pSIG - SIG != FIPS205_SIG_BYTES)
			success = ERROR;

		if (success == ERROR)
			memset(SIG, 0, FIPS205_SIG_BYTES);
	}
	return success;
}

SUCCESS slh_verify_internal__OLD(const uint8_t* M_, size_t M_len, const uint8_t* SIG, size_t SIG_len, const uint8_t* PK)
{
	SUCCESS success = ERROR;

	if (SIG_len == (1 + FIPS205_K * (1 + FIPS205_A) + FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N)
	{
		const uint8_t* PK_seed_ = PK, * PK_root = PK + FIPS205_N;

#ifndef SHAKE
		if (is_predcalc_pk_256_OLD == 0)
		{
			sha256_predcalc_pk(predcalc_pk_256_OLD, PK_seed_);
			is_predcalc_pk_256_OLD = 1;
		}
#if (FIPS205_N != 16) 
		if (is_predcalc_pk_512_OLD == 0)
		{
			sha512_predcalc_pk(predcalc_pk_512_OLD, PK_seed_);
			is_predcalc_pk_512_OLD = 1;
		}
#endif
#endif

#ifdef SHAKE
		uint8_t* PK_seed = PK_seed_;
#else
		uint32_t* PK_seed = predcalc_pk_256_OLD;
#if FIPS205_N == 16
		uint32_t* PK_seed_n = predcalc_pk_256_OLD;
#else
		uint64_t* PK_seed_n = predcalc_pk_512_OLD;
#endif
#endif



		const uint8_t* R = SIG;
		

		uint8_t digest[FIPS205_M];

		size_t buf_len = 3 * FIPS205_N + M_len + 64;

		if (buf_len < 128)
			buf_len = 128;

		uint8_t* buf = malloc(buf_len);

		HMsg__OLD(digest, R,
#if 0
			PK_seed_, PK_root,
#else
			PK,
#endif
			M_, M_len, buf);
		free(buf);

#if 0
		uint8_t* md = digest, * tmp_idxtree = digest + (K * A + 7) / 8,
			* tmp_idxleaf = tmp_idxtree + (H - H / D + 7) / 8;
		uint64_t idxtree = toInt64(tmp_idxtree, (H - H / D + 7) / 8) & (((uint64_t)1 << (H - H / D)) - 1);
		uint32_t idxleaf = toInt32(tmp_idxleaf, ((H + 8 * D - 1) / (8 * D))) % ((uint64_t)1 << (H / D));
#else

		uint8_t* md = digest;
		uint32_t idxleaf;
		uint64_t idxtree = DigestParse(/*md, */&idxleaf, digest);
#endif



		// 17: PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
		uint8_t PKFORS[FIPS205_N];

#ifdef SHAKE
		uint8_t adr[32] = { 0 };
		//setTreeAddress(&adr, idxtree);
		SetAddress8(adr, TreeAddressOFFSET, idxtree);
		//  15: ADRS.setTypeAndClear(FORS_TREE)
		SetAddressType4_0(adr, FORS_TREE);
		// 16: ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
		SetAddress4(adr, KeyPairAddressOFFSET, idxleaf);
#else
		uint8_t adr[22] = { 0 };
		ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET_OLD, idxtree);
		ShortSetAddressType1_OLD(adr, FORS_TREE_OLD);
		ShortSetAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, idxleaf);
#endif


		fors_pkFromSig___OLD(PKFORS, SIG + FIPS205_N, md,
			PK_seed,
#ifndef SHAKE
			PK_seed_n,
#endif
			adr);

		//const uint8_t* SIGHT = SIG + FIPS205_N + K * (1 + A) * FIPS205_N;

		success = ht_verify__OLD(PKFORS, SIG + FIPS205_N + FIPS205_K * (1 + FIPS205_A) * FIPS205_N,
			PK_seed,
#ifndef SHAKE
			PK_seed_n,
#endif
			idxtree, idxleaf, PK_root);
	}
	return success;
}