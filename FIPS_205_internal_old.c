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

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//void slh_keygen_internal_OLD(uint8_t* SK, uint8_t* PK, const uint8_t* SK_seed, const uint8_t* SK_prf, const uint8_t* PK_seed)
//{
//
//	// 1: ADRS ← toByte(0, 32) ▷ generate the public key for the top-level XMSS tree
//	ADR_OLD adr;
//
//	
//	memset(&adr, 0, sizeof(ADR_OLD));
//	memcpy(PK + 0, PK_seed, FIPS205_N);
//
//
//	
//
//	// 2: ADRS.setLayerAddress(𝑑 −1)
//	setLayerAddress_OLD(&adr, FIPS205_D - 1);
//	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′,PK.seed,ADRS)
//	xmss_node_OLD(PK + FIPS205_N, SK_seed, 0, FIPS205_H_, 
//		PK_seed, 
//		&adr);
//	
//	/*
//	#ifdef SHAKE
//	const uint8_t* PK_seed,
//#else
//	const void* PK_seed,
//	const void* PK_seed_n,
//#endif
//	*/
//	/*
//
//
//
//4: return ((SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
//	*/
//	//1: ADRS ← toByte(0, 32) ▷ generate the public key for the top - level XMSS tree
//
//	
//
//	memcpy(SK, SK_seed, FIPS205_N);
//	memcpy(SK + FIPS205_N, SK_prf, FIPS205_N);
//	memcpy(SK + 2 * FIPS205_N, PK_seed, FIPS205_N);
//	memcpy(SK + 3 * FIPS205_N, PK + FIPS205_N, FIPS205_N);
//	memcpy(PK, PK_seed, FIPS205_N);
//	
//	
//}

void slh_keygen_internal__OLD(uint8_t* PK_root, const uint8_t* SK_seed, const uint8_t* SK_prf, const uint8_t* PK_seed_)
{
	/*is_predcalc_pk_256 = 0;
#if FIPS205_N != 16
	is_predcalc_pk_512 = 0;
#endif*/
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


/*
Algorithm 19 slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
		Generates an SLH - DSA signature.
		Input: Message 𝑀, private key SK = (SK.seed, SK.prf, PK.seed, PK.root),
		(optional)additional randomness 𝑎𝑑𝑑𝑟𝑛𝑑.Output : SLH - DSA signature SIG.
*/
//SUCCESS slh_sign_internal_OLD(uint8_t* SIG, const uint8_t* MSG, size_t MSG_len,
//	const uint8_t* SK, /*size_t SK_len, */const uint8_t* ADRand)
//{
//	SUCCESS success = ERROR;
//	uint8_t opt_rand[FIPS205_N];
//	uint8_t R[FIPS205_N];
//	uint8_t digest[FIPS205_M];
//	uint8_t PK_fors[FIPS205_N];
//	uint8_t md[(FIPS205_K * FIPS205_A + 7) / 8];
//	uint8_t tmp_idxtree[(FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8];
//	uint8_t tmp_idxleaf[(FIPS205_H + 8 * FIPS205_D - 1) / (8 * FIPS205_D)];
//	uint64_t idxtree;
//	uint32_t idxleaf;
//	const uint8_t* SK_seed = SK, * SK_prf = SK + FIPS205_N;
//	const uint8_t* PK_seed = SK + 2 * FIPS205_N, * PK_root = SK + 3 * FIPS205_N;
//
//	uint8_t* pSIG = SIG;
//	ADR_OLD adr = { 0 };
//	uint8_t* buf = malloc(FIPS205_N + MSG_len);
//	if (buf)
//	{
//		success = OK;
//		/*if (SK_len != SK_BYTES)
//			return ERROR;*/
//
//			// 1 : ADRS ← toByte(0, 32)
//
//			// 2 : 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛𝑑 ▷ substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant
//		if (ADRand)
//			memcpy(opt_rand, ADRand, FIPS205_N);
//		else
//			memcpy(opt_rand, SK + 2 * FIPS205_N, FIPS205_N);
//
//		// 	3 : 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀) ▷ generate randomizer
//		// PRFmsg__OLD(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* opt_rand, const uint8_t* Msg, size_t Msg_len, uint8_t *buf)
//		PRFmsg__OLD(R, SK + FIPS205_N, opt_rand, MSG, MSG_len, buf);
//		free(buf);
//		// 4 : SIG ← 𝑅
//		memcpy(SIG, R, FIPS205_N);
//		pSIG += FIPS205_N;
//		// 5 : 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀) ▷ compute message digest
//		// SUCCESS HMsg_OLD(uint8_t* dest, const uint8_t* R, const uint8_t* PK_seed, const uint8_t* PK_root, const uint8_t* msg, size_t m_len)
//		if (HMsg_OLD(digest, R, PK_seed, PK_root, MSG, MSG_len) == ERROR)
//			goto sign_lab;
//		// 6 : 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡[0 ∶ ⌈𝑘⋅𝑎 8 ⌉ bytes
//		memcpy(md, digest, sizeof(md));
//		// 7 tmp_idx_tree
//		memcpy(tmp_idxtree, digest + sizeof(md), sizeof(tmp_idxtree));
//		// 8 tmp_idx_leaf
//		memcpy(tmp_idxleaf, digest + sizeof(md) + sizeof(tmp_idxtree), sizeof(tmp_idxleaf));
//		//	9 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← toInt(𝑡𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒, ⌈ℎ−ℎ / 𝑑 8𝑑⌉) mod 2ℎ / 𝑑
//		idxtree = toInt64(tmp_idxtree, (H - H / D + 7) / 8) & (((uint64_t)1 << (H - H / D)) - 1);
//		//idxtree = toInt64(tmp_idxtree, (H - H / D + 7) / 8);
//		////idxtree %= ((uint64_t)1 << (H - H / D));
//		//uint32_t h = H, d = D, t = h - h / d;
//
//
//		//uint64_t temp = ((uint64_t)1 << (H - H / D)) - 1;
//		//idxtree &= temp;
//
//
//
//		//10   𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← toInt(𝑡𝑚𝑝_𝑖𝑑𝑥𝑙𝑒𝑎𝑓, ⌈ ℎ
//		idxleaf = toInt32(tmp_idxleaf, ((H + 8 * D - 1) / (8 * D))) % ((uint64_t)1 << (H / D));
//		//11: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
//		setTreeAddress_OLD(&adr, idxtree);
//		// 12 : ADRS.setTypeAndClear(FORS_TREE)
//		setTypeAndClear_OLD(&adr, FORS_TREE);
//		// 13 : ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//		setKeyPairAddress_OLD(&adr, idxleaf);
//		// 14 :SIGfors ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS) 
//		// 15: SIG ← SIG || SIG𝐹 𝑂𝑅𝑆
//		uint8_t* SIGFORS = pSIG;
//		pSIG = fors_sign_OLD(pSIG, md, SK_seed, PK_seed, &adr);
//		//pSIG += FIPS205_N; // ????
//		// 16 : PK𝐹 𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)▷ get FORS key
//		fors_pkFromSig_OLD(PK_fors, SIGFORS, md, PK_seed, &adr);
//		// 17: SIG𝐻𝑇 ← ht_sign(PK𝐹 𝑂𝑅𝑆, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//		pSIG = ht_sign_OLD(pSIG, PK_fors, SK_seed, PK_seed, idxtree, idxleaf);
//		//free(buf);
//		if (pSIG - SIG != FIPS205_SIG_BYTES)
//			success = ERROR;
//	}
//
//sign_lab:
//	if (success == ERROR)
//		memset(SIG, 0, FIPS205_SIG_BYTES);
//	return success;
//}
//#if 0

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


//SUCCESS slh_verify_internal_OLD(const uint8_t* M_, size_t M_len, const uint8_t* SIG, size_t SIG_len, const uint8_t* PK)
//{
//	SUCCESS success = OK;
//
//	/*1: if | SIG | ≠(1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅𝑙𝑒𝑛)⋅𝑛 then
//		2 : return false
//		3 : end if
//		*/
//	if (SIG_len != (1 + FIPS205_K * (1 + FIPS205_A) + FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N)
//		return ERROR;
//	const uint8_t* PK_seed = PK, * PK_root = PK + FIPS205_N;
//
//	// 4: ADRS ← toByte(0, 32)
//	ADR_OLD adr = { 0 };
//
//	// 5: 𝑅 ← SIG.getR() ▷ SIG[0 ∶ 𝑛]
//	uint8_t R[FIPS205_N];
//	//uint8_t* R = SIG;
//	const uint8_t* p = SIG;
//	memcpy(R, p, FIPS205_N);
//	p += FIPS205_N;
//	// 6: SIG𝐹 𝑂𝑅𝑆 ← SIG.getSIG_FORS() ▷ SIG[𝑛 ∶ (1+𝑘(1+𝑎))⋅𝑛]
//	uint8_t SIGFORS[FIPS205_K * (1 + FIPS205_A) * FIPS205_N];
//	//uint8_t* SIGFORS = SIG + FIPS205_N;
//	memcpy(SIGFORS, p, sizeof(SIGFORS));
//	p += sizeof(SIGFORS);
//	// 7: SIG𝐻𝑇 ← SIG.getSIG_HT() ▷ SIG[(1+𝑘(1+𝑎))⋅𝑛 ∶ (1+𝑘(1+𝑎)+ℎ+𝑑 ⋅𝑙𝑒𝑛)⋅𝑛]
//	uint8_t SIGHT[(FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N];
//	//uint8_t* SIGHT = SIG + FIPS205_N + K * (1 + A) * FIPS205_N;
//	memcpy(SIGHT, p, sizeof(SIGHT));
//	// 8: 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅,PK.seed,PK.root,𝑀) ▷ compute message digest
//	uint8_t digest[FIPS205_M];
//	//H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀) ▷ compute message digest
//	// SUCCESS HMsg(uint8_t* dest, const uint8_t* R, const uint8_t* PK_seed, const uint8_t* PK_root, const uint8_t* msg, size_t m_len)
//	
//	HMsg_OLD(digest, R, PK_seed, PK_root, M_, M_len);
//	uint8_t md[(FIPS205_K * FIPS205_A + 7) / 8];
//	//uint8_t* md = digest;
//	// 9: 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎 8 ⌉ bytes
//	
//	memcpy(md, digest, sizeof(md));
//	// 10: 𝑡𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈𝑘⋅𝑎 8 ⌉] 8 ⌉ bytes 8 ⌉+⌈ℎ−ℎ/𝑑 8 ⌉+⌈ℎ−ℎ/𝑑
//	// 11: 𝑡𝑚𝑝_𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈𝑘⋅𝑎 8 ⌉ ∶ ⌈𝑘⋅𝑎 8 ⌉ + ⌈8𝑑ℎ ⌉] ▷ next ⌈8𝑑ℎ ⌉ bytes
//	uint8_t tmp_idxtree[(FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8];
//	//uint8_t* tmp_idxtree = digest + (K * A + 7) / 8;
//	uint8_t tmp_idxleaf[(FIPS205_H + 8 * FIPS205_D - 1) / (8 * FIPS205_D)];
//	//uint8_t* tmp_idxleaf = digest + (K * A + 7) / 8 + (H - H / D + 7) / 8;
//	memcpy(tmp_idxtree, digest + sizeof(md), sizeof(tmp_idxtree));
//	memcpy(tmp_idxleaf, digest + sizeof(md) + sizeof(tmp_idxtree), sizeof(tmp_idxleaf));
//	// 12: 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← toInt(𝑡𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒, ⌈ℎ−ℎ / 𝑑 8𝑑⌉) mod 2ℎ / 𝑑
//	uint64_t idxtree = toInt64(tmp_idxtree, (FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8) & (((uint64_t)1 << (FIPS205_H - FIPS205_H / FIPS205_D)) - 1);
//	//13: 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← toInt(𝑡𝑚𝑝_𝑖𝑑𝑥𝑙𝑒𝑎𝑓, ⌈ ℎ 8
//	uint32_t idxleaf = toInt32(tmp_idxleaf, sizeof(tmp_idxleaf)) % ((uint64_t)1 << (FIPS205_H / FIPS205_D));
//	// 14: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒) ▷ compute FORS public key
//
//
//	setTreeAddress_OLD(&adr, idxtree);
//	//SetAddress8(adr, TreeAddressOFFSET, idxtree);
//	setTypeAndClear_OLD(&adr, FORS_TREE);
//	setKeyPairAddress_OLD(&adr, idxleaf);
//
//	// 17: PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
//	uint8_t PKFORS[FIPS205_N];
//	fors_pkFromSig_OLD(PKFORS, SIGFORS, md,	PK_seed, &adr);
//	
//	return ht_verify_OLD(PKFORS, SIGHT, PK_seed, idxtree, idxleaf, PK_root);
//
//}


SUCCESS slh_verify_internal__OLD(const uint8_t* M_, size_t M_len, const uint8_t* SIG, size_t SIG_len, const uint8_t* PK)
{
	SUCCESS success = ERROR;



	/*1: if | SIG | ≠(1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅𝑙𝑒𝑛)⋅𝑛 then
		2 : return false
		3 : end if
		*/
	/*if (SIG_len != (1 + K * (1 + A) + H + D * LEN) * FIPS205_N)
		return ERROR;*/
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
//#else
//		return ht_verify_(PKFORS, SIGHT,
//			PK_seed,
//
//#ifndef SHAKE
//			PK_seed_n,
//#endif
//			idxtree, idxleaf, PK_root);
//#endif
}


//int test_internal()
//{
//	uint8_t SK1[4 * FIPS205_N], PK1[2 * FIPS205_N], SK_seed[FIPS205_N], SK_prf[FIPS205_N], PK_seed_[FIPS205_N];
//	uint8_t SK2[4 * FIPS205_N], PK2[2 * FIPS205_N];
//	uint8_t seed[FIPS205_N];
//	uint8_t msg[1983];
//	size_t msg_len = 1983;
//	static uint8_t sig1[SIG_BYTES], sig2[SIG_BYTES];
//
//	int i;
//	srand(0);
//	for (i = 0; i < FIPS205_N; ++i)
//	{
//		SK_seed[i] = rand() % 256;
//		SK_prf[i] = rand() % 256;
//		PK_seed_[i] = rand() % 256;
//		seed [i] = rand() % 256;
//	}
//	for (i = 0; i < msg_len; ++i)
//		msg[i] = rand() % 256;
//
////#ifdef SHAKE
////	uint8_t* PK_seed = PK_seed_;
////#else
////	uint32_t PK_seed[8];
////#if FIPS205_N == 16
////	uint32_t PK_seed_n[8];
////#else
////	uint64_t PK_seed_n[8];
////#endif
////	predcalcs_pk(PK_seed, PK_seed_n, PK_seed_);
////#endif
//
//
//#ifndef _DEBUG
//	uint64_t tacts, min_tacts;
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 5; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		slh_keygen_internal(SK1, PK1, SK_seed, SK_prf, PK_seed_);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("slh_keygen_internal time = %I64d\n", min_tacts);
//#endif
//	
//#ifndef _DEBUG
//	
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 5; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		slh_keygen_internal_(SK2, PK2, SK_seed, SK_prf, PK_seed_);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("slh_keygen_internal_ time = %I64d\n", min_tacts);
//#endif
//	int res = memcmp(SK1, SK2, sizeof(SK1));
//	printf("slh_keygen_internal and slh_keygen_internal_ %s\n", res == 0 ? "OK" : "ERROR");
//	////
//
//#ifndef _DEBUG
//	
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 5; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		slh_sign_internal(sig1, msg, msg_len, SK1, seed);
//		
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("slh_sign_internal time = %I64d\n", min_tacts);
//#endif
//
//#ifndef _DEBUG
//
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 5; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		slh_sign_internal_(sig2, msg, msg_len, SK1, seed);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("slh_sign_internal_ time = %I64d\n", min_tacts);
//#endif
//	res = memcmp(sig1, sig2, sizeof(sig1));
//	printf("slh_sign_internal and slh_sign_internal_ %s\n", res == 0 ? "OK" : "ERROR");
//	////
//
//#ifndef _DEBUG
//
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 5; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		res = slh_verify_internal(msg, msg_len, sig1, sizeof (sig1), PK1);
//
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("slh_verify_internal time = %I64d res = %s\n", min_tacts, res==0? "OK" : "ERROR");
//#endif
//
//#ifndef _DEBUG
//
//	min_tacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 5; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//		res = slh_verify_internal_(msg, msg_len, sig1, sizeof(sig1), PK1);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < min_tacts)
//			min_tacts = tacts;
//	}
//	printf("slh_verify_internal_ time = %I64d res = %s\n", min_tacts, res == 0 ? "OK" : "ERROR");
//#endif
//	//res = memcmp(sig1, sig2, sizeof(sig1));
//	printf("slh_verify_internal and slh_verify_internal_ %s\n", res == 0 ? "OK" : "ERROR");
//	////
//	return res;
//}
