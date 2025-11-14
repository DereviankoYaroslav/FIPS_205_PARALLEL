#include <malloc.h>


#include "FIPS_205_internal.h"
#include "Common.h"
#include "print.h"
#ifndef SHAKE
uint32_t is_predcalc_pk_256;
__m256i AVX_predcalc_pk_256;
__m256i AVX_predcalc_pk_256_[8];	// Block
#if FIPS205_N != 16
uint32_t is_predcalc_pk_512;
__m256i AVX_predcalc_pk_512[2];
__m256i AVX_predcalc_pk_512_[8]; // BLOCK

#endif
#endif
void FIPS205_keygen_internal(uint8_t* PK_root, const uint8_t* SK_seed, const uint8_t* SK_prf, const uint8_t* PK_seed_)
{
	// 1: ADRS ← toByte(0, 32)
	uint8_t adr[ADR_SIZE];
	memset(adr, 0, ADR_SIZE);
	// 2: ADRS.setLayerAddress(𝑑 −1)
	setLayerAddress(adr, FIPS205_D - 1);

#ifndef SHAKE
	if (is_predcalc_pk_256 == 0)
	{
		AVX_sha256_predcalc_pk ((uint32_t *)&AVX_predcalc_pk_256, PK_seed_);

		AVX_sha256_predcalc_pk_(AVX_predcalc_pk_256_, PK_seed_);

		is_predcalc_pk_256 = 1;
	}
#if (FIPS205_N != 16) 
	if (is_predcalc_pk_512 == 0)
	{
		AVX_sha512_predcalc_pk((uint64_t*)AVX_predcalc_pk_512, PK_seed_);
		AVX_sha512_predcalc_pk_(AVX_predcalc_pk_512_, PK_seed_);
		is_predcalc_pk_512 = 1;
	}
#endif
#endif

	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′,PK.seed,ADRS)
	/*
	FIPS205_wots_gen_pk_new__(
		__m256i* pk,
		const uint8_t* SK_seed,
		//const __m256i* keysBlocks,
		const __m256i* state256_block,
//#if FIPS205_N > 16
//		const __m256i* state512,
//#endif
		uint8_t* adr)
	*/

	FIPS205_AVX_xmss_node__(
		PK_root,
		SK_seed,
		
#ifdef SHAKE
		PK_seed_,
#else
		AVX_predcalc_pk_256_, // Block
#if FIPS205_N == 16
		&AVX_predcalc_pk_256,
#else
		AVX_predcalc_pk_512,
#endif
#endif
		adr
	);

}

#if 1
void FIPS205_sign_internal(uint8_t* sign, const uint8_t* M, uint32_t M_len, const uint8_t* SK, uint8_t* addrng)
{
	
	const uint8_t* SK_seed = SK, * SK_prf = SK + FIPS205_N, * PK_seed_ = SK + 2 * FIPS205_N, *PK_root = SK + 3 * FIPS205_N;
	// 1: ADRS ← toByte(0, 32)
	uint8_t adr[ADR_SIZE] = { 0 };
	//uint8_t R[FIPS205_N];
	uint8_t digest[FIPS205_M];
	// 2: 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛𝑑
	uint8_t* PK = PK_seed_;
	uint8_t* opt_rand = addrng;

	uint8_t* psign = sign;
	uint8_t* buf = malloc(4 * FIPS205_N + M_len);
	uint64_t idx_tree;

	uint32_t idx_leaf;
	
	uint8_t md[FIPS205_M];
	if (buf != 0)
	{
		// predcalc PK
#ifndef SHAKE
		//if (is_predcalc_pk_256 == 0)
		{
			AVX_sha256_predcalc_pk((uint32_t*)&AVX_predcalc_pk_256, PK_seed_);

			AVX_sha256_predcalc_pk_(AVX_predcalc_pk_256_, PK_seed_);

			is_predcalc_pk_256 = 1;
		}
#if FIPS205_N != 16
		//if (is_predcalc_pk_512 == 0)
		{
			// AVX_sha512_predcalc_pk((uint64_t*)state512, PK_seed_);
			AVX_sha512_predcalc_pk((uint64_t*)AVX_predcalc_pk_512, PK_seed_);
			AVX_sha512_predcalc_pk_(AVX_predcalc_pk_512_, PK_seed_);
			is_predcalc_pk_512 = 1;
		}
#endif
#endif

		//3: 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀) ▷ generate randomizer
		AVX_PRFmsg(sign, SK_prf, opt_rand, M, M_len, buf);
		psign += FIPS205_N;
		//printf("AVX_PRFmsg \n");
		//print(FIPS205_N * 8, psign);
		/*
		4: SIG ← 𝑅
5: 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅,PK.seed,PK.root,𝑀)
		*/
		AVX_HMsg(digest, sign, PK, M, M_len, buf);
		//printf("AVX_HMsg \n");
		//print(FIPS205_M * 8, digest);
		/*
		6: 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎 8 ⌉ bytes
8⌉] ▷ first ⌈𝑘⋅𝑎 8 ⌉+⌈ℎ−ℎ/𝑑 ▷ next ⌈ℎ−ℎ/𝑑
8 ⌉ ∶ ⌈𝑘⋅𝑎
7: 𝑡𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈𝑘⋅𝑎 8 ⌉] 8 ⌉ bytes 8 ⌉+⌈ℎ−ℎ/𝑑 8 ⌉+⌈ℎ−ℎ/𝑑
8: 𝑡𝑚𝑝_𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈𝑘⋅𝑎 8 ⌉ ∶ ⌈𝑘⋅𝑎 8 ⌉ + ⌈8𝑑ℎ ⌉] ▷ next ⌈8𝑑ℎ ⌉ bytes
⌉) mod 2ℎ−ℎ/𝑑
9: 8
𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← toInt (𝑡𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒, ⌈ℎ−ℎ/𝑑 8𝑑⌉) mod 2ℎ/𝑑
		*/
		
		free(buf);
		memcpy(md, digest, (FIPS205_K * FIPS205_A + 7)/8);
		idx_tree = (uint64_t)DigestParse(&idx_leaf, digest);
		//printf("idx_tree %lld", idx_tree);
		/*
		11: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
12: ADRS.setTypeAndClear(FORS_TREE)
13: ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
		*/
		setTreeAddress(adr, idx_tree);
		setType1(adr, FORS_TREE);
		setKeyPairAddress(adr, idx_leaf);

		//printf("adr");
		//print(ADR_SIZE * 8, adr);
		
	/*
	#if FIPS205_N == 16
        p2 = FIPS205_AVX_fors_sign_(
		fors_sign2, 
		md, 
		//in64,
            SK_seed,
            //&state256, 
            state256_,  // block 256
            state256_,  // block 256 or 512
            cur_adr);
#else
        p2 = FIPS205_AVX_fors_sign_(fors_sign2, md, //in64,
            SK_seed,
            //&state256,
            state256_,
            state512_,
            cur_adr);

#endif
	*/
#ifdef SHAKE
			p2 = FIPS205_AVX_fors_sign(fors_sign2, md, SK_seed, PK_seed, cur_adr);
#else
		uint8_t* fors_sign = psign;

		/*
		uint8_t * FIPS205_AVX_fors_sign_new(uint8_t *sign, uint8_t *md, const uint8_t* SK_seed, const void* PK_256, const void* PK_256_512, uint8_t* adr)
		*/
		#if FIPS205_N == 16 
			psign = FIPS205_AVX_fors_sign_new(
				psign,
				md,
				SK_seed,
				AVX_predcalc_pk_256_,      // BLOCK for 256 
				&AVX_predcalc_pk_256,
				adr
			);     // for 256 or 512 predcalc
#else
			psign = FIPS205_AVX_fors_sign_new(
				psign,
				md,
				SK_seed,
				AVX_predcalc_pk_256_,      
				AVX_predcalc_pk_512,
				adr
			);
#endif

			//printf("fors sign");
			//print(FIPS205_K* (1 + FIPS205_A)* FIPS205_N*8, fors_sign);
// 
//#if FIPS205_N == 16 
//			psign = FIPS205_AVX_fors_sign(
//				psign,
//				md,
//				SK_seed,
//				AVX_predcalc_pk_256_,      // BLOCK for 256 
//				AVX_predcalc_pk_256_,
//				adr
//			);     // for 256 or 512 predcalc
//#else
//			psign = FIPS205_AVX_fors_sign(
//				psign,
//				md,
//				SK_seed,
//				AVX_predcalc_pk_256_,      
//				AVX_predcalc_pk_512_,
//				adr
//			);
//#endif

#endif
			// 16: PK𝐹 𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑,PK.seed,ADRS)
			uint8_t pkFromSig[FIPS205_N];
#if FIPS205_N == 16
			FIPS205_AVX_fors_pkFromSig(
			//fors_pkFromSig___OLD(
				pkFromSig,
				fors_sign,
				md,
				&AVX_predcalc_pk_256,		// one 256 0r 512
				AVX_predcalc_pk_256_,		// block 256
				AVX_predcalc_pk_256_,		// block 256, or 512
				adr);
#else
			FIPS205_AVX_fors_pkFromSig(
			//fors_pkFromSig___OLD(
				pkFromSig,
				fors_sign,
				md,
				&AVX_predcalc_pk_512,		// one 256 0r 512
				AVX_predcalc_pk_256_,		// block 256
				AVX_predcalc_pk_512_,		// block 256, or 512
				adr);
#endif

			//printf("pkSromSig = \n");
			//print(FIPS205_N * 8, pkFromSig);
			// SIG𝐻𝑇 ← ht_sign(PK𝐹 𝑂𝑅𝑆,SK.seed,PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
			psign = FIPS205_AVX_ht_sign(
				psign, 
				pkFromSig, 
				SK_seed,
#ifdef SHAKE
				const uint8_t * PK_seed,
#else
#if FIPS205_N == 16
				AVX_predcalc_pk_256_,
				&AVX_predcalc_pk_256,
#else
				AVX_predcalc_pk_256_,
				AVX_predcalc_pk_512,
#endif
#endif
				idx_tree,
				idx_leaf);
			//free(buf);

	}
	else
	{
		memset(sign, 0, FIPS205_SIG_BYTES);
	}
}

void FIPS205_sign_internal_new__(uint8_t* sign, const uint8_t* M, uint32_t M_len, const uint8_t* SK, uint8_t* addrng)
{

	const uint8_t* SK_seed = SK, * SK_prf = SK + FIPS205_N, * PK_seed_ = SK + 2 * FIPS205_N, * PK_root = SK + 3 * FIPS205_N;
	// 1: ADRS ← toByte(0, 32)
	uint8_t adr[ADR_SIZE] = { 0 };
	//uint8_t R[FIPS205_N];
	uint8_t digest[FIPS205_M];
	// 2: 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛𝑑
	uint8_t* PK = PK_seed_;
	uint8_t* opt_rand = addrng;

	uint8_t* psign = sign;
	uint8_t* buf = malloc(4 * FIPS205_N + M_len);
	uint64_t idx_tree;

	uint32_t idx_leaf;

	uint8_t md[FIPS205_M];
	if (buf != 0)
	{
		// predcalc PK
#ifndef SHAKE
		//if (is_predcalc_pk_256 == 0)
		{
			AVX_sha256_predcalc_pk((uint32_t*)&AVX_predcalc_pk_256, PK_seed_);

			AVX_sha256_predcalc_pk_(AVX_predcalc_pk_256_, PK_seed_);

			is_predcalc_pk_256 = 1;
		}
#if FIPS205_N != 16
		//if (is_predcalc_pk_512 == 0)
		{
			// AVX_sha512_predcalc_pk((uint64_t*)state512, PK_seed_);
			AVX_sha512_predcalc_pk((uint64_t*)AVX_predcalc_pk_512, PK_seed_);
			AVX_sha512_predcalc_pk_(AVX_predcalc_pk_512_, PK_seed_);
			is_predcalc_pk_512 = 1;
		}
#endif
#endif

		//3: 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀) ▷ generate randomizer
		AVX_PRFmsg(sign, SK_prf, opt_rand, M, M_len, buf);
		psign += FIPS205_N;
		//printf("AVX_PRFmsg new__ \n");
		//print(FIPS205_N * 8, psign);
		/*
		4: SIG ← 𝑅
5: 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅,PK.seed,PK.root,𝑀)
		*/
		AVX_HMsg(digest, sign, PK, M, M_len, buf);
		//printf("AVX_HMsg new__ \n");
		//print(FIPS205_M * 8, digest);
		/*
		6: 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎 8 ⌉ bytes
8⌉] ▷ first ⌈𝑘⋅𝑎 8 ⌉+⌈ℎ−ℎ/𝑑 ▷ next ⌈ℎ−ℎ/𝑑
8 ⌉ ∶ ⌈𝑘⋅𝑎
7: 𝑡𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈𝑘⋅𝑎 8 ⌉] 8 ⌉ bytes 8 ⌉+⌈ℎ−ℎ/𝑑 8 ⌉+⌈ℎ−ℎ/𝑑
8: 𝑡𝑚𝑝_𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈𝑘⋅𝑎 8 ⌉ ∶ ⌈𝑘⋅𝑎 8 ⌉ + ⌈8𝑑ℎ ⌉] ▷ next ⌈8𝑑ℎ ⌉ bytes
⌉) mod 2ℎ−ℎ/𝑑
9: 8
𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← toInt (𝑡𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒, ⌈ℎ−ℎ/𝑑 8𝑑⌉) mod 2ℎ/𝑑
		*/

		free(buf);
		memcpy(md, digest, (FIPS205_K * FIPS205_A + 7) / 8);
		idx_tree = (uint64_t)DigestParse(&idx_leaf, digest);
		//printf("idx_tree new__ %lld", idx_tree);
		/*
		11: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
12: ADRS.setTypeAndClear(FORS_TREE)
13: ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
		*/
		setTreeAddress(adr, idx_tree);
		setType1(adr, FORS_TREE);
		setKeyPairAddress(adr, idx_leaf);

		//printf("adr new__");
		//print(ADR_SIZE*8, adr);


		/*
		#if FIPS205_N == 16
			p2 = FIPS205_AVX_fors_sign_(
			fors_sign2,
			md,
			//in64,
				SK_seed,
				//&state256,
				state256_,  // block 256
				state256_,  // block 256 or 512
				cur_adr);
	#else
			p2 = FIPS205_AVX_fors_sign_(fors_sign2, md, //in64,
				SK_seed,
				//&state256,
				state256_,
				state512_,
				cur_adr);

	#endif
		*/
#ifdef SHAKE
		p2 = FIPS205_AVX_fors_sign(fors_sign2, md, SK_seed, PK_seed, cur_adr);
#else
		uint8_t* fors_sign = psign;

		/*
		uint8_t * FIPS205_AVX_fors_sign_new(uint8_t *sign, uint8_t *md, const uint8_t* SK_seed, const void* PK_256, const void* PK_256_512, uint8_t* adr)
		*/

#if FIPS205_N == 16 
		psign = FIPS205_AVX_fors_sign_new__(
			psign,
			md,
			SK_seed,
			AVX_predcalc_pk_256_,      // BLOCK for 256 
			&AVX_predcalc_pk_256,
			adr
		);     // for 256 or 512 predcalc
#else
		psign = FIPS205_AVX_fors_sign_new__(
			psign,
			md,
			SK_seed,
			AVX_predcalc_pk_256_,
			AVX_predcalc_pk_512,
			adr
		);
#endif

		//printf("fors sign new__");
		//print(FIPS205_K* (1 + FIPS205_A)* FIPS205_N * 8, fors_sign);
		// 
		//#if FIPS205_N == 16 
		//			psign = FIPS205_AVX_fors_sign(
		//				psign,
		//				md,
		//				SK_seed,
		//				AVX_predcalc_pk_256_,      // BLOCK for 256 
		//				AVX_predcalc_pk_256_,
		//				adr
		//			);     // for 256 or 512 predcalc
		//#else
		//			psign = FIPS205_AVX_fors_sign(
		//				psign,
		//				md,
		//				SK_seed,
		//				AVX_predcalc_pk_256_,      
		//				AVX_predcalc_pk_512_,
		//				adr
		//			);
		//#endif

#endif
			// 16: PK𝐹 𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹 𝑂𝑅𝑆, 𝑚𝑑,PK.seed,ADRS)
		uint8_t pkFromSig[FIPS205_N];
#if FIPS205_N == 16
		FIPS205_AVX_fors_pkFromSig_new__(
			//fors_pkFromSig___OLD(
			pkFromSig,
			fors_sign,
			md,
			&AVX_predcalc_pk_256,		// one 256 0r 512
			&AVX_predcalc_pk_256,		// block 256
			//AVX_predcalc_pk_256_,		// block 256, or 512
			adr);
#else
		FIPS205_AVX_fors_pkFromSig_new__(
			//fors_pkFromSig___OLD(
			pkFromSig,
			fors_sign,
			md,
			&AVX_predcalc_pk_512,		// one 256 0r 512
			&AVX_predcalc_pk_256,		// block 256
			//AVX_predcalc_pk_512_,		// block 256, or 512
			adr);
#endif

		//printf("pkSromSig_new__ = \n");
		//print(FIPS205_N*8, pkFromSig);
		// SIG𝐻𝑇 ← ht_sign(PK𝐹 𝑂𝑅𝑆,SK.seed,PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
		psign = FIPS205_AVX_ht_sign(
			psign,
			pkFromSig,
			SK_seed,
#ifdef SHAKE
			const uint8_t * PK_seed,
#else
#if FIPS205_N == 16
			AVX_predcalc_pk_256_,
			&AVX_predcalc_pk_256,
#else
			AVX_predcalc_pk_256_,
			AVX_predcalc_pk_512,
#endif
#endif
			idx_tree,
			idx_leaf);
		//free(buf);

	}
	else
	{
		memset(sign, 0, FIPS205_SIG_BYTES);
	}
}
#endif



SUCCESS FIPS205_verify_internal(const uint8_t* M, uint32_t M_len, const uint8_t* SIG, uint32_t SIG_len, const uint8_t* PK)
{
	/*
	1: if |SIG| ≠ (1+𝑘(1+𝑎)+ℎ+𝑑 ⋅𝑙𝑒𝑛)⋅𝑛 then
2: return false
3: end if
	*/
	SUCCESS success = ERROR;
	uint8_t* buf = malloc(4 * FIPS205_N + M_len);
		
	if (buf &&
		SIG_len == (1 + FIPS205_K * (1 + FIPS205_A) + FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N)
	{
		
		//uint8_t* PK_seed_ = PK;
#ifndef SHAKE
		//if (is_predcalc_pk_256 == 0)
		{
			AVX_sha256_predcalc_pk((uint32_t*)&AVX_predcalc_pk_256, PK);

			AVX_sha256_predcalc_pk_(AVX_predcalc_pk_256_, PK);

			is_predcalc_pk_256 = 1;
		}
#if FIPS205_N != 16
		//if (is_predcalc_pk_512 == 0)
		{
			// AVX_sha512_predcalc_pk((uint64_t*)state512, PK_seed_);
			AVX_sha512_predcalc_pk((uint64_t*)AVX_predcalc_pk_512, PK);
			AVX_sha512_predcalc_pk_(AVX_predcalc_pk_512_, PK);
			is_predcalc_pk_512 = 1;
		}
#endif
#endif
		
		//𝑅 ← SIG.getR() ▷ SIG[0 ∶ 𝑛]
		uint8_t* R = SIG;
		// SIG𝐹 𝑂𝑅𝑆 ← SIG.getSIG_FORS()
		uint8_t* SIG_FORS = SIG + FIPS205_N;
		// 7: SIG𝐻𝑇 ← SIG.getSIG_HT()
		uint8_t* SIG_HT = SIG + FIPS205_N + FIPS205_K * (1 + FIPS205_A) * FIPS205_N;
		// 8: 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅,PK.seed,PK.root,𝑀)
		uint8_t digest[FIPS205_M], *md = digest;

		AVX_HMsg(digest, SIG, PK, M, M_len, buf);
		free(buf);
		//memcpy(md, digest, FIPS205_M);
		uint32_t idx_leaf;
		uint64_t idx_tree = (uint64_t)DigestParse(&idx_leaf, digest);
		uint8_t adr[ADR_SIZE] = { 0 };
		/*
		14: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒) ▷ compute FORS public key
15: ADRS.setTypeAndClear(FORS_TREE)
16: ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
		
		*/
		setTreeAddress(adr, idx_tree);
		setType1(adr, FORS_TREE);
		setKeyPairAddress(adr, idx_leaf);
		uint8_t pkFromSig[FIPS205_N];
		/*
		fors_pkFromSig___OLD(uint8_t* PK_fors, const uint8_t* SIGfors, const uint8_t* md, const

	void* PK_seed_,
#ifndef SHAKE
	void* PK_seed_n,
#endif
	uint8_t* adr)
		*/

//#if FIPS205_N == 16
//		fors_pkFromSig___OLD(
//			pkFromSig,
//			SIG_FORS,
//			md,
//			&AVX_predcalc_pk_256,		
//			&AVX_predcalc_pk_256,		
//			adr);
//#else
//		fors_pkFromSig___OLD(
//			pkFromSig,
//			SIG_FORS,
//			md,
//			&AVX_predcalc_pk_256,		
//			&AVX_predcalc_pk_512,
//			adr);
//#endif

#if FIPS205_N == 16
		FIPS205_AVX_fors_pkFromSig(
			pkFromSig,
			SIG_FORS,
			md,
			&AVX_predcalc_pk_256,		// one 256 0r 512
			AVX_predcalc_pk_256_,		// block 256
			AVX_predcalc_pk_256_,		// block 512
			adr);
#else
		FIPS205_AVX_fors_pkFromSig(
			pkFromSig,
			SIG_FORS,
			md,
			&AVX_predcalc_pk_512,		// one 256 0r 512
			AVX_predcalc_pk_256_,		// block 256
			AVX_predcalc_pk_512_,		// block 512
			adr);
#endif
		success = FIPS205_AVX_ht_verify(
			pkFromSig,
			SIG_HT,
#ifdef SHAKE
			const uint8_t * PK_seed,
#else
#if FIPS205_N == 16
			AVX_predcalc_pk_256_,
			&AVX_predcalc_pk_256,
#else
			AVX_predcalc_pk_256_,
			&AVX_predcalc_pk_512,
#endif
#endif
			idx_tree, idx_leaf, PK + FIPS205_N);


	}
	return success;

}

SUCCESS FIPS205_verify_internal_new__(const uint8_t* M, uint32_t M_len, const uint8_t* SIG, uint32_t SIG_len, const uint8_t* PK)
{
	/*
	1: if |SIG| ≠ (1+𝑘(1+𝑎)+ℎ+𝑑 ⋅𝑙𝑒𝑛)⋅𝑛 then
2: return false
3: end if
	*/
	SUCCESS success = ERROR;
	uint8_t* buf = malloc(4 * FIPS205_N + M_len);

	if (buf &&
		SIG_len == (1 + FIPS205_K * (1 + FIPS205_A) + FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N)
	{

		//uint8_t* PK_seed_ = PK;
#ifndef SHAKE
		//if (is_predcalc_pk_256 == 0)
		{
			AVX_sha256_predcalc_pk((uint32_t*)&AVX_predcalc_pk_256, PK);

			AVX_sha256_predcalc_pk_(AVX_predcalc_pk_256_, PK);

			is_predcalc_pk_256 = 1;
		}
#if FIPS205_N != 16
		//if (is_predcalc_pk_512 == 0)
		{
			// AVX_sha512_predcalc_pk((uint64_t*)state512, PK_seed_);
			AVX_sha512_predcalc_pk((uint64_t*)AVX_predcalc_pk_512, PK);
			AVX_sha512_predcalc_pk_(AVX_predcalc_pk_512_, PK);
			is_predcalc_pk_512 = 1;
		}
#endif
#endif

		//𝑅 ← SIG.getR() ▷ SIG[0 ∶ 𝑛]
		uint8_t* R = SIG;
		// SIG𝐹 𝑂𝑅𝑆 ← SIG.getSIG_FORS()
		uint8_t* SIG_FORS = SIG + FIPS205_N;
		// 7: SIG𝐻𝑇 ← SIG.getSIG_HT()
		uint8_t* SIG_HT = SIG + FIPS205_N + FIPS205_K * (1 + FIPS205_A) * FIPS205_N;
		// 8: 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅,PK.seed,PK.root,𝑀)
		uint8_t digest[FIPS205_M], * md = digest;

		AVX_HMsg(digest, SIG, PK, M, M_len, buf);
		free(buf);
		//memcpy(md, digest, FIPS205_M);
		uint32_t idx_leaf;
		uint64_t idx_tree = (uint64_t)DigestParse(&idx_leaf, digest);
		uint8_t adr[ADR_SIZE] = { 0 };
		/*
		14: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒) ▷ compute FORS public key
15: ADRS.setTypeAndClear(FORS_TREE)
16: ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)

		*/
		setTreeAddress(adr, idx_tree);
		setType1(adr, FORS_TREE);
		setKeyPairAddress(adr, idx_leaf);
		uint8_t pkFromSig[FIPS205_N];
		/*
		fors_pkFromSig___OLD(uint8_t* PK_fors, const uint8_t* SIGfors, const uint8_t* md, const

	void* PK_seed_,
#ifndef SHAKE
	void* PK_seed_n,
#endif
	uint8_t* adr)
		*/

		//#if FIPS205_N == 16
		//		fors_pkFromSig___OLD(
		//			pkFromSig,
		//			SIG_FORS,
		//			md,
		//			&AVX_predcalc_pk_256,		
		//			&AVX_predcalc_pk_256,		
		//			adr);
		//#else
		//		fors_pkFromSig___OLD(
		//			pkFromSig,
		//			SIG_FORS,
		//			md,
		//			&AVX_predcalc_pk_256,		
		//			&AVX_predcalc_pk_512,
		//			adr);
		//#endif

#if FIPS205_N == 16
		FIPS205_AVX_fors_pkFromSig_new__(
			pkFromSig,
			SIG_FORS,
			md,
			&AVX_predcalc_pk_256,		// one 256 0r 512
			&AVX_predcalc_pk_256,		// one 256
			//AVX_predcalc_pk_256_,		// block 512
			adr);
#else
		FIPS205_AVX_fors_pkFromSig_new__(
			pkFromSig,
			SIG_FORS,
			md,
			&AVX_predcalc_pk_512,		// one 256 0r 512
			&AVX_predcalc_pk_256,		// block 256
			//AVX_predcalc_pk_512_,		// block 512
			adr);
#endif
		success = FIPS205_AVX_ht_verify(
			pkFromSig,
			SIG_HT,
#ifdef SHAKE
			const uint8_t * PK_seed,
#else
#if FIPS205_N == 16
			AVX_predcalc_pk_256_,
			&AVX_predcalc_pk_256,
#else
			AVX_predcalc_pk_256_,
			&AVX_predcalc_pk_512,
#endif
#endif
			idx_tree, idx_leaf, PK + FIPS205_N);


	}
	return success;

}