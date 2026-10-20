#include "FIPS_205_xmss.h"

#include <omp.h>

#include "AVX512.h"


// Algorithm 9 xmss_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS
// Computes the root of a Merkle subtree of WOTS+ public keys.
//Вхід: 
// SK.seed - компонент секретного ключа, 
// 𝑖 - індекс вузла дерева, 
// 𝑧 - висота вузла, 
// PK.seed, PK_seed_n - компонет відкритого ключа або передобчислені значення
// adr - структура з інформацією.
// Вихід:
// PK_root - корень дерева, компонент відкритого ключа


void FIPS205_AVX_xmss_node(
	uint8_t* PK_root,
	const uint8_t* SK_seed,
	size_t  i,
	size_t z,
#ifdef SHAKE
	const uint8_t* PK_seed_,
#else
	const void* PK_seed_,
	const void* PK_seed_n_,
#endif
	uint8_t* adr)
{
	uint8_t lnode[FIPS205_N], rnode[FIPS205_N];
	//uint8_t temp[2][FIPS205_N];
#ifdef SHAKE
	uint8_t* PK_seed = (uint8_t*)PK_seed;
#else
	__m256i* PK_seed = (__m256i*)PK_seed_;
#if FIPS205_N == 16
	uint32_t* PK_seed_n = (uint32_t*)PK_seed_n_;
#else
	uint64_t* PK_seed_n = (uint64_t*)PK_seed_n_;
#endif
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

		setType(adr, WOTS_HASH)
			//3: ADRS.setKeyPairAddress(𝑖)
			//setKeyPairAddress(adr, (uint32_t)i);
		setKeyPairAddress(adr, (uint32_t)i);
		//setAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, (uint32_t)i);
		
		FIPS205_AVX_wots_gen_pk(
			PK_root,
			SK_seed,
			PK_seed,
			PK_seed_n_,
			adr);
#endif
	}
	//5: else
	else
	{
		//6: 𝑙𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
#ifdef SHAKE
		
		FIPS205_AVX_xmss_node (lnode, SK_seed, 2 * i, z - 1, PK_seed, adr);
		FIPS205_AVX_xmss_node (rnode, SK_seed, 2 * i + 1, z - 1, PK_seed, adr);

		//	8 : ADRS.setTypeAndClear(TREE)
		setType(adr);
		//setTypeAndClear(adr, TREE);
		//SetAddressType4_0_OLD(adr, TREE);
		
		// 9 : ADRS.setTreeHeight(𝑧)
		//setTreeHeight(adr, (uint32_t)z);
		setTreeHeight(adr, (uint32_t)z);
		//SetAddress4_OLD(adr, TreeHeightOFFSET, (uint32_t)z);
		//10 : ADRS.setTreeIndex(𝑖)
		setTreeIndex(adr, (uint32_t)i);
		//SetAddress4_OLD(adr, TreeIndexOFFSET, (uint32_t)i);
		memcpy(temp[0], lnode, FIPS205_N);
		memcpy(temp[1], rnode, FIPS205_N);
#else
		//xmss_node__OLD(lnode, SK_seed, 2 * i, z - 1, PK_seed, PK_seed_n, adr);
		FIPS205_AVX_xmss_node(
			lnode,
			SK_seed,
			2 * i,
			z - 1,
			PK_seed,
			PK_seed_n,
			adr);

		//	7 : 𝑟𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖 + 1, 𝑧 −1, PK.seed, ADRS)
		FIPS205_AVX_xmss_node(
			rnode, 
			SK_seed, 
			2 * i + 1, 
			z - 1, 
			PK_seed, 
			PK_seed_n, 
			adr);

		//	8 : ADRS.setTypeAndClear(TREE)
		setType (adr, TREE);
		//ShortSetAddressType1_OLD((uint8_t*)adr, TREE);
		// 9 : ADRS.setTreeHeight(𝑧)
		setTreeHeight(adr, (uint32_t)z);
		//ShortSetAddress4_OLD((uint8_t*)adr, ShortTreeHeightOFFSET_OLD, (uint32_t)z);
		//10 : ADRS.setTreeIndex(𝑖)
		setTreeIndex(adr, (uint32_t)i);
		//ShortSetAddress4_OLD((uint8_t*)adr, ShortTreeIndexOFFSET_OLD, (uint32_t)i);
		//memcpy(temp[0], lnode, FIPS205_N);
		//memcpy(temp[1], rnode, FIPS205_N);
#endif
		//11 : 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)

		// void H_with_predcalc (uint8_t* out, const void* pk, uint8_t* adr, const uint8_t Msg[2][N])
		//H_with_predcalc(PK_root, PK_seed_n, adr, temp);
		H_with_predcalc(
			PK_root,
			PK_seed_n,
			adr,
			lnode, 
			rnode);
//#endif

		//12 : end if
	}
	//13: return 𝑛𝑜𝑑𝑒

}

void FIPS205_AVX_xmss_sign(uint8_t* SIGtmp, const uint8_t* Msg, const uint8_t* SK_seed,
	size_t idx,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr)
{
	//Algorithm 9 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
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
	
#ifdef SHAKE
		FIPS205_AVX_xmss_node(
			auth, SK_seed, k, j,
			const uint8_t * PK_seed,
			uint8_t * adr);

		auth += FIPS205_N;
		//xmss_node_not_recurse_(auth[j], SK_seed, k, j, PK_seed, adr);
#else
		
		FIPS205_AVX_xmss_node (auth, SK_seed, k, j, PK_seed, PK_seed_n, adr);
		auth += FIPS205_N;
		
#endif

		
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
	//ShortSetAddressType1_OLD(adr, WOTS_HASH);
	setType(adr, WOTS_HASH);
		//6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	setKeyPairAddress(adr, (uint32_t)idx);
#endif
#ifdef SHAKE
	FIPS205_AVX_wots_sign ((uint8_t (*)[FIPS205_N])p, Msg, SK_seed, PK_seed, adr);
#else
	FIPS205_AVX_wots_sign((uint8_t(*)[FIPS205_N])p, Msg, SK_seed, PK_seed, adr);
#endif

}

void calc_xmss_auth(uint8_t *auth, int ind, uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed_,
#else
	const void* PK_seed_,  // block 256
	const void* PK_seed_n_,// single 256 or 512
#endif
	uint8_t* adr)
{
	uint8_t* pauth = auth;
	uint8_t cur_adr[ADR_SIZE] = { 0 };
	memcpy(cur_adr, adr, 9);
	setType1(cur_adr, WOTS_HASH);

	uint8_t roots[1 << FIPS205_H_][FIPS205_N];
	int i, k = (1 << FIPS205_H_);
	//omp_set_num_threads(8);
	//for (size_t i = 0; i < ((size_t)1 << (z /*- 1*/)); ++i)
#pragma omp parallel for
	for (i = 0; i < k; ++i)
	{
		uint8_t ca[ADR_SIZE];

		memcpy(ca, cur_adr, ADR_SIZE);
		setKeyPairAddress(ca, i);
		FIPS205_AVX_wots_gen_pk(
			roots[i],
			SK_seed,
#ifdef SHAKE
			const uint8_t * PK_seed;
#else
			PK_seed_,
			PK_seed_n_,
#endif
			ca);

	}

	size_t r = (size_t)1 << FIPS205_H_, r1 = 1;

	setType1(cur_adr, WOTS_HASH);

#if FIPS205_N == 16
	__m256i blocks_[64];
	__m256i blocks[2];
#define BLOCK_SIZE	64
	__m256i state;
#else
	__m256i blocks_[80];
	__m256i blocks[4];
	__m256i state[4];

#define BLOCK_SIZE	128
#endif

#define BYTES (BLOCK_SIZE + ADR_SIZE + FIPS205_N + FIPS205_N)
#define BYTE1	((uint8_t)((BYTES) >> 13))
#define BYTE2	((uint8_t)((BYTES) >> 5))
#define BYTE3	((uint8_t)((BYTES) << 3))
	uint8_t* pblocks = (uint8_t*)blocks;
	memcpy(pblocks, cur_adr, ADR_SIZE);
	pblocks[ADR_SIZE + FIPS205_N + FIPS205_N] = 0x80;
	memset(pblocks + ADR_SIZE + FIPS205_N + FIPS205_N + 1, 0, BLOCK_SIZE - (ADR_SIZE + FIPS205_N + FIPS205_N + 1));
	*((uint8_t*)blocks + BLOCK_SIZE - 3) = BYTE1;
	*((uint8_t*)blocks + BLOCK_SIZE - 2) = BYTE2;
	*((uint8_t*)blocks + BLOCK_SIZE - 1) = BYTE3;

	setType1(pblocks, TREE);
	memset(pblocks + 10, 0, 12);
	int t = 0;
	memcpy(pauth, roots[ind ^ 1], FIPS205_N);
	pauth += FIPS205_N;
	ind >>= 1;
	while (r != 2)
	{
		int j = 0;
		for (size_t i = 0; i < r / 2; ++i)
		{
			setTreeHeight(pblocks, r1);
			setTreeIndex(pblocks, j);
			memcpy(pblocks + ADR_SIZE, roots[2 * i], FIPS205_N);
			memcpy(pblocks + ADR_SIZE + FIPS205_N, roots[2 * i + 1], FIPS205_N);

#if FIPS205_N == 16
			blocks_[0] = _mm256_shuffle_epi8(blocks[0], maska_for_shuffle_32);
			blocks_[1] = _mm256_shuffle_epi8(blocks[1], maska_for_shuffle_32);
			memcpy(&state, (uint8_t*)PK_seed_n_, sizeof(state));
			AVX_sha256_compress((uint32_t*)&state, blocks_);
			state = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
			memcpy(roots[i], &state, FIPS205_N);
#else
			blocks_[0] = _mm256_shuffle_epi8(blocks[0], maska_for_shuffle_64);
			blocks_[1] = _mm256_shuffle_epi8(blocks[1], maska_for_shuffle_64);
			blocks_[2] = _mm256_shuffle_epi8(blocks[2], maska_for_shuffle_64);
			blocks_[3] = _mm256_shuffle_epi8(blocks[3], maska_for_shuffle_64);
			memcpy(state, (uint8_t*)PK_seed_n_, sizeof(state));
			AVX_sha512_compress((uint64_t*)state, blocks_);
			state[0] = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);
			memcpy(roots[i], &state[0], FIPS205_N);
#endif

			++j;
		}
		memcpy(pauth, roots[ind ^ 1], FIPS205_N);
		pauth += FIPS205_N;
		++r1;
		r /= 2;
		ind >>= 1;
	}


}

void FIPS205_AVX_xmss_sign_(
	uint8_t* SIGtmp, 
	const uint8_t* Msg, 
	const uint8_t* SK_seed,
	size_t idx,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr)
{
	//Algorithm 9 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
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

	calc_xmss_auth(auth, idx, SK_seed,
#ifdef SHAKE
		const uint8_t * PK_seed_,
#else
		PK_seed,  // block 256
		PK_seed_n,// single 256 or 512
#endif
		adr);

#ifdef SHAKE
	SetAddressType4_0(adr, WOTS_HASH);
	//setTypeAndClear(adr, WOTS_HASH);
	//6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	SetAddress4(adr, KeyPairAddressOFFSET, (uint32_t)idx);
	//setKeyPairAddress(adr, (uint32_t)idx);
	wots_sign_(p, Msg, SK_seed, PK_seed, adr);
#else
	//ShortSetAddressType1_OLD(adr, WOTS_HASH);
	setType(adr, WOTS_HASH);
	//6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	setKeyPairAddress(adr, (uint32_t)idx);
#endif
#ifdef SHAKE
	FIPS205_AVX_wots_sign((uint8_t(*)[FIPS205_N])p, Msg, SK_seed, PK_seed, adr);
#else
	FIPS205_AVX_wots_sign((uint8_t(*)[FIPS205_N])p, Msg, SK_seed, PK_seed, adr);
#endif

}




void FIPS205_AVX_xmss_pkFromSig(
	//uint8_t* root,
	uint8_t* node,
	size_t idx,
	const uint8_t* SIGtmp,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr)

{

#ifdef SHAKE
	
	SetAddressType4_0(adr, WOTS_HASH);
	SetAddress4(adr, KeyPairAddressOFFSET, (uint32_t)idx);
#else
	setType(adr, WOTS_HASH);
	setKeyPairAddress(adr, (uint32_t)idx);
#endif
	const uint8_t* sig = SIGtmp;
	const uint8_t* auth = SIGtmp + FIPS205_LEN * FIPS205_N, * pauth = auth;
	
	FIPS205_AVX_wots_pkFromSig(
		node, SIGtmp, Msg,
#ifdef SHAKE
		PK_seed,
#else
		PK_seed,
		PK_seed_n,
#endif
		adr);
		
#ifdef SHAKE
	SetAddressType4_0(adr, TREE);
	SetAddress4(adr, TreeIndexOFFSET, (uint32_t)idx);
#else
	//ShortSetAddressType1_OLD(adr, TREE_OLD);
	setType(adr, TREE);
	//ShortSetAddress4_OLD(adr, ShortTreeIndexOFFSET_OLD, (uint32_t)idx);
	setTreeIndex (adr, (uint32_t)idx);
#endif
			
	uint32_t k;
	
	for (k = 0; k < FIPS205_H_; ++k)
	{
		uint32_t value;
		
#ifdef SHAKE
		//setTreeHeight(adr, k + 1);
		SetAddress4(adr, TreeHeightOFFSET, k + 1);
#else
		//ShortSetAddress4_OLD(adr, ShortTreeHeightOFFSET_OLD, k + 1);
		setTreeHeight (adr, k + 1);
		value = getTreeIndex(adr);
#endif
		
		if (idx & 1)
		{
			
#ifdef SHAKE

			SetAddress4(adr, TreeIndexOFFSET, (value -1) / 2);
#else
			
			setTreeIndex(adr, (value - 1) / 2);
#endif
			
#ifdef SHAKE
			//HASH_with_predcalc(node, PK_seed, (uint8_t*)adr, temp);
			HASH_with_predcalc2(node, PK_seed, (uint8_t*)adr, pauth, node);
#else
			
			H_with_predcalc(node, PK_seed_n, adr, (uint8_t*)pauth, node);

#endif
			
		}
		// 13: else
		else
		{
			
#ifdef SHAKE
			
			SetAddress4(adr, TreeIndexOFFSET, (value ) / 2);
#else
			setTreeIndex(adr, (value ) / 2);
#endif
			
#ifdef SHAKE
			
			HASH_with_predcalc2(node, PK_seed, (uint8_t*)adr, node, pauth);
#else


			H_with_predcalc(node, PK_seed_n, adr, node, pauth);
#endif
		}
		
		pauth += FIPS205_N;
		
		idx >>= 1;

	}
}


void FIPS205_AVX_xmss_node__(
	uint8_t* root,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed_,
#else
	const void* PK_seed_,  // block 256
	const void* PK_seed_n_,// single 256 or 512
#endif
	uint8_t* adr)
{
	uint8_t cur_adr[ADR_SIZE] = {0};
	memcpy(cur_adr, adr, 9);
	setType1(cur_adr, WOTS_HASH);


	uint8_t roots[1 << FIPS205_H_][FIPS205_N];
	int i, k = (1 << FIPS205_H_);
	//for (size_t i = 0; i < ((size_t)1 << (z /*- 1*/)); ++i)
#pragma omp parallel for schedule(static)
	for ( i = 0; i < k; ++i)
	{
		uint8_t ca[ADR_SIZE];

		memcpy(ca, cur_adr, ADR_SIZE);
		setKeyPairAddress(ca, i);
		FIPS205_AVX_wots_gen_pk(
			roots[i],
			SK_seed,
#ifdef SHAKE
			const uint8_t * PK_seed;
#else
			PK_seed_,
			PK_seed_n_,
#endif
			ca);

	}
	size_t r = (size_t)1 << FIPS205_H_, r1 = 1;

	
	setType1(cur_adr, WOTS_HASH);
	
#if FIPS205_N == 16
	__m256i blocks_[64];
	__m256i blocks[2];
#define BLOCK_SIZE	64
	__m256i state;
#else
	__m256i blocks_[80];
	__m256i blocks[4];
	__m256i state[2];
	
#define BLOCK_SIZE	128
#endif
	
	#define BYTES (BLOCK_SIZE + ADR_SIZE + FIPS205_N + FIPS205_N)
#define BYTE1	((uint8_t)((BYTES) >> 13))
#define BYTE2	((uint8_t)((BYTES) >> 5))
#define BYTE3	((uint8_t)((BYTES) << 3))
	uint8_t* pblocks = (uint8_t*)blocks;
	memcpy(pblocks, cur_adr, ADR_SIZE);
	pblocks[ADR_SIZE + FIPS205_N + FIPS205_N] = 0x80;
	memset(pblocks + ADR_SIZE + FIPS205_N + FIPS205_N + 1, 0, BLOCK_SIZE - (ADR_SIZE + FIPS205_N + FIPS205_N + 1));
	*((uint8_t*)blocks + BLOCK_SIZE - 3) = BYTE1;
	*((uint8_t*)blocks + BLOCK_SIZE - 2) = BYTE2;
	*((uint8_t*)blocks + BLOCK_SIZE - 1) = BYTE3;

	setType1(pblocks, TREE);
	memset(pblocks + 10, 0, 12);
	while (r != 1)
	{
		int j = 0;
		for (size_t i = 0; i < r/2 ; ++i)
		{
			setTreeHeight(pblocks, r1);
			setTreeIndex(pblocks, j);
			memcpy(pblocks + ADR_SIZE, roots[2 * i], FIPS205_N);
			memcpy(pblocks + ADR_SIZE + FIPS205_N, roots[2 * i + 1], FIPS205_N);
		
#if FIPS205_N == 16
			blocks_[0] = _mm256_shuffle_epi8(blocks[0], maska_for_shuffle_32);
			blocks_[1] = _mm256_shuffle_epi8(blocks[1], maska_for_shuffle_32);
			memcpy(&state, (uint8_t*)PK_seed_n_, sizeof(state));
			AVX_sha256_compress((uint32_t*)&state, blocks_);
			state = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
			memcpy(roots[i], &state, FIPS205_N);
#else
			blocks_[0] = _mm256_shuffle_epi8(blocks[0], maska_for_shuffle_64);
			blocks_[1] = _mm256_shuffle_epi8(blocks[1], maska_for_shuffle_64);
			blocks_[2] = _mm256_shuffle_epi8(blocks[2], maska_for_shuffle_64);
			blocks_[3] = _mm256_shuffle_epi8(blocks[3], maska_for_shuffle_64);
			memcpy(state, (uint8_t*)PK_seed_n_, sizeof(state));
			AVX_sha512_compress((uint32_t *)state, blocks_);
			state[0] = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);
			memcpy(roots[i], &state[0], FIPS205_N);
#endif
			
			++j;
		}
		++r1;
		r /= 2;
	}
	memcpy(root, roots[0], FIPS205_N);
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

