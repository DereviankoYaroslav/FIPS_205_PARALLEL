#include "FIPS205_WOTS.h"
#include "FIPS205_WOTS.h"
#include "FIPS_205_Adr.h"
#include "Common.h"
#if FIPS205_N != 16
#include "SHA512.h"
#include "AVX512.h"
#endif

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


// Оновлення ключа в блоці завдовжки 64 байта
void replace_key(__m256i* dest_, __m256i key_)
{
	

	dest_[0] = _mm256_or_si256(_mm256_andnot_si256(KEY_MASKA0_, dest_[0]), AVX2_sll22(key_));
	
	dest_[1] = _mm256_or_si256(
		_mm256_andnot_si256(KEY_MASKA1_, dest_[1]),
		_mm256_and_si256(KEY_MASKA1_, 
			_mm256_alignr_epi8(
				_mm256_permute2x128_si256(key_, key_, 1), key_, 10)));

	

}

//// Перетворення блоків, кожний блок містить 8 ключів, в масив з (FIPS205_LEN + 7) ключів в AVX форматі
void convert_to_m256_block_keys(__m256i *keys, __m256i* block_keys)
{
	__m256i temp;
	uint32_t* block_keys_32 = (uint32_t*)block_keys;
	int i, j, k = 0;

	for (i = 0; i < (FIPS205_LEN + 7) / 8 ; ++i)
	{
		block_keys_32 = (uint32_t*)block_keys;
		for (j = 0; j < 8; ++j)
		{
			temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
			keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);

			//memcpy(key[k++], temp.m256i_i8, FIPS205_N);
			//block_keys_32++;

		}
		block_keys += 8;
	}

}

void convert_to_m256_block_keys_(uint8_t *keys, __m256i* block_keys)
{
	__m256i temp;
	uint8_t* pkeys = keys;
	uint32_t* block_keys_32 = (uint32_t*)block_keys;
	int i, j, k = 0;

	//for (i = 0; i < (FIPS205_LEN + 7) / 8; ++i)
	for (i = 0; i < (FIPS205_LEN + 7) / 8; ++i)
	{
		block_keys_32 = (uint32_t*)block_keys;
		for (j = 0; j < 8; ++j)
		{
			temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
			temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);

			memcpy(pkeys, &temp, FIPS205_N);
			pkeys += FIPS205_N;
			//block_keys_32++;

		}
		block_keys += 8;
	}


}

// Перетворення вхідних даних для гешування в блоки для паралельного гешування
void create_blocks_for_in64(__m256i* blocks, __m256i* in64)
{

	__m256i temp[16];

#if 1
	for (int i = 0; i < 16; ++i)
#else
	for (int i = 0; i < 4; ++i)
#endif

		temp[i] = _mm256_shuffle_epi8(in64[i], maska_for_shuffle_32);	// key after shuffle
#if 0
	memcpy(temp + 4, temp, 4 * sizeof(__m256i));
	memcpy(temp + 8, temp, 8 * sizeof(__m256i));
#endif
	uint32_t* temp32 = (uint32_t*)temp;

	for (int i = 0; i < 16; ++i)
	{
		blocks[i] = _mm256_i32gather_epi32((const int*)temp32, idx16, 4);
		++temp32;
	}
}


// Відновлення блоків для 8 ключей новими ключами
void replace_blocks_key8__(__m256i blockdest_[16], __m256i blockkey256[8])
{
	//__m256i key01_const = _mm256_setr_epi16(0, 0xFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	__m256i keylow_const = _mm256_set1_epi32(0x0000FFFF);
	__m256i keyhigh_const = _mm256_set1_epi32(0xFFFF0000);
	__m256i keylowhigh_const = _mm256_set1_epi32(0xFFFFFFFF);
	__m256i temp, temp_;
	int j = 0;
#if FIPS205_N == 16
#define LAST_KEY_BLOCK	3
#define LAST_DEST_BLOCK	9
#elif FIPS205_N == 24
#define LAST_KEY_BLOCK	5
#define LAST_DEST_BLOCK	11
#else
#define LAST_KEY_BLOCK	7
#define LAST_DEST_BLOCK	13
#endif

	
		// 5
#if 1
	temp = _mm256_and_si256(blockkey256[0], keyhigh_const);// 0 comp for 8 keys
	temp = _mm256_srli_epi32(temp, 16);
	blockdest_[5] = _mm256_andnot_si256(keylow_const, blockdest_[5]);
	blockdest_[5] = _mm256_or_si256(temp, blockdest_[5]);

	temp = _mm256_and_si256(blockkey256[0], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256[1], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2

	temp = _mm256_or_si256(temp, temp_);
	blockdest_[6] = _mm256_andnot_si256(keylowhigh_const, blockdest_[6]);
	blockdest_[6] = _mm256_or_si256(temp, blockdest_[6]);

	temp = _mm256_and_si256(blockkey256[1], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256[2], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[7] = _mm256_or_si256(temp, temp_);
	
	temp = _mm256_and_si256(blockkey256[2], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256[3], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[8] = _mm256_or_si256(temp, temp_);
#else
	//temp = _mm256_and_si256(blockkey256[0], keyhigh_const);// 0 comp for 8 keys
	temp = _mm256_srli_epi32(_mm256_and_si256(blockkey256[0], keyhigh_const), 16);
	//blockdest_[5] = _mm256_andnot_si256(keylow_const, blockdest_[5]);
	blockdest_[5] = _mm256_or_si256(temp, _mm256_andnot_si256(keylow_const, blockdest_[5]));

	temp = 
		_mm256_or_si256(
			_mm256_slli_epi32(_mm256_and_si256(blockkey256[0], keylow_const), 16),
			_mm256_srli_epi32(_mm256_and_si256(blockkey256[1], keyhigh_const), 16)
		);
	//blockdest_[6] = _mm256_andnot_si256(keylowhigh_const, blockdest_[6]);
	blockdest_[6] = _mm256_or_si256(
		_mm256_or_si256(
			_mm256_slli_epi32(_mm256_and_si256(blockkey256[0], keylow_const), 16),
			_mm256_srli_epi32(_mm256_and_si256(blockkey256[1], keyhigh_const), 16)
		),
		_mm256_andnot_si256(keylowhigh_const, blockdest_[6])
	);

	blockdest_[7] = _mm256_or_si256(
		_mm256_slli_epi32(temp = _mm256_and_si256(blockkey256[1], keylow_const), 16), 
		_mm256_srli_epi32(_mm256_and_si256(blockkey256[2], keyhigh_const), 16)
	);

	blockdest_[8] = _mm256_or_si256(
		_mm256_slli_epi32(_mm256_and_si256(blockkey256[2], keylow_const), 16), 
		_mm256_srli_epi32(_mm256_and_si256(blockkey256[3], keyhigh_const), 16));
#endif

#if FIPS205_N > 16
	temp = _mm256_and_si256(blockkey256[3], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256[4], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[9] = _mm256_or_si256(temp, temp_);

	temp = _mm256_and_si256(blockkey256[4], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256[5], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[10] = _mm256_or_si256(temp, temp_);

#if FIPS205_N > 24

	temp = _mm256_and_si256(blockkey256[5], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256[6], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[11] = _mm256_or_si256(temp, temp_);

	temp = _mm256_and_si256(blockkey256[6], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256[7], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[12] = _mm256_or_si256(temp, temp_);

#endif
#endif
	// write for LASTKEY
	temp = _mm256_and_si256(blockkey256[LAST_KEY_BLOCK], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2

	//temp = _mm256_srli_epi32(temp, 16);	//00k3k2
	blockdest_[LAST_DEST_BLOCK] = _mm256_andnot_si256(keyhigh_const, blockdest_[LAST_DEST_BLOCK]);
	blockdest_[LAST_DEST_BLOCK] = _mm256_or_si256(temp, blockdest_[LAST_DEST_BLOCK]);
}



// Генерація масиву секретних ключів (OLD)
void FIPS205_wots_gen_sk_old(uint8_t sk[][FIPS205_N], const uint8_t* SK_seed, const uint8_t* PK_seed, const uint8_t* Adr)
{
	uint8_t skADRS[ADR_SIZE];
	memcpy(skADRS, Adr, ADR_SIZE);
	setType(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress (Adr));
	setHashAddress(skADRS, 0);
	for (int i = 0; i < FIPS205_LEN; ++i)
	{
		setChainAddress(skADRS, i);
		PRF(sk[i], PK_seed, skADRS, SK_seed);
	}
}


// Функція chain (OLD)
void FIPS205_wots_chain_old(uint8_t* out, const uint8_t *pk, const uint8_t* in, uint8_t* Adr, int i, int s)
{
	/*
	1: 𝑡𝑚𝑝 ← 𝑋
2: for 𝑗 from 𝑖 to 𝑖 + 𝑠 − 1 do
3: ADRS.setHashAddress(𝑗)
4: 𝑡𝑚𝑝 ← F(PK.seed,ADRS, 𝑡𝑚𝑝)
5: end for
	*/
	
	memcpy(out, in, FIPS205_N);
	
	for (int j = i; j < i + s; ++j)
	{
		setHashAddress(Adr, j);
		F(out, pk, Adr, out);
	}
	
}

// Генерація масиву відкритих ключів (OLD)
void FIPS205_wots_gen_pk_old(uint8_t pk[FIPS205_LEN][FIPS205_N], const uint8_t sk[FIPS205_LEN][FIPS205_N], const uint8_t* PK_seed, uint8_t* Adr)
{
	
	for (int i = 0; i < FIPS205_LEN; ++i)
	{
		setChainAddress(Adr, i);
		FIPS205_wots_chain_old(pk[i], PK_seed, sk[i], Adr, 0, FIPS205_W - 1);
	}

}

// Генерація підпису (OLD)
void FIPS205_wots_gen_sign_old(uint8_t sign[][FIPS205_N], const uint8_t *M, const uint8_t *SK_seed, const uint8_t* PK_seed, uint8_t* Adr)
{
	uint32_t base_b[FIPS205_LEN] = {0};
	base_2b_old(base_b, M, 4, FIPS205_N * 2);
	/*
	for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
5: end for
	*/
	uint32_t csum = 0;
	for (int i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];
	// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8)
	csum = csum << ((8 - ((FIPS205_LEN2 * 4) % 8)) % 8);
	uint8_t temp[2];
	to_byte16(temp, csum);

	base_2b_old(base_b + FIPS205_LEN1, temp, 4, FIPS205_LEN2);

	/*
	8: skADRS ← ADRS ▷ copy address to create key generation key address
9: skADRS.setTypeAndClear(WOTS_PRF)
10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	*/
	uint8_t skADRS[ADR_SIZE];
	memcpy(skADRS, Adr, ADR_SIZE);
	setType(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(Adr));
	/*for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
		12: skADRS.setChainAddress(𝑖)
		13 : 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute chain 𝑖 secret value
		14 : ADRS.setChainAddress(𝑖)
		15 : 𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖], PK.seed, ADRS)▷ compute chain 𝑖 signature value
		16 : end for*/
	uint8_t sk[FIPS205_N];

	for (int i = 0; i < FIPS205_LEN; ++i)
	{
		setChainAddress(skADRS, i);
		
		PRF(sk, PK_seed, skADRS, SK_seed);
		setChainAddress(Adr, i);
		// void FIPS205_wots_chain_old(uint8_t* out, const uint8_t *pk, const uint8_t* in, uint8_t* Adr, int i, int s)
		FIPS205_wots_chain_old(sign[i], PK_seed, sk, Adr, 0, base_b[i]);
	}

}

// Формування блоку для adr та ключа
void init_in_block(__m256i* in256, const uint8_t* adr, const uint8_t* key)
{
	in256[0] = _mm256_setzero_si256();
	in256[1] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)&in256[0];
	memcpy(p, adr, ADR_SIZE);
	memcpy(p + ADR_SIZE, key, FIPS205_N);
	p[ADR_SIZE + FIPS205_N] = 0x80;
	int bytes = (64 + ADR_SIZE + FIPS205_N);
	p[62] = (uint8_t)(bytes >> 5);
	p[63] = (uint8_t)(bytes << 3);
}
// Block without key
// Формування блоку для adr та ключа = 0
void init_in_block0(__m256i* in256, const uint8_t* adr)
{
	in256[0] = _mm256_setzero_si256();
	in256[1] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)&in256[0];
	memcpy(p, adr, ADR_SIZE);
	//memcpy(p + ADR_SIZE, key, FIPS205_N);
	p[ADR_SIZE + FIPS205_N] = 0x80;
	int bytes = (64 + ADR_SIZE + FIPS205_N);
	p[62] = (uint8_t)(bytes >> 5);
	p[63] = (uint8_t)(bytes << 3);
}




// Генерація масиву секретних ключів (NEW)
void FIPS205_wots_gen_sk_new(
	__m256i* keysBlocks,
	const uint8_t* SK_seed,
	const __m256i* state256,
	//uint8_t* adr
	__m256i blocks[64]
)
{

	/*1: skADRS ← ADRS ▷ copy address to create key generation key address
		2 : skADRS.setTypeAndClear(WOTS_PRF)
		3 : skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())*/
	const int por_count = (FIPS205_LEN + 7) / 8;

	//__m256i cur_state[8]/*, cur_state_etalon[8]*/;
	__m256i* curKeys = keysBlocks;



	__m256i start_value = step1_sll16;

	for (int i = 0; i < por_count; ++i)
	{

		blocks[4] = start_value;

		start_value = _mm256_add_epi32(start_value, eight_256);

		memcpy(curKeys, state256, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;
	}
}

// Генерація масиву відкритих ключів (NEW). Цикл по порціям 
	void FIPS205_wots_gen_pk_new__(
		__m256i* pk,
		const uint8_t* SK_seed,
		//const __m256i* keysBlocks,
		const __m256i* state256_block,
//#if FIPS205_N > 16
//		const __m256i* state512,
//#endif
		uint8_t* adr)
	{

		
		__m256i in64[16];
		__m256i blocks[64];
		__m256i keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
		uint8_t skADRS[ADR_SIZE];
		memcpy(skADRS, adr, ADR_SIZE);
		setType(skADRS, WOTS_PRF);
		setKeyPairAddress(skADRS, getKeyPairAddress(adr));
		
		init_in_block(in64, skADRS, SK_seed);
		memcpy(in64 + 2, in64, 2 * sizeof(__m256));
		memcpy(in64 + 4, in64, 4 * sizeof(__m256));
		memcpy(in64 + 8, in64, 8 * sizeof(__m256));

		create_blocks_for_in64(blocks, in64);


		FIPS205_wots_gen_sk_new(
			keysBlocks,
			SK_seed,
			state256_block,
			blocks);


		

		const int por_count = (FIPS205_LEN + 7) / 8;

		__m256i* curKeys = keysBlocks;

		// Create type
		////////////////////////////////////////////////////////////////////
		blocks[2] = _mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]);

		__m256i start_value_i = step1_sll16;

		for (int i = 0; i < por_count; ++i)
		{
			blocks[4] = start_value_i;

			blocks[5] = _mm256_setzero_si256();
			
			for (int j = 0; j < FIPS205_W - 1; ++j)
			{
				replace_blocks_key8__(blocks, curKeys);
				
				memcpy(curKeys, state256_block, 8 * sizeof(__m256i));

				AVX_sha256_compress8(curKeys, blocks);

				blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));
				
			}
			curKeys += 8;

			start_value_i = _mm256_add_epi32(start_value_i, eight_256);

		}
		

		convert_to_m256_block_keys(pk, keysBlocks);
	}


	// Генерація масиву відкритих ключів (NEW). Цикл по порціям 
	void FIPS205_AVX_wots_gen_pks(
		uint8_t *pk,
		const uint8_t* SK_seed,
#ifdef SHAKE
		const uint8_t* PK_seed,
#else
		const __m256i* state256,
#endif
		uint8_t* adr)
	{


		__m256i in64[16];
		__m256i blocks[64];
		__m256i keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
		uint8_t skADRS[ADR_SIZE];
		memcpy(skADRS, adr, ADR_SIZE);
		setType(skADRS, WOTS_PRF);
		setKeyPairAddress(skADRS, getKeyPairAddress(adr));

		init_in_block(in64, skADRS, SK_seed);
		memcpy(in64 + 2, in64, 2 * sizeof(__m256));
		memcpy(in64 + 4, in64, 4 * sizeof(__m256));
		memcpy(in64 + 8, in64, 8 * sizeof(__m256));

		create_blocks_for_in64(blocks, in64);


		FIPS205_wots_gen_sk_new(
			keysBlocks,
			SK_seed,
			state256,
			blocks);




		const int por_count = (FIPS205_LEN + 7) / 8;

		__m256i* curKeys = keysBlocks;

		// Create type
		////////////////////////////////////////////////////////////////////
		blocks[2] = _mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]);

		__m256i start_value_i = step1_sll16;

		for (int i = 0; i < por_count; ++i)
		{
			blocks[4] = start_value_i;

			blocks[5] = _mm256_setzero_si256();

			for (int j = 0; j < FIPS205_W - 1; ++j)
			{
				replace_blocks_key8__(blocks, curKeys);

				memcpy(curKeys, state256, 8 * sizeof(__m256i));

				AVX_sha256_compress8(curKeys, blocks);

				blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));

			}
			curKeys += 8;

			start_value_i = _mm256_add_epi32(start_value_i, eight_256);

		}


		convert_to_m256_block_keys_(pk, keysBlocks);
	}

// Генерація масиву підписів (цикл по W)

void FIPS205_wots_gen_sig___(
	__m256i* pk,
	const uint8_t* SK_seed,
	const __m256i* state256,
#if FIPS205_N > 16
	const __m256i* state512,
#endif
	uint8_t* adr)
{

	// 
	uint8_t skADRS[ADR_SIZE];
	memcpy(skADRS, adr, ADR_SIZE);
	setType(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(adr));
	__m256i /*in64start [16], */in64[16], keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
	__m256i blocks[64];

	init_in_block(in64, skADRS, SK_seed);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);

	//FIPS205_wots_gen_sk8(/*sk256*/ keys, (__m256i*)in256, state);
	const int por_count = (FIPS205_LEN + 7) / 8;

	//__m256i cur_state[8]/*, cur_state_etalon[8]*/;
	__m256i* curKeys = keysBlocks;



	__m256i start_value = step1_sll16;

	for (int i = 0; i < por_count; ++i)
	{

		blocks[4] = start_value;

		start_value = _mm256_add_epi32(start_value, eight_256);

		memcpy(curKeys, state256, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;
	}



	// Create type
	blocks[2] = _mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]);

	for (int j = 0; j < FIPS205_W - 1; ++j)
	{
		blocks[5] = _mm256_or_si256(_mm256_andnot_si256(HashAddressClearMaska, blocks[5]), _mm256_set1_epi32(j << 16));

		__m256i start_value_i = step1_sll16;

		curKeys = keysBlocks;

		for (int i = 0; i < por_count; ++i)
		{

			blocks[4] = start_value_i;

			replace_blocks_key8__(blocks, curKeys);

			memcpy(curKeys, state256, 8 * sizeof(__m256i));

			AVX_sha256_compress8(curKeys, blocks);

			curKeys += 8;

			start_value_i = _mm256_add_epi32(start_value_i, eight_256);
		}

	}

	convert_to_m256_block_keys(pk, keysBlocks);

}

void FIPS205_wots_chain_new(uint8_t  *out, const __m256i predcalc_pk, __m256i in[2], __m256i key, int32_t i, int32_t s)
{
	__m256i temp = key;
	//*out = key;
	/*
	for 𝑗 from 𝑖 to 𝑖 + 𝑠 − 1 do
		3: ADRS.setHashAddress(𝑗)
		4 : 𝑡𝑚𝑝 ← F(PK.seed, ADRS, 𝑡𝑚𝑝)
		5 : end for
	*/

	__m256i state;
	__m256i in_[64];
	in_[0] = in[0];
	in_[1] = in[1];

	for (int32_t j = i; j < i + s; ++j)
	{
		in_[0] = in[0];
		in_[1] = in[1];

		AVXSetValue(in_[0], HASH_MASKA, j);
		replace_key(in_, temp);
		in_[0] = _mm256_shuffle_epi8(in_[0], maska_for_shuffle_32);
		in_[1] = _mm256_shuffle_epi8(in_[1], maska_for_shuffle_32);
		state = predcalc_pk;
		AVX_sha256_compress((uint32_t*)&state, in_);
		temp = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
		temp = _mm256_and_si256(temp, maska_for_N);
	}
	
	memcpy(out, &temp, FIPS205_N);


}

void FIPS205_wots_gen_sign_new(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, __m256i state256, const __m256i blocksstate256[8], uint8_t* adr)
{
	// sk
		uint32_t base_b[FIPS205_LEN];
	base_4_new(base_b, M, FIPS205_N * 2);
	/*
	for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
5: end for
	*/
	uint32_t csum = 0;
	for (int i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];
	// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8)
	//csum = csum << 4/*((8 - ((FIPS205_LEN2 * 4) % 8)) % 8)*/;
	//uint8_t temp[2];
	//to_byte16(temp, csum);
	
	/*base_b[FIPS205_LEN1] = (csum >> 12) ;
	base_b[FIPS205_LEN1+1] = (csum >> 8) & 0xFF;
	base_b[FIPS205_LEN1 + 2] = (csum >> 4) & 0xFF;*/
	base_b[FIPS205_LEN1] = (csum >> 8);
	base_b[FIPS205_LEN1 + 1] = (csum >> 4) & 0xF;
	base_b[FIPS205_LEN1 + 2] = (csum ) & 0xF;


	/*
	8: skADRS ← ADRS ▷ copy address to create key generation key address
9: skADRS.setTypeAndClear(WOTS_PRF)
10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	*/
	/*1: skADRS ← ADRS ▷ copy address to create key generation key address
		2 : skADRS.setTypeAndClear(WOTS_PRF)
		3 : skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())*/
	uint8_t skADRS[ADR_SIZE];
	memcpy(skADRS, adr, ADR_SIZE);
	setType(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(adr));
	__m256i /*in64start [16], */in64[16], keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
	__m256i blocks[64];

	init_in_block(in64, skADRS, SK_seed);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);

	//FIPS205_wots_gen_sk8(/*sk256*/ keys, (__m256i*)in256, state);
	//const int por_count = (FIPS205_M + 7) / 8;
	const int por_count = (FIPS205_LEN + 7) / 8;
		
	__m256i* curKeys = keysBlocks;
			
	__m256i curKeys_[8];
	uint32_t* cur_keys_32; // = (uint32_t*)curKeys_;


	__m256i start_value = step1_sll16;

	for (int i = 0; i < por_count; ++i)
	{

		blocks[4] = start_value;

		start_value = _mm256_add_epi32(start_value, eight_256);

		memcpy(curKeys_, blocksstate256, 8 * sizeof(__m256i));

		cur_keys_32 = (uint32_t*)curKeys_;

		AVX_sha256_compress8(curKeys_, blocks);

		for (int j = 0; j < 8; ++j)
		{
			curKeys[j] = _mm256_shuffle_epi8 (_mm256_i32gather_epi32((const int*)cur_keys_32++, idx8, 4), maska_for_shuffle_32);
			//curKeys[j] = _mm256_shuffle_epi8(curKeys[j], maska_for_shuffle_32);
		}
				
		curKeys += 8;
	}

	curKeys = keysBlocks;
	
	init_in_block(in64, adr, SK_seed);
	//in64[0] = _mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), in64[2]);
	//AVXSetValue(in64[0], CHANGE_MASKA, (adr[9]));
	for (int j = 0; j < FIPS205_LEN; ++j)
	{
		AVXSetValue(in64[0], CHANGE_MASKA, j);
		FIPS205_wots_chain_new(sign[j], state256, in64, curKeys[j], 0, base_b[j]);
	}
	
}



void FIPS205_wots_gen_sign_new_(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, const __m256i* state256, const __m256i* blockstate256, uint8_t* adr)
{
	uint32_t base_b[FIPS205_LEN];
	base_4_new(base_b, M, FIPS205_N * 2);
	/*
	for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
5: end for
	*/
	uint32_t csum = 0;
	for (int i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];
	
	//csum = csum << 4/*((8 - ((FIPS205_LEN2 * 4) % 8)) % 8)*/;
	//uint8_t temp[2];
	//to_byte16(temp, csum);
	
	base_b[FIPS205_LEN1] = (csum >> 8) ;
	base_b[FIPS205_LEN1+1] = (csum >> 4) & 0xF;
	base_b[FIPS205_LEN1 + 2] = (csum ) & 0xF;


	/*
	8: skADRS ← ADRS ▷ copy address to create key generation key address
9: skADRS.setTypeAndClear(WOTS_PRF)
10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	*/
	/*1: skADRS ← ADRS ▷ copy address to create key generation key address
		2 : skADRS.setTypeAndClear(WOTS_PRF)
		3 : skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())*/
	uint8_t skADRS[ADR_SIZE];
	memcpy(skADRS, adr, ADR_SIZE);
	setType(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(adr));
	__m256i /*in64start [16], */in64[16], keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
	__m256i blocks[64];

	init_in_block(in64, skADRS, SK_seed);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);

	//FIPS205_wots_gen_sk8(/*sk256*/ keys, (__m256i*)in256, state);
	const int por_count = (FIPS205_LEN + 7) / 8;

	//__m256i cur_state[8]/*, cur_state_etalon[8]*/;
	__m256i* curKeys = keysBlocks;

	__m256i start_value = step1_sll16;

	
	//__m256i curKeys_[8]/*, temp*/;
	uint32_t *cur_keys_32;

	__m256i sign256[FIPS205_W][(FIPS205_LEN + 7) / 8][8];

	for (int i = 0; i < por_count; ++i)
	{

		blocks[4] = start_value;

		start_value = _mm256_add_epi32(start_value, eight_256);

		memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		cur_keys_32 = (uint32_t*)curKeys;

		for (int j = 0; j < 8; ++j)
		{
			
			sign256[0][i][j] = _mm256_shuffle_epi8 (
				_mm256_i32gather_epi32((const int*)cur_keys_32++, idx8, 4), maska_for_shuffle_32);
		}

				
	
		curKeys += 8;
	}
	
	
	// Create type
	blocks[2] = _mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]);

	for (int j = 0; j < FIPS205_W - 1; ++j)
	{
		blocks[5] = _mm256_or_si256(_mm256_andnot_si256(HashAddressClearMaska, blocks[5]), _mm256_set1_epi32(j << 16));

		__m256i start_value_i = step1_sll16;

		curKeys = keysBlocks;
		
		//__m256i curKeys_[8];

		
		for (int i = 0; i < por_count; ++i)
		{

			blocks[4] = start_value_i;
		
			replace_blocks_key8__(blocks, curKeys);
			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));
			AVX_sha256_compress8(curKeys, blocks);

			//convert_to_m256_one_block_keys(curKeys_, curKeys);

			//memcpy(&sign256[j + 1][i], curKeys_, 8 * sizeof(__m256i));
			cur_keys_32 = (uint32_t*)curKeys;
			
			for (int k = 0; k < 8; ++k)
			{

				sign256[j + 1][i][k] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi32((const int*)cur_keys_32++, idx8, 4), maska_for_shuffle_32);
			}

			curKeys += 8;

			start_value_i = _mm256_add_epi32(start_value_i, eight_256);
		}

	}

	for (int i = 0; i < FIPS205_LEN; ++i)
#ifdef _MSC_VER
		memcpy(sign[i], sign256[base_b[i]][i / 8][i % 8].m256i_i8, FIPS205_N);
#else
			memcpy(sign[i], (uint8_t*)&sign256[base_b[i]][i / 8][i % 8], FIPS205_N);
#endif
}

//void FIPS205_AVX_wots_sign(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, /*const __m256i* state256, */const __m256i* blockstate256, uint8_t* adr)
void FIPS205_AVX_wots_sign(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, /*const __m256i* state256, */const __m256i* blockstate256, uint8_t* adr)
{
	uint32_t base_b[FIPS205_LEN];
	base_4_new(base_b, M, FIPS205_N * 2);
	/*
	for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
5: end for
	*/
	uint32_t csum = 0;
	for (int i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];

	//csum = csum << 4/*((8 - ((FIPS205_LEN2 * 4) % 8)) % 8)*/;
	//uint8_t temp[2];
	//toByte16(temp, csum);

	base_b[FIPS205_LEN1] = (csum >> 8);
	base_b[FIPS205_LEN1 + 1] = (csum >> 4) & 0xF;
	base_b[FIPS205_LEN1 + 2] = (csum) & 0xF;


	/*
	8: skADRS ← ADRS ▷ copy address to create key generation key address
9: skADRS.setTypeAndClear(WOTS_PRF)
10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	*/
	/*1: skADRS ← ADRS ▷ copy address to create key generation key address
		2 : skADRS.setTypeAndClear(WOTS_PRF)
		3 : skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())*/
	uint8_t skADRS[ADR_SIZE];
	memcpy(skADRS, adr, ADR_SIZE);
	setType(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(adr));
	__m256i /*in64start [16], */in64[16], keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
	__m256i blocks[64];

	init_in_block(in64, skADRS, SK_seed);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);

	FIPS205_wots_gen_sk_new(
		keysBlocks,
		SK_seed,
		blockstate256,
		blocks);
	
	__m256i sign256[FIPS205_W][(FIPS205_LEN + 7) / 8][8];

	//FIPS205_wots_gen_sk8(/*sk256*/ keys, (__m256i*)in256, state);
	const int por_count = (FIPS205_LEN + 7) / 8;
	__m256i* curKeys = keysBlocks;
	uint32_t* cur_keys_32;
	for (int i = 0; i < por_count; ++i)
	{
		cur_keys_32 = (uint32_t*)curKeys;
		
		for (int j = 0; j < 8; ++j)
		{

			sign256[0][i][j] = _mm256_shuffle_epi8(
				_mm256_i32gather_epi32((const int*)cur_keys_32++, idx8, 4), maska_for_shuffle_32);
		}
		curKeys += 8;

	}

	// Create type
	blocks[2] = _mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]);

	for (int j = 0; j < FIPS205_W - 1; ++j)
	{
		blocks[5] = _mm256_or_si256(_mm256_andnot_si256(HashAddressClearMaska, blocks[5]), _mm256_set1_epi32(j << 16));

		__m256i start_value_i = step1_sll16;

		curKeys = keysBlocks;

		//__m256i curKeys_[8];


		for (int i = 0; i < por_count; ++i)
		{

			blocks[4] = start_value_i;

			replace_blocks_key8__(blocks, curKeys);
			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));
			AVX_sha256_compress8(curKeys, blocks);

			//convert_to_m256_one_block_keys(curKeys_, curKeys);

			//memcpy(&sign256[j + 1][i], curKeys_, 8 * sizeof(__m256i));
			cur_keys_32 = (uint32_t*)curKeys;

			for (int k = 0; k < 8; ++k)
			{

				sign256[j + 1][i][k] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi32((const int*)cur_keys_32++, idx8, 4), maska_for_shuffle_32);
			}

			curKeys += 8;

			start_value_i = _mm256_add_epi32(start_value_i, eight_256);
		}

	}

	for (int i = 0; i < FIPS205_LEN; ++i)
#ifdef _MSC_VER
		memcpy(sign[i], sign256[base_b[i]][i / 8][i % 8].m256i_i8, FIPS205_N);
#else
			memcpy(sign[i], (uint8_t*)&sign256[base_b[i]][i / 8][i % 8], FIPS205_N);
#endif
}

// Упорядкування signs в порядку збільшення кількості додаткових ітерацій
// src - кількість ітерацій, які зроблені при генерації sign
// dest -  упорядкований масив з кількістю ітерацій, які зроблені при генерації sign
// dest_ упорядкований масив з номерами підписів для упорядкованого масиву

void sort_signs(uint32_t* dest, uint32_t* dest_, uint32_t* src)
{
	uint32_t cnts[16];
	memset(cnts, 0, 16 * sizeof(cnts[0]));
	for (uint32_t i = 0; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
		cnts[src[i]] += 1;

	uint32_t cnts_[16];
	cnts_[0] = 0;
	for (uint32_t i = 1; i < 16; ++i)
	{
		cnts_[i] = cnts_[i - 1] + cnts[i - 1];
	}
	for (uint32_t i = 0; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
	{
		dest[cnts_[src[i]]] = src[i];
		dest_[cnts_[src[i]]] = i;
		cnts_[src[i]] += 1;
	}

}

void sort_signs_(uint32_t cnts[16], /*uint32_t* dest, */uint32_t* dest_, uint32_t* src)
{
	memset(cnts, 0, 16 * sizeof(cnts[0]));
	for (uint32_t i = 0; i < FIPS205_LEN/*(FIPS205_LEN + 7) / 8 * 8*/; ++i)
		cnts[src[i]] += 1;

	uint32_t cnts_[16];
	cnts_[0] = 0;
	for (uint32_t i = 1; i < 16; ++i)
	{
		cnts_[i] = cnts_[i - 1] + cnts[i - 1];
	}
	for (uint32_t i = 0; i < FIPS205_LEN/*(FIPS205_LEN + 7) / 8 * 8*/; ++i)
	{
		//dest[cnts_[src[i]]] = src[i];
		dest_[cnts_[src[i]]] = i;
		cnts_[src[i]] += 1;
	}

}

// завантаження даних за їх номерами
void load_datas(__m256i* datas256, const uint8_t datas8[][FIPS205_N], const uint32_t* data_num)
{
	memcpy(&datas256[0], datas8[data_num[0]], FIPS205_N);
	memcpy(&datas256[1], datas8[data_num[1]], FIPS205_N);
	memcpy(&datas256[2], datas8[data_num[2]], FIPS205_N);
	memcpy(&datas256[3], datas8[data_num[3]], FIPS205_N);
	memcpy(&datas256[4], datas8[data_num[4]], FIPS205_N);
	memcpy(&datas256[5], datas8[data_num[5]], FIPS205_N);
	memcpy(&datas256[6], datas8[data_num[6]], FIPS205_N);
	memcpy(&datas256[7], datas8[data_num[7]], FIPS205_N);
	datas256[0] = _mm256_shuffle_epi8(datas256[0], maska_for_shuffle_32);
	datas256[1] = _mm256_shuffle_epi8(datas256[1], maska_for_shuffle_32);
	datas256[2] = _mm256_shuffle_epi8(datas256[2], maska_for_shuffle_32);
	datas256[3] = _mm256_shuffle_epi8(datas256[3], maska_for_shuffle_32);
	datas256[4] = _mm256_shuffle_epi8(datas256[4], maska_for_shuffle_32);
	datas256[5] = _mm256_shuffle_epi8(datas256[5], maska_for_shuffle_32);
	datas256[6] = _mm256_shuffle_epi8(datas256[6], maska_for_shuffle_32);
	datas256[7] = _mm256_shuffle_epi8(datas256[7], maska_for_shuffle_32);


}

void FIPS205_AVX_wots_sign_sorted(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed,
	const __m256i* blockstate256, uint8_t* adr)
{
	enum { LEN8 = (FIPS205_LEN + 7) / 8 * 8, POR = (FIPS205_LEN + 7) / 8 };

	/* 1. message -> base-16 digits + checksum (as in FIPS205_AVX_wots_sign) */
	ALIGN64 uint32_t base_b[LEN8];
	base_4_new(base_b, M, FIPS205_N * 2);
	uint32_t csum = 0;
	for (int i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];
	base_b[FIPS205_LEN1] = (csum >> 8);
	base_b[FIPS205_LEN1 + 1] = (csum >> 4) & 0xF;
	base_b[FIPS205_LEN1 + 2] = (csum) & 0xF;
	for (int i = FIPS205_LEN; i < LEN8; ++i)
		base_b[i] = 0;			/* padding lanes: no hashing needed */

	/* 2. secret keys for all chains, 8 at a time (as in FIPS205_AVX_wots_sign) */
	uint8_t skADRS[ADR_SIZE];
	memcpy(skADRS, adr, ADR_SIZE);
	setType(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(adr));

	__m256i in64[16], blocks[64], keysBlocks[LEN8];
	init_in_block(in64, skADRS, SK_seed);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256i));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256i));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256i));
	create_blocks_for_in64(blocks, in64);
	FIPS205_wots_gen_sk_new(keysBlocks, SK_seed, blockstate256, blocks);

	/* transposed key blocks -> one byte string per chain (padded length, so
	   load_datas never reads past the array) */
	ALIGN32 uint8_t sk[LEN8][FIPS205_N];
	for (int i = 0; i < POR; ++i)
	{
		const uint32_t* k32 = (const uint32_t*)(keysBlocks + 8 * i);
		for (int j = 0; j < 8; ++j)
		{
			__m256i r = _mm256_shuffle_epi8(
				_mm256_i32gather_epi32((const int*)(k32 + j), idx8, 4), maska_for_shuffle_32);
			memcpy(sk[8 * i + j], &r, FIPS205_N);
		}
	}

	/* 3. sort chains by number of steps */
	uint32_t iters[LEN8], numbers[LEN8];
	sort_signs(iters, numbers, base_b);

	/* hash blocks for the chain function F (WOTS_HASH address, as in
	   FIPS205_AVX_wots_pkFromSig) */
	init_in_block0(in64, adr);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256i));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256i));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256i));
	create_blocks_for_in64(blocks, in64);
	const __m256i hash_addr0 = _mm256_andnot_si256(HashAddressClearMaska, blocks[5]);

	/* 4. groups of 8 chains */
	for (int g = 0; g < POR; ++g)
	{
		const uint32_t* n32 = numbers + 8 * g;
		const uint32_t* i32 = iters + 8 * g;		/* ascending */

		ALIGN32 __m256i temp[8] = { 0 };
		__m256i curKeys[8];
		load_datas(temp, (const uint8_t(*)[FIPS205_N])sk, n32);
		const uint32_t* t32 = (const uint32_t*)temp;
		for (int w = 0; w < 8; ++w)
			curKeys[w] = _mm256_i32gather_epi32((const int*)(t32 + w), idx8, 4);

		blocks[4] = _mm256_slli_epi32(_mm256_loadu_si256((const __m256i*)n32), 16);	/* chain addresses */
		blocks[5] = hash_addr0;														/* hash address 0  */

		uint32_t steps = 0, k = 0;
		for (;;)
		{
			/* lanes whose chain is complete after 'steps' steps */
			while (k < 8 && i32[k] == steps)
			{
				if (n32[k] < FIPS205_LEN)
				{
					__m256i r = _mm256_shuffle_epi8(
						_mm256_i32gather_epi32((const int*)((const uint32_t*)curKeys + k), idx8, 4),
						maska_for_shuffle_32);
					memcpy(sign[n32[k]], &r, FIPS205_N);
				}
				++k;
			}
			if (k == 8)
				break;
			replace_blocks_key8__(blocks, curKeys);
			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));
			AVX_sha256_compress8(curKeys, blocks);
			blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));
			++steps;
		}
	}
}

void FIPS205_wots_gen_pkFromSig_old(uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const uint8_t* PK_seed,
	uint8_t* adr)
{
	uint32_t base_b[FIPS205_LEN] = { 0 };
	base_2b_old(base_b, M, 4, FIPS205_N * 2);
	/*
	for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
5: end for
	*/
	uint32_t csum = 0;
	for (int i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];
	// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8)
	csum = csum << ((8 - ((FIPS205_LEN2 * 4) % 8)) % 8);
	uint8_t temp[2];
	to_byte16(temp, csum);

	base_2b_old(base_b + FIPS205_LEN1, temp, 4, FIPS205_LEN2);

	uint8_t cur_adr[ADR_SIZE];
	memcpy(cur_adr, adr, ADR_SIZE);
	for (int i = 0; i < FIPS205_LEN; ++i)
	{		
		setChainAddress(cur_adr, i);
		// void FIPS205_wots_chain_old(uint8_t* out, const uint8_t *pk, const uint8_t* in, uint8_t* Adr, int i, int s)
		FIPS205_wots_chain_old(pk[i], PK_seed, sign[i], cur_adr, base_b[i], FIPS205_W - 1 - base_b[i]);
	}
}

// Цикл по порціям
void FIPS205_wots_gen_pkFromSig_new___
//void 
//FIPS205_AVX_wots_gen_pkFromSig
(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr)
{



	// sign256[i][l][j]
	// calc indexes

	ALIGN64 uint32_t base_b[(FIPS205_LEN + 7) / 8 * 8];
	__m256i* base_b_256 = (__m256i*) base_b;
	base_4_new(base_b, M, FIPS205_N * 2);

	uint32_t csum = 0;
	for (int i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];


	base_b[FIPS205_LEN1] = (csum >> 8);
	base_b[FIPS205_LEN1 + 1] = (csum >> 4) & 0xF;
	base_b[FIPS205_LEN1 + 2] = (csum) & 0xF;
	for (int i = FIPS205_LEN; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
		base_b[i] = 15;
	uint32_t base_b_[(FIPS205_LEN + 7) / 8 * 8];
	uint32_t k = 0, i, j/*, l*/;
	for (i = 0; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
		base_b_[i] = FIPS205_W - 1 - base_b[i];

#if 0
	uint32_t min[(FIPS205_LEN + 7) / 8];
	for (i = 0; i < (FIPS205_LEN + 7) / 8; ++i)
	{

		k = i * 8;
		//int cur_min = base_b[k];
		uint32_t cur_min = 15;
		for (j = 0; j < 8; ++j)
		{
			if (base_b[k] < cur_min)
				cur_min = base_b[k];
			++k;
		}
		min[i] = cur_min;
}
#else
	uint32_t max[(FIPS205_LEN + 7) / 8];
	for (i = 0; i < (FIPS205_LEN + 7) / 8; ++i)
	{

		k = i * 8;
		//int cur_min = base_b[k];
		uint32_t cur_max = 0;
		for (j = 0; j < 8; ++j)
		{
			if (base_b_[k] > cur_max)
				cur_max = base_b_[k];
			++k;
		}
		max[i] = cur_max;
	}
#endif





	// adr
	__m256i in64[16];
	__m256i blocks[64];

	init_in_block(in64, adr, sign[0]);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);
	__m256i start_value_i = step1_sll16;
	//blocks[4] = start_value_i;

	__m256i sign256/*[(FIPS205_LEN + 7) / 8]*/[FIPS205_W][8];
	//__m256i keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
	__m256i curKeys[8];
	__m256i temp[8] = { 0 };



	uint32_t* temp32 = (uint32_t*)temp;

	uint32_t por_count = (FIPS205_LEN + 7) / 8;
	//for (i = 0; i < por_count - 1; ++i)

	k = 0;
	for (i = 0; i < por_count; ++i)
	{
		blocks[4] = start_value_i;
#if 0
		// convert sign to blocks They will be sk
		for (j = 0; j < 8; ++j)
		{
			memcpy(&temp[j], sign[k++], FIPS205_N);
			temp[j] = _mm256_shuffle_epi8(temp[j], maska_for_shuffle_32);
			sign256[0][j] = temp[j];
		}
#endif	
#if 1		
		memcpy(&temp[0], sign[k++], FIPS205_N);
		memcpy(&temp[1], sign[k++], FIPS205_N);
		memcpy(&temp[2], sign[k++], FIPS205_N);
		memcpy(&temp[3], sign[k++], FIPS205_N);
		memcpy(&temp[4], sign[k++], FIPS205_N);
		memcpy(&temp[5], sign[k++], FIPS205_N);
		memcpy(&temp[6], sign[k++], FIPS205_N);
		memcpy(&temp[7], sign[k++], FIPS205_N);
		temp[0] = _mm256_shuffle_epi8(temp[0], maska_for_shuffle_32);
		temp[1] = _mm256_shuffle_epi8(temp[1], maska_for_shuffle_32);
		temp[2] = _mm256_shuffle_epi8(temp[2], maska_for_shuffle_32);
		temp[3] = _mm256_shuffle_epi8(temp[3], maska_for_shuffle_32);
		temp[4] = _mm256_shuffle_epi8(temp[4], maska_for_shuffle_32);
		temp[5] = _mm256_shuffle_epi8(temp[5], maska_for_shuffle_32);
		temp[6] = _mm256_shuffle_epi8(temp[6], maska_for_shuffle_32);
		temp[7] = _mm256_shuffle_epi8(temp[7], maska_for_shuffle_32);
		
#if 0
		sign256[0][0] = temp[0];
		sign256[0][1] = temp[1];
		sign256[0][2] = temp[2];
		sign256[0][3] = temp[3];
		sign256[0][4] = temp[4];
		sign256[0][5] = temp[5];
		sign256[0][6] = temp[6];
		sign256[0][7] = temp[7];
#else
		__m256i* p = &sign256[0][0];
		p[0] = temp[0];
		p[1] = temp[1];
		p[2] = temp[2];
		p[3] = temp[3];
		p[4] = temp[4];
		p[5] = temp[5];
		p[6] = temp[6];
		p[7] = temp[7];

#endif


#endif
#if 0
		temp[0] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);
		temp[1] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);
		temp[2] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);
		temp[3] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);
		temp[4] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);
		temp[5] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);
		temp[6] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);
		temp[7] = _mm256_shuffle_epi8(_mm256_and_si256(_mm256_lddqu_si256(sign[k++]), maska_for_N), maska_for_shuffle_32);

		sign256[0][0] = temp[0];
		sign256[0][1] = temp[1];
		sign256[0][2] = temp[2];
		sign256[0][3] = temp[3];
		sign256[0][4] = temp[4];
		sign256[0][5] = temp[5];
		sign256[0][6] = temp[6];
		sign256[0][7] = temp[7];
#endif
		temp32 = (uint32_t*)temp;

		curKeys[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		//
		blocks[5] = _mm256_or_si256(_mm256_andnot_si256(HashAddressClearMaska, blocks[5]), _mm256_slli_epi32(base_b_256[i], 16));

#if 0
		for (j = 1; j < FIPS205_W - min[i]; ++j) // дописывать
#else
		for (j = 1; j <= max[i]; ++j) // дописывать
#endif
		{
			replace_blocks_key8__(blocks, curKeys);

			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));

			AVX_sha256_compress8(curKeys, blocks);

			temp32 = (uint32_t*)curKeys;

#if 0
			for (l = 0; l < 8; ++l)
			{
				sign256[j][l] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4)/*, maska_for_shuffle_32)*/;

			}
#else
			
#if 0
			sign256[j][0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			sign256[j][1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			sign256[j][2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			sign256[j][3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			sign256[j][4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			sign256[j][5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			sign256[j][6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			sign256[j][7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
#else
			__m256i* p = &sign256[j][0];
			p[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);

#endif
#endif
			blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));

		}


#if 1
		uint32_t index = i * 8;
		for (j = 0; j < 8; ++j)
		{
			__m256i r = _mm256_shuffle_epi8(
				sign256[FIPS205_W - 1 - base_b[index + j]][j], maska_for_shuffle_32);
			memcpy(pk[index + j], &r, FIPS205_N);
		}
#elif 1
		uint32_t index = i * 8;
		for (j = 0; j < 8; ++j)
		{
			__m256i r = _mm256_shuffle_epi8(
				sign256[base_b_[index + j]][j], maska_for_shuffle_32);
			memcpy(pk[index + j], &r, FIPS205_N);
		}

#else
		uint32_t index = i * 8;
		uint32_t* p = base_b_ + index;
		temp[0] = _mm256_shuffle_epi8(
			sign256[p[0]][0], maska_for_shuffle_32);
		temp[1] = _mm256_shuffle_epi8(
			sign256[p[1]][1], maska_for_shuffle_32);
		temp[2] = _mm256_shuffle_epi8(
			sign256[p[2]][2], maska_for_shuffle_32);
		temp[3] = _mm256_shuffle_epi8(
			sign256[p[3]][3], maska_for_shuffle_32);
		temp[4] = _mm256_shuffle_epi8(
			sign256[p[4]][4], maska_for_shuffle_32);
		temp[5] = _mm256_shuffle_epi8(
			sign256[p[5]][5], maska_for_shuffle_32);
		temp[6] = _mm256_shuffle_epi8(
			sign256[p[6]][6], maska_for_shuffle_32);
		temp[7] = _mm256_shuffle_epi8(
			sign256[p[7]][7], maska_for_shuffle_32);



		memcpy(pk[index + 0], &temp[0], FIPS205_N);
		memcpy(pk[index + 1], &temp[1], FIPS205_N);
		memcpy(pk[index + 2], &temp[2], FIPS205_N);
		memcpy(pk[index + 3], &temp[3], FIPS205_N);
		memcpy(pk[index + 4], &temp[4], FIPS205_N);
		memcpy(pk[index + 5], &temp[5], FIPS205_N);
		memcpy(pk[index + 6], &temp[6], FIPS205_N);
		memcpy(pk[index + 7], &temp[7], FIPS205_N);

#endif


		start_value_i = _mm256_add_epi32(start_value_i, eight_256);

		}

}




void load_signs_(__m256i* signs256, const uint8_t signs8[][FIPS205_N], const uint32_t* sign_num, uint32_t count)
{
	for (uint8_t i = 0; i < count; ++i)
	{
		memcpy(&signs256[i], signs8[sign_num[i]], FIPS205_N);
		signs256[i] = _mm256_shuffle_epi8(signs256[i], maska_for_shuffle_32);
	}
	for (uint8_t i = count; i < 8; ++i)
		signs256[i] = _mm256_setzero_si256();
}

void
FIPS205_AVX_wots_gen_pkFromSig
(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr)
{

	ALIGN64 uint32_t base_b[(FIPS205_LEN + 7) / 8 * 8];
	__m256i* base_b_256 = (__m256i*) base_b;
	uint32_t k = 0, i, j/*, l*/;

	base_4_new(base_b, M, FIPS205_N * 2);

	uint32_t csum = 0;
	for (i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];


	base_b[FIPS205_LEN1] = (csum >> 8);
	base_b[FIPS205_LEN1 + 1] = (csum >> 4) & 0xF;
	base_b[FIPS205_LEN1 + 2] = (csum) & 0xF;
	for (int i = FIPS205_LEN; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
		base_b[i] = 15;
	//uint32_t base_b_[(FIPS205_LEN + 7) / 8 * 8];
	
	/*for (i = 0; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
		base_b_[i] = FIPS205_W - 1 - base_b[i];*/
	uint32_t iters[(FIPS205_LEN + 7) / 8 * 8];
	uint32_t numbers[(FIPS205_LEN + 7) / 8 * 8];
	sort_signs(iters, numbers, base_b);

	// adr
	__m256i in64[16];
	__m256i blocks[64];

	init_in_block0(in64, adr);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);
	//__m256i start_value_i = step1_sll16;
	//blocks[4] = start_value_i;

	__m256i sign256[FIPS205_W][8];
	//__m256i keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
	__m256i curKeys[8];
	__m256i temp[8] = { 0 };

	uint32_t* temp32 = (uint32_t*)temp;

	uint32_t por_count = (FIPS205_LEN + 7 ) / 8;
	//for (i = 0; i < por_count - 1; ++i)

	k = 0;
	uint32_t* n32 = numbers ;
	uint32_t* i32 = iters;

	for (i = 0; i < por_count; ++i)
	{
		//blocks[4] = start_value_i;
		

		blocks[4] = _mm256_slli_epi32 (_mm256_lddqu_si256((const __m256i*)n32), 16);
	
#if 1		
		load_datas(temp, sign, /*numbers + 8 * i*/n32);
#if 0
		sign256[0][0] = temp[0];
		sign256[0][1] = temp[1];
		sign256[0][2] = temp[2];
		sign256[0][3] = temp[3];
		sign256[0][4] = temp[4];
		sign256[0][5] = temp[5];
		sign256[0][6] = temp[6];
		sign256[0][7] = temp[7];
#else
		__m256i* p = &sign256[0][0];
		p[0] = temp[0];
		p[1] = temp[1];
		p[2] = temp[2];
		p[3] = temp[3];
		p[4] = temp[4];
		p[5] = temp[5];
		p[6] = temp[6];
		p[7] = temp[7];

#endif


#endif
		temp32 = (uint32_t*)temp;

		curKeys[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		//
//		iters
			
		blocks[5] = _mm256_or_si256(_mm256_andnot_si256(HashAddressClearMaska, blocks[5]), 
			_mm256_slli_epi32(
				_mm256_lddqu_si256((const __m256i*)i32), 16));

		//uint32_t curi = i32[0];
		uint32_t last_iter = i32[7];
		uint32_t first_iter = i32[0];

		for (j = 0; j < FIPS205_W - 1 - last_iter; ++j) // дописывать

		{
			replace_blocks_key8__(blocks, curKeys);

			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));

			AVX_sha256_compress8(curKeys, blocks);

			blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));
		}
		
		temp32 = (uint32_t*)curKeys;

		p = &sign256[j ][0];
		p[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		
		for (j = FIPS205_W - 1 - last_iter; j < FIPS205_W - 1 - first_iter; ++j)
		{ 
			replace_blocks_key8__(blocks, curKeys);

			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));

			AVX_sha256_compress8(curKeys, blocks);
			blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));
			p = &sign256[j + 1][0];
			temp32 = (uint32_t*)curKeys;

			p[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		}
		
		
		for (j = 0; j < 8; ++j)
		{
			__m256i r = _mm256_shuffle_epi8(
				sign256[FIPS205_W - 1 - i32[j]][j], maska_for_shuffle_32);
			memcpy(pk[n32[j]], &r, FIPS205_N);
		}

		//start_value_i = _mm256_add_epi32(start_value_i, eight_256);
		n32 += 8;
		i32 += 8;

	}
	// last por
	

}

void FIPS205_AVX_wots_gen_pk(
	uint8_t* pk,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed;
#else
	const __m256i* state_blocks,
	const void *predcalc,
#endif
	uint8_t* adr)
{

	uint8_t pks[(FIPS205_LEN + 7)/8 *8  *FIPS205_N];
	
	FIPS205_AVX_wots_gen_pks(
		pks ,
		SK_seed,
		state_blocks,
		adr);
	
	/*
	wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
11: wotspkADRS.setTypeAndClear(WOTS_PK)
12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	*/
	uint8_t wotspkADRS[ADR_SIZE];
	memcpy(wotspkADRS, adr, ADR_SIZE);
	setType(wotspkADRS, WOTS_PK);
	//setChainAddress(wotspkADRS, 0);
	//setHashAddress(wotspkADRS, 0);
	setKeyPairAddress(wotspkADRS, getKeyPairAddress(adr));

	AVX_Tl_(pk, predcalc, wotspkADRS, pks, FIPS205_LEN);

	
}

void FIPS205_AVX_wots_gen_pk_(
	uint8_t* pk,
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed;
#else
	const __m256i* state_blocks,
	const void* predcalc,
#endif
	uint8_t* adr)
{

	uint8_t pks[(FIPS205_LEN + 7) / 8 * 8 * FIPS205_N];

	FIPS205_AVX_wots_gen_pks(
		pks,
		SK_seed,
		state_blocks,
		adr);

	/*
	wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
11: wotspkADRS.setTypeAndClear(WOTS_PK)
12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	*/
	uint8_t wotspkADRS[ADR_SIZE];
	memcpy(wotspkADRS, adr, ADR_SIZE);
	setType(wotspkADRS, WOTS_PK);
	//setChainAddress(wotspkADRS, 0);
	//setHashAddress(wotspkADRS, 0);
	setKeyPairAddress(wotspkADRS, getKeyPairAddress(adr));

	AVX_Tl_(pk, predcalc, wotspkADRS, pks, FIPS205_LEN);


}


void
FIPS205_AVX_wots_pkFromSig
(
	uint8_t pk[FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
#ifdef SHAKE
	const uint8_t *pk,
#else
	const __m256i* blockstate256,
	const void * pk_n,
#endif
	uint8_t* adr)
{

	ALIGN64 uint32_t base_b[(FIPS205_LEN + 7) / 8 * 8];
	__m256i* base_b_256 = (__m256i*) base_b;
	uint32_t k = 0, i, j/*, l*/;

	base_4_new(base_b, M, FIPS205_N * 2);

	uint32_t csum = 0;
	for (i = 0; i < FIPS205_LEN1; ++i)
		csum += FIPS205_W - 1 - base_b[i];


	base_b[FIPS205_LEN1] = (csum >> 8);
	base_b[FIPS205_LEN1 + 1] = (csum >> 4) & 0xF;
	base_b[FIPS205_LEN1 + 2] = (csum) & 0xF;
	for (int i = FIPS205_LEN; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
		base_b[i] = 15;
	//uint32_t base_b_[(FIPS205_LEN + 7) / 8 * 8];

	/*for (i = 0; i < (FIPS205_LEN + 7) / 8 * 8; ++i)
		base_b_[i] = FIPS205_W - 1 - base_b[i];*/
	uint32_t iters[(FIPS205_LEN + 7) / 8 * 8];
	uint32_t numbers[(FIPS205_LEN + 7) / 8 * 8];
	sort_signs(iters, numbers, base_b);

	// adr
	__m256i in64[16];
	__m256i blocks[64];

	init_in_block0(in64, adr);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);
	//__m256i start_value_i = step1_sll16;
	//blocks[4] = start_value_i;

	__m256i sign256[FIPS205_W][8];
	//__m256i keysBlocks[(FIPS205_LEN + 7) / 8 * 8];
	__m256i curKeys[8];
	__m256i temp[8] = { 0 };

	uint32_t* temp32 = (uint32_t*)temp;

	uint32_t por_count = (FIPS205_LEN + 7) / 8;
	//for (i = 0; i < por_count - 1; ++i)

	k = 0;
	uint32_t* n32 = numbers;
	uint32_t* i32 = iters;

	uint8_t pks[((FIPS205_LEN + 7) / 8) * 8][FIPS205_N];
	for (i = 0; i < por_count; ++i)
	{
		//blocks[4] = start_value_i;


		blocks[4] = _mm256_slli_epi32(_mm256_lddqu_si256((const __m256i*)n32), 16);

#if 1		
		load_datas(temp, sign, /*numbers + 8 * i*/n32);
#if 0
		sign256[0][0] = temp[0];
		sign256[0][1] = temp[1];
		sign256[0][2] = temp[2];
		sign256[0][3] = temp[3];
		sign256[0][4] = temp[4];
		sign256[0][5] = temp[5];
		sign256[0][6] = temp[6];
		sign256[0][7] = temp[7];
#else
		__m256i* p = &sign256[0][0];
		p[0] = temp[0];
		p[1] = temp[1];
		p[2] = temp[2];
		p[3] = temp[3];
		p[4] = temp[4];
		p[5] = temp[5];
		p[6] = temp[6];
		p[7] = temp[7];

#endif


#endif
		temp32 = (uint32_t*)temp;

		curKeys[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		curKeys[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		//
//		iters

		blocks[5] = _mm256_or_si256(_mm256_andnot_si256(HashAddressClearMaska, blocks[5]),
			_mm256_slli_epi32(
				_mm256_lddqu_si256((const __m256i*)i32), 16));

		//uint32_t curi = i32[0];
		uint32_t last_iter = i32[7];
		uint32_t first_iter = i32[0];

		for (j = 0; j < FIPS205_W - 1 - last_iter; ++j) // дописывать

		{
			replace_blocks_key8__(blocks, curKeys);

			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));

			AVX_sha256_compress8(curKeys, blocks);

			blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));
		}

		temp32 = (uint32_t*)curKeys;

		p = &sign256[j][0];
		p[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		p[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);

		for (j = FIPS205_W - 1 - last_iter; j < FIPS205_W - 1 - first_iter; ++j)
		{
			replace_blocks_key8__(blocks, curKeys);

			memcpy(curKeys, blockstate256, 8 * sizeof(__m256i));

			AVX_sha256_compress8(curKeys, blocks);
			blocks[5] = _mm256_add_epi32(blocks[5], _mm256_set1_epi32(1 << 16));
			p = &sign256[j + 1][0];
			temp32 = (uint32_t*)curKeys;

			p[0] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[1] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[2] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[3] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[4] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[5] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[6] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			p[7] = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
		}

		
		for (j = 0; j < 8; ++j)
		{
			__m256i r = _mm256_shuffle_epi8(
				sign256[FIPS205_W - 1 - i32[j]][j], maska_for_shuffle_32);
			memcpy(pks[n32[j]], &r, FIPS205_N);
		}

		//start_value_i = _mm256_add_epi32(start_value_i, eight_256);
		n32 += 8;
		i32 += 8;

	}
	// last por
	uint8_t wotspkADRS[ADR_SIZE];
	memcpy(wotspkADRS, adr, ADR_SIZE);
	setType(wotspkADRS, WOTS_PK);
	setKeyPairAddress(wotspkADRS, getKeyPairAddress(adr));
	AVX_Tl_(pk, pk_n, wotspkADRS, (uint8_t*)pks, FIPS205_LEN);

}
