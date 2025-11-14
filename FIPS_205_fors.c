#include "FIPS_205_Fors.h"
#include "FIPS_205_Adr.h"
#include "AVX512.h"
#include <malloc.h>
#include <omp.h>

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

inline __m256i _mm256_blendv_epi32(__m256i a, __m256i b, __m256i mask) {
	return _mm256_castps_si256(
		_mm256_blendv_ps(
			_mm256_castsi256_ps(a),
			_mm256_castsi256_ps(b),
			_mm256_castsi256_ps(mask)
		)
	);
}

inline __m256i _mm256_blendv_epi64(__m256i a, __m256i b, __m256i mask) {
	return _mm256_castpd_si256(
		_mm256_blendv_pd(
			_mm256_castsi256_pd(a),
			_mm256_castsi256_pd(b),
			_mm256_castsi256_pd(mask)
		)
	);
}

#if _WIN32
#else
static inline void* _aligned_malloc(size_t size, size_t alignment) {
    void* ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0)
        return NULL;
    return ptr;
}
static inline void _aligned_free(void* ptr) {
    free(ptr);
}
#endif

void convert_to_keys(uint8_t keys[][FIPS205_N], const __m256i* block_keys)
{

	__m256i temp;
	uint32_t* block_keys_32 = (uint32_t*)block_keys;
	int i, k = 0;

	for (i = 0; i < FIPS205_K / 8; ++i)
	{
		block_keys_32 = (uint32_t*)block_keys;


		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k++], &temp, FIPS205_N);
		block_keys += 8;
	}
	
	block_keys_32 = (uint32_t*)block_keys;
	
	

	for (; k < FIPS205_K; ++k)
	{
		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		memcpy(keys[k], &temp, FIPS205_N);
	}

}

// __m256i Array from Blocks 
void convert_to_keys_64_256(__m256i keys[], const __m256i* block_keys)
{
	//__m256i temp [(FIPS205_K + 7)/8 * 8];
	__m256i temp;
	uint32_t* block_keys_32 = (uint32_t*)block_keys;
	int i, k = 0;

	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		block_keys_32 = (uint32_t*)block_keys;


		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys [k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		
		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		
		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		
		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		
		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		//memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		//memcpy(keys[k++], &temp, FIPS205_N);

		temp = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
		//memcpy(keys[k++], &temp, FIPS205_N);

		block_keys += 8;
	}

	
}

void convert_from_keys(__m256i* block_keys, const uint8_t keys[][FIPS205_N] )
{
	
	uint32_t* block_keys_32 = (uint32_t*)block_keys;
	int i, j, k = 0;
	__m256i temp[8] = {0};
	uint32_t* ptemp32 = (uint32_t*)temp;
	for (i = 0; i < FIPS205_K / 8; ++i)
	{
		for (j = 0; j < 8; ++j)
		{
			memcpy((void*)&temp[j], keys[k++], FIPS205_N);
			temp[j] = _mm256_shuffle_epi8(temp[j], maska_for_shuffle_32);
		}
		block_keys[0] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys[1] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys[2] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys[3] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys[4] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys[5] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys[6] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys[7] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
		block_keys += 8;
	}
	for (j = 0; j < FIPS205_K % 8; ++j)
	{
		memcpy((void*)&temp[j], keys[k++], FIPS205_N);
		temp[j] = _mm256_shuffle_epi8(temp[j], maska_for_shuffle_32);
	}
	block_keys[0] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
	block_keys[1] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
	block_keys[2] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
	block_keys[3] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
	block_keys[4] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
	block_keys[5] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
	block_keys[6] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
	block_keys[7] = _mm256_i32gather_epi32((const int*)ptemp32++, idx8, 4);
}



void convert_to_keys_64(uint8_t keys[][FIPS205_N], const __m256i* block_keys)
{
	__m256i temp;
	uint64_t* block_keys_64 = (uint64_t*)block_keys;
	int i, j, k = 0;
	__m128i idx = _mm_setr_epi32(0, 4, 8, 12);
	for (i = 0; i < FIPS205_K / 8; ++i)
	{
		block_keys_64 = (uint64_t*)block_keys;
		for (j = 0; j < 4; ++j)
		{
			// _mm256_i32gather_epi64((__int64 const*)temp, idx, 8);
			temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
			//temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
			temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
			//state_256[1] = _mm256_shuffle_epi8(state_256[1], maska_for_shuffle_64);
			memcpy(keys[k++], &temp, FIPS205_N);
		}
		block_keys += 4;
		block_keys_64 = (uint64_t*)block_keys;
		for (j = 0; j < 4; ++j)
		{
			// _mm256_i32gather_epi64((__int64 const*)temp, idx, 8);
			temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
			//temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
			temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
			//state_256[1] = _mm256_shuffle_epi8(state_256[1], maska_for_shuffle_64);
			memcpy(keys[k++], &temp, FIPS205_N);
		}
		block_keys += 4;
	}
#if FIPS205_K % 8 != 0
	block_keys_64 = (uint64_t*)block_keys;
	
#if FIPS205_K % 8 >=4
	temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
	temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
	memcpy(keys[k++], &temp, FIPS205_N);
	temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
	temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
	memcpy(keys[k++], &temp, FIPS205_N);
	temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
	temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
	memcpy(keys[k++], &temp, FIPS205_N);
	temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
	temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
	memcpy(keys[k++], &temp, FIPS205_N);
	block_keys += 4;
	block_keys_64 = (uint64_t*)block_keys;
#endif
#if FIPS205_K % 4 !=0
	for (; k < FIPS205_K; ++k)
	{
		temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
		temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
		memcpy(keys[k++], &temp, FIPS205_N);
	}
#endif
#endif


}

void convert_to_keys_128_256(__m256i *keys, const __m256i* block_keys)
{
	__m256i temp;
	uint64_t* block_keys_64 = (uint64_t*)block_keys;
	int i, j, k = 0;
	__m128i idx = _mm_setr_epi32(0, 4, 8, 12);
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		block_keys_64 = (uint64_t*)block_keys;
		for (j = 0; j < 4; ++j)
		{
			// _mm256_i32gather_epi64((__int64 const*)temp, idx, 8);
			temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
			//temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
			keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
			//state_256[1] = _mm256_shuffle_epi8(state_256[1], maska_for_shuffle_64);
			//memcpy(keys[k++], &temp, FIPS205_N);
		}
		block_keys += 4;
		block_keys_64 = (uint64_t*)block_keys;
		for (j = 0; j < 4; ++j)
		{
			// _mm256_i32gather_epi64((__int64 const*)temp, idx, 8);
			temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
			//temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
			keys[k++] = _mm256_shuffle_epi8(temp, maska_for_shuffle_64);
			//state_256[1] = _mm256_shuffle_epi8(state_256[1], maska_for_shuffle_64);
			//memcpy(keys[k++], &temp, FIPS205_N);
		}
		block_keys += 4;
	}


}

void convert_to_keys_64_(uint8_t keys[][FIPS205_N], __m256i* block_keys)
{
	//__m256i temp;

	__m256i temp_[(FIPS205_K + 3) / 4 * 4];
	int i, k = 0;

	uint64_t* block_keys_64 = (uint64_t*)block_keys;

	__m128i idx = _mm_setr_epi32(0, 4, 8, 12);
	for (i = 0; i < (FIPS205_K + 3) / 4; ++i)
	{
		block_keys_64 = (uint64_t*)block_keys;

#if 0
		for (j = 0; j < 4; ++j)
		{

			temp_[k++] = _mm256_shuffle_epi8(_mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8), maska_for_shuffle_64);

		}
#endif
		temp_[k++] = _mm256_shuffle_epi8(_mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8), maska_for_shuffle_64);
		temp_[k++] = _mm256_shuffle_epi8(_mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8), maska_for_shuffle_64);
		temp_[k++] = _mm256_shuffle_epi8(_mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8), maska_for_shuffle_64);
		temp_[k++] = _mm256_shuffle_epi8(_mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8), maska_for_shuffle_64);

		block_keys += 4;
		
	}

	
	for (i = 0; i < FIPS205_K; ++i)
	{
		memcpy(keys[i], &temp_[i], FIPS205_N);
	}


}

// Формування блоку для adr та ключа = 0
/////////////////////////////////////////////////
void FIPS205_AVX_fors_init_in_block0(__m256i* in256, const uint8_t* adr)
{
#if FIPS205_N == 16
	in256[0] = _mm256_setzero_si256();
	in256[1] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)&in256[0];
	memcpy(p, adr, ADR_SIZE);
	setType1(p, FORS_TREE);
	//memcpy(p + ADR_SIZE, key, FIPS205_N);
	p[ADR_SIZE + 2 * FIPS205_N] = 0x80;
	int bytes = (64 + ADR_SIZE + 2 * FIPS205_N);
	/*for (unsigned int i = ADR_SIZE + 2 * FIPS205_N + 1; i < 62; ++i)
		p[i] = 0;*/
	p[62] = (uint8_t)(bytes >> 5);
	p[63] = (uint8_t)(bytes << 3);
#else
	in256[0] = _mm256_setzero_si256();
	in256[1] = _mm256_setzero_si256();
	in256[2] = _mm256_setzero_si256();
	in256[3] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)&in256[0];
	memcpy(p, adr, ADR_SIZE);
	setType1(p, FORS_TREE);
	//memcpy(p + ADR_SIZE, key, FIPS205_N);
	p[ADR_SIZE + 2 * FIPS205_N] = 0x80;
	int bytes = (128 + ADR_SIZE + 2 * FIPS205_N);
	/*for (unsigned int i = ADR_SIZE + 2 * FIPS205_N + 1; i < 126; ++i)
		p[i] = 0;*/
	p[125] = (uint8_t)(bytes >> 13);
	p[126] = (uint8_t)(bytes >> 5);
	p[127] = (uint8_t)(bytes << 3);
#endif
}

// 1 block 128 bytes
// there is 4 (__m256i)
// for 4 parallel datas 4 * 4 = 16 (__m128)

void create_blocks_for_in128(__m256i* blocks, __m256i* in128)
{


	uint64_t* in128_64 = (uint64_t*)in128;

	
	blocks[0] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[1] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[2] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[3] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[4] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[5] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[6] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[7] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[8] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[9] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[10] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[11] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[12] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[13] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[14] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
	blocks[15] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);

}



// Відновлення блоків для 8 пар ключей (hash, Тільки для FIPS256_N = 16)


void AVX_fors_replace_blocks_keys8__(__m256i blockdest_[], __m256i blockkey256_1[8], __m256i blockkey256_2[8])
{
	//__m256i key01_const = _mm256_setr_epi16(0, 0xFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	__m256i keylow_const = _mm256_set1_epi32(0x0000FFFF);
	__m256i keyhigh_const = _mm256_set1_epi32(0xFFFF0000);
	//__m256i keylowhigh_const = _mm256_set1_epi32(0xFFFFFFFF);
	__m256i temp, temp_;

#if FIPS205_N == 16
#define SIZE	2
#define LAST_DEST	9
#define LAST_DEST1	13
	blockkey256_1[4] = blockkey256_1[5] = blockkey256_2[4] = blockkey256_2[5] = 
		blockkey256_1[6] = blockkey256_1[7] = _mm256_setzero_si256();
	//blockdest_[1] = 0;
#endif

#if FIPS205_N == 24
	#define SIZE	4
	#define LAST_DEST	11
	#define LAST_DEST1	17
	blockkey256_1[6] = blockkey256_1[7] = _mm256_setzero_si256();
#endif

#if FIPS205_N == 32
#define SIZE	4
#define LAST_DEST	13	
#define LAST_DEST1	21	
#endif

//#define END_NUMBER (LAST_KEY + 6)


	int j = 0;
	/*memset(blockkey256_1 + 4, 0, 4 * sizeof(__m256i));
	memset(blockkey256_2 + 4, 0, 4 * sizeof(__m256i));*/

	// 5

	temp = _mm256_and_si256(blockkey256_1[0], keyhigh_const);// 0 comp for 8 keys
	temp = _mm256_srli_epi32(temp, 16);
	blockdest_[5] = _mm256_andnot_si256(keylow_const, blockdest_[5]);
	blockdest_[5] = _mm256_or_si256(temp, blockdest_[5]);

	temp = _mm256_and_si256(blockkey256_1[0], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_1[1], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[6] = _mm256_or_si256(temp, temp_);
	//blockdest_[6] = _mm256_or_si256(temp, blockdest_[6]);
	//blockdest_[6] = _mm256_or_si256(temp, blockdest_[6]);

	temp = _mm256_and_si256(blockkey256_1[1], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_1[2], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[7] = _mm256_or_si256(temp, temp_);

	temp = _mm256_and_si256(blockkey256_1[2], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_1[3], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[8] = _mm256_or_si256(temp, temp_);

	temp = _mm256_and_si256(blockkey256_1[3], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
#if FIPS205_N  > 16
	temp_ = _mm256_and_si256(blockkey256_1[4], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[9] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_1[4], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_1[5], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[10] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_1[5], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2

#if FIPS205_N  > 24
	temp_ = _mm256_and_si256(blockkey256_1[6], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[11] = _mm256_or_si256(temp, temp_);

	temp = _mm256_and_si256(blockkey256_1[6], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_1[7], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[12] = _mm256_or_si256(temp, temp_);

	temp = _mm256_and_si256(blockkey256_1[7], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
#endif
#endif
	// 2
	temp_ = _mm256_and_si256(blockkey256_2[0], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_2[0], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_2[1], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST + 1] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_2[1], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_2[2], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST + 2] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_2[2], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_2[3], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST + 3] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_2[3], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2

#if FIPS205_N > 16
	temp_ = _mm256_and_si256(blockkey256_2[4], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST + 4] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_2[4], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_2[5], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST + 5] = _mm256_or_si256(temp, temp_);

	temp = _mm256_and_si256(blockkey256_2[5], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
#if FIPS205_N > 24
	temp_ = _mm256_and_si256(blockkey256_2[6], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST + 6] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_2[6], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
	temp_ = _mm256_and_si256(blockkey256_2[7], keyhigh_const);
	temp_ = _mm256_srli_epi32(temp_, 16);	//00k3k2
	blockdest_[LAST_DEST + 7] = _mm256_or_si256(temp, temp_);
	temp = _mm256_and_si256(blockkey256_2[7], keylow_const);
	temp = _mm256_slli_epi32(temp, 16);	//00k3k2
#endif
#endif
	blockdest_[LAST_DEST1] = _mm256_and_si256(keylow_const, blockdest_[LAST_DEST1]);
	blockdest_[LAST_DEST1 ] = _mm256_or_si256(temp, blockdest_[LAST_DEST1]);
#undef LAST_DEST1
#undef LAST_DEST
}
//#endif
#if FIPS205_N != 16
void AVX_fors_replace_blocks_keys4__(__m256i blockdest_[], __m256i blockkey256_1[], __m256i blockkey256_2[])
{

#if FIPS205_N == 24
#define LAST_DEST1 8
#define LAST_DEST 5
#endif
#if FIPS205_N == 32
#define LAST_DEST1 10
#define LAST_DEST 6
#endif
	blockdest_[3] = blockdest_[4] = blockdest_[5] = blockdest_[6] = blockdest_[7] = _mm256_setzero_si256();
#if FIPS205_N == 32
	blockdest_[8] = blockdest_[9] = _mm256_setzero_si256();
#endif
	// data1
	__m256i keylow_const = _mm256_set1_epi64x(0xFFFF000000000000);
	__m256i keyhigh_const = _mm256_set1_epi32(0x000000000000FFFF);
	__m256i t1 = _mm256_srli_epi64 (_mm256_and_si256(keylow_const, blockkey256_1[0]),48);
	__m256i t2 = _mm256_andnot_si256(keyhigh_const, blockdest_[2]);
	blockdest_[2] = _mm256_or_si256(t1, t2);
	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_1[0]), 16);
	t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockkey256_1[1]), 48);
	blockdest_[3] = _mm256_or_si256(t1, t2);

	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_1[1]), 16);
	t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockkey256_1[2]), 48);
	blockdest_[4] = _mm256_or_si256(t1, t2);
	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_1[2]), 16);
#if FIPS205_N == 32
	t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockkey256_1[3]), 48);
	blockdest_[5] = _mm256_or_si256(t1, t2);
	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_1[3]), 16);
#endif
	t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockkey256_2[0]), 48);
	blockdest_[LAST_DEST] = _mm256_or_si256(t1, t2);
	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_2[0]), 16);
	t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockkey256_2[1]), 48);
	blockdest_[LAST_DEST + 1] = _mm256_or_si256(t1, t2);
	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_2[1]), 16);
	t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockkey256_2[2]), 48);
	blockdest_[LAST_DEST + 2] = _mm256_or_si256(t1, t2);
	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_2[2]), 16);

#if FIPS205_N == 32
	t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockkey256_2[3]), 48);
	blockdest_[LAST_DEST + 3] = _mm256_or_si256(t1, t2);
	t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_2[3]), 16);
#endif
	//t2 = _mm256_srli_epi64(_mm256_and_si256(keylow_const, blockdest_[LAST_DEST1]), 48);
	//t1 = _mm256_slli_epi64(_mm256_andnot_si256(keylow_const, blockkey256_2[2]), 16);
	blockdest_[LAST_DEST1] = _mm256_or_si256(blockdest_[LAST_DEST1], t1);
#undef LAST_DEST1
#undef LAST_DEST
}
#endif

#if FIPS205_N != 16
void convert_32_64(__m256i dest[2][4], const __m256i src[8])
{
	__m256i temp1[2], temp2[2];
	//uint32_t i;
	
	{

		temp1[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[0], 0));
		temp1[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[0], 1));
		temp2[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[1], 0));
		temp2[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[1], 1));
		dest[0][0] = _mm256_add_epi64(_mm256_slli_epi64(temp1[0], 32), temp2[0]);
		dest[1][0] = _mm256_add_epi64(_mm256_slli_epi64(temp1[1], 32), temp2[1]);
		temp1[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[2], 0));
		temp1[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[2], 1));
		temp2[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[3], 0));
		temp2[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[3], 1));
		dest[0][1] = _mm256_add_epi64(_mm256_slli_epi64(temp1[0], 32), temp2[0]);
		dest[1][1] = _mm256_add_epi64(_mm256_slli_epi64(temp1[1], 32), temp2[1]);

		temp1[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[4], 0));
		temp1[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[4], 1));
		temp2[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[5], 0));
		temp2[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[5], 1));
		dest[0][2] = _mm256_add_epi64(_mm256_slli_epi64(temp1[0], 32), temp2[0]);
		dest[1][2] = _mm256_add_epi64(_mm256_slli_epi64(temp1[1], 32), temp2[1]);

		temp1[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[6], 0));
		temp1[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[6], 1));
		temp2[0] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[7], 0));
		temp2[1] = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(src[7], 1));
		dest[0][3] = _mm256_add_epi64(_mm256_slli_epi64(temp1[0], 32), temp2[0]);
		dest[1][3] = _mm256_add_epi64(_mm256_slli_epi64(temp1[1], 32), temp2[1]);
	}


		
	}

#endif

///////////////////////////////////////////////// 
void FIPS205_AVX_fors_H_(__m256i *keysBlocks, __m256i* in_block, const void* PK_seed_, __m256i* node1, __m256i* node2, __m256i* ind, uint32_t z)

{

#if FIPS205_N == 16
	__m256i in64[16], * ind256 = (__m256i*)ind;
	__m256i blocks[64];
	//__m256i keysBlocks[(FIPS205_K + 7) / 8 * 8];
	in64[0] = in_block[0];
	in64[1] = in_block[1];
#ifdef _MSC_VER
	uint8_t* w = in64[0].m256i_i8;
#else
	uint8_t* w = (uint8_t*)&in64[0];
#endif
	setTreeHeight(w, z);

	setType1(w, FORS_TREE);

	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));


	create_blocks_for_in64(blocks, in64);
	//// type
	//blocks[2] = _mm256_or_si256(
	//	_mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]),
	//	_mm256_set1_epi32(FORS_PRF << 16));

	//// treeheight
	//blocks[3] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[3]);
	//blocks[3] = _mm256_or_si256(_mm256_set1_epi32(z << 24), blocks[3]);
	//blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks[4]);
	__m256i start_value = fors_step1_sll16;
	__m256i* curKeys = keysBlocks;

	for (int i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		blocks[5] = _mm256_and_si256(blocks[5], _mm256_set1_epi32(0x0000FFFF));
		blocks[5] = _mm256_or_si256(
			blocks[5], _mm256_slli_epi32(*ind256++, 16));

		AVX_fors_replace_blocks_keys8__(blocks, node1, node2);
		start_value = _mm256_add_epi32(start_value, fors_eight_256);

		memcpy(curKeys, (__m256i*)PK_seed_, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		node1 += 8;

		node2 += 8;
		
		curKeys += 8;
	}

	//convert_to_keys(node, keysBlocks);
#else

	__m256i in128[16], * ind256 = (__m256i*)ind;
	__m256i blocks[80];
	
#ifdef _MSC_VER
	uint8_t* w = in_block[0].m256i_i8;
#else
	uint8_t* w = (uint8_t*)&in_block[0];
#endif
	setTreeHeight(w, z);
	setType1(w, FORS_TREE);
	
	in128[0] = _mm256_shuffle_epi8(in_block[0], maska_for_shuffle_64);
	in128[1] = _mm256_shuffle_epi8(in_block[1], maska_for_shuffle_64);
	in128[2] = _mm256_shuffle_epi8(in_block[2], maska_for_shuffle_64);
	in128[3] = _mm256_shuffle_epi8(in_block[3], maska_for_shuffle_64);

	memcpy(in128 + 4, in128, 4 * sizeof(__m256i));
	memcpy(in128 + 8, in128, 8 * sizeof(__m256i));
	
	int j = 0;
	__m256i temp[8], *ptemp = (__m256i*)temp;
	
	__m256i ind1[2 * (FIPS205_K + 7) / 8]; /* = { 0 }*/
	for (int i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		ind1[2 * i] = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(ind[i], 0));
		ind1[2 * i + 1] = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(ind[i], 1));
	}
	for (int i = 0; i < (FIPS205_K + 3) / 4; ++i)
	{
		
		create_blocks_for_in128(blocks, in128);
		AVX_fors_replace_blocks_keys4__(blocks, node1, node2);
		blocks[2] = _mm256_and_si256(blocks[2], _mm256_set1_epi64x(0xFFFFFFFF0000FFFF));
		blocks[2] = _mm256_or_si256(
			blocks[2], _mm256_slli_epi64(ind1[i], 16));

		
		memcpy(temp, (__m256i*)PK_seed_, 8 * sizeof(__m256i));
		AVX_sha512_compress4(temp, blocks);
		memcpy(keysBlocks, temp, 4 * sizeof(__m256i));
		keysBlocks += 4;
		node1 += 4;
		node2 += 4;
	}




#endif

}



// load SK
////////////////////////////////////////////////////
void FIPS205_AVX_fors_init(__m256i *in64, const uint8_t* SK_seed, uint8_t* adr)
{
	//uint8_t skADRS[ADR_SIZE];
	//memcpy(skADRS, adr, ADR_SIZE);
	init_in_block(in64, adr, SK_seed);
}

void FIPS205_AVX_fors_init_for_prf(__m256i* in64, const uint8_t* SK_seed, uint8_t* adr)
{
	in64[0] = _mm256_setzero_si256();
	in64[1] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)in64;
		
	memcpy(p, adr, ADR_SIZE);
	setType1(p, FORS_PRF);
	memset(p + 14, 0, 8);
	
	memcpy(p + ADR_SIZE, SK_seed, FIPS205_N);
	p[ADR_SIZE + FIPS205_N] = 0x80;
	int bytes = (64 + ADR_SIZE + FIPS205_N);
	p[62] = (uint8_t)(bytes >> 5);
	p[63] = (uint8_t)(bytes << 3);
	in64[0] = _mm256_shuffle_epi8(in64[0], maska_for_shuffle_32);
	in64[1] = _mm256_shuffle_epi8(in64[1], maska_for_shuffle_32);

}

void FIPS205_AVX_fors_init_for_tree(__m256i* in64, uint8_t* adr)
{
	in64[0] = _mm256_setzero_si256();
	in64[1] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)in64;

	memcpy(p, adr, ADR_SIZE);
	setType1(p, FORS_TREE);
	memset(p + 14, 0, 8);
	p[ADR_SIZE + FIPS205_N] = 0x80;
	int bytes = (64 + ADR_SIZE + FIPS205_N);
	p[62] = (uint8_t)(bytes >> 5);
	p[63] = (uint8_t)(bytes << 3);

	in64[0] = _mm256_shuffle_epi8(in64[0], maska_for_shuffle_32);
	in64[1] = _mm256_shuffle_epi8(in64[1], maska_for_shuffle_32);
}


//#define FORS_FILE
#ifdef FORS_FILE
char fn[256] = "";
FILE* f = 0;
#endif

void FIPS205_AVX_fors_z0(uint8_t node[FIPS205_N], const void* PK_seed, __m256i in64[2]/*const uint8_t* adr*/, uint32_t i)
{

	//__m256i blocks[64];
	__m256i keysBlock;

	__m256i w[64]/*, t1, t2, t3*/;
	w[0] = in64 [0];
	w[1] = in64 [1];
	uint8_t* w8 = (uint8_t*)w;
	setType1(w8, FORS_PRF);
	setTreeIndex(w8, i);
	w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_32);
	w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_32);
	memcpy(&keysBlock, (__m256i*)PK_seed, sizeof(__m256i));

	AVX_sha256_compress((uint32_t*)&keysBlock, w);
#ifdef FORS_FILE
	fprintf(f, "keysBlock step1\n");
	for (int k = 0; k < 32; ++k)
		fprintf(f, "%x ", keysBlock.m256i_u8 [k]);
	fprintf(f, "\n");
#endif

	keysBlock = _mm256_shuffle_epi8(keysBlock, maska_for_shuffle_32);

	memcpy(w8, in64, 2 * sizeof(__m256i));

	memcpy(w8 + 22, &keysBlock, FIPS205_N);
	
	setTreeHeight(w8, 0);

	setTreeIndex(w8, i);
	
	setType1(w8, FORS_TREE);
	
	w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_32);
	
	w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_32);

	//replace_key(w, keysBlock);

	memcpy(&keysBlock, (__m256i*)PK_seed, sizeof(__m256i));
		
	AVX_sha256_compress((uint32_t*)&keysBlock, w);
#ifdef FORS_FILE
	fprintf(f, "keysBlock step2\n");
	for (int k = 0; k < 32; ++k)
		fprintf(f, "%x ", keysBlock.m256i_u8 [k]);
	fprintf(f, "\n");
#endif
	
	keysBlock = _mm256_shuffle_epi8(keysBlock, maska_for_shuffle_32);

	memcpy(node, &keysBlock, FIPS205_N);
	//convert_to_keys(node, &keysBlock);

}


void FIPS205_AVX_fors_node(uint8_t node[FIPS205_N], const void* PK_256, const void* PK_256_512, __m256i in64[2], /*uint8_t * adr, */uint32_t i, uint32_t z)
{
	if (z == 0)
	{
#ifdef FORS_FILE
		fprintf(f, "z = %d node\n", z);
		fprintf(f, "call FIPS205_AVX_fors_z0 for z = %d i = %d\n", z, i);
#endif
		
		FIPS205_AVX_fors_z0(node, PK_256, in64, i);
#ifdef FORS_FILE
		for (int k = 0; k < FIPS205_N; ++k)
			fprintf(f, "%x ", node[k]);
		fprintf(f, "\n");

#endif
	}
	else
	{
		uint8_t nodes[2][FIPS205_N];
#ifdef FORS_FILE
		fprintf(f, "call FIPS205_AVX_fors_node for 2 * i = %d z - 1 = %d\n", 2 * i, z - 1);
#endif
		FIPS205_AVX_fors_node(nodes[0], PK_256, PK_256_512, in64, /*adr, */2 * i, z - 1);
#ifdef FORS_FILE
		for (int k = 0; k < FIPS205_N; ++k)
			fprintf(f, "%x ", nodes[0][k]);
		fprintf(f, "\n");

		fprintf(f, "call FIPS205_AVX_fors_node for 2 * i + 1 = %d z - 1 = %d\n", 2 * i + 1, z - 1);
#endif
		FIPS205_AVX_fors_node(nodes[1], PK_256, PK_256_512, in64, /*adr, */2 * i + 1, z - 1);
#ifdef FORS_FILE
		for (int k = 0; k < FIPS205_N; ++k)
			fprintf(f, "%x ", nodes[1][k]);
		fprintf(f, "\n");
#endif
		//AVXSetTreeHeight(in64[0], z);
		uint8_t adr[22]; 
		memcpy(adr, in64, 22);
		setTreeHeight(adr, z);
		setTreeIndex(adr, i);
#ifdef FORS_FILE
		fprintf(f, "call AVX_HASH node\n");
		fprintf(f, "node[0]\n");
		for (int k = 0; k < FIPS205_N; ++k)
			fprintf(f, "%x ", nodes[0][k]);
		fprintf(f, "\n");

		fprintf(f, "node[1]\n");
		for (int k = 0; k < FIPS205_N; ++k)
			fprintf(f, "%x ", nodes[1][k]);
		fprintf(f, "\n");

		for (int k = 0; k < 22; ++k)
			fprintf(f, "%x ", adr[k]);
		fprintf(f, "\n");
#endif
		AVX_HASH(node, PK_256_512, adr, nodes);
#ifdef FORS_FILE
		for (int k = 0; k < FIPS205_N; ++k)
			fprintf(f, "%x ", node[k]);
		fprintf(f, "\n");
#endif
	}
}




void FIPS205_AVX_fors_sk(uint8_t sk[][FIPS205_N], const uint8_t* SK_seed, const void* PK_seed, const uint8_t* adr)
{
	
	__m256i in64[16];
	__m256i blocks[64];
	__m256i keysBlocks[(FIPS205_K + 7)/8*8];
	
	uint8_t skADRS[ADR_SIZE ];
	memcpy(skADRS, adr, ADR_SIZE);
	setType(skADRS, FORS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(adr));
	
	init_in_block(in64, skADRS, SK_seed);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);

	__m256i* curKeys = keysBlocks;

	__m256i start_value = step1_sll16;

	for (uint32_t i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		
		blocks[5] = _mm256_or_si256 (
			_mm256_and_si256(_mm256_set1_epi32 (0x0000FFFF), blocks[5]), 
			/*blocks[5], */start_value);

		start_value = _mm256_add_epi32(start_value, eight_256);

		memcpy(curKeys, (__m256i*)PK_seed, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;
		
		
	}
	
	convert_to_keys(sk, keysBlocks);

}


// Keys for HASH tree
void FIPS205_AVX_fors_sks(uint8_t *sk, 
	__m256i *in_block, 
	const void* PK_seed, 
	uint32_t *ind)
{

	__m256i in64[16];
	__m256i blocks[64];
	__m256i keysBlocks[(FIPS205_K + 7) / 8 * 8];
	__m256i* ind256 = (__m256i*)ind;
	
	in64 [0] = in_block [0];
	in64 [1] = in_block [1];
	uint8_t* in64_8 = (uint8_t*)in64;
	setType1(in64_8, FORS_PRF);
	//in64[0] = _mm256_shuffle_epi8(in64[0], maska_for_shuffle_32);
	//in64[1] = _mm256_shuffle_epi8(in64[1], maska_for_shuffle_32);
		
	//init_in_block(in64, skADRS, SK_seed);
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);

	__m256i* curKeys = keysBlocks;

	__m256i start_value = fors_step1_sll16;

	for (uint32_t i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		blocks[4] = _mm256_and_si256(blocks[4], _mm256_set1_epi32(0xFFFF0000));
		blocks[4] = _mm256_or_si256(
			blocks[4], _mm256_srli_epi32(*ind256, 16));
		blocks[5] = _mm256_and_si256(blocks[5], _mm256_set1_epi32(0x0000FFFF));
		blocks[5] = _mm256_or_si256(
			blocks[5], _mm256_or_si256 (start_value, _mm256_slli_epi32 (*ind256++, 16)));

		start_value = _mm256_add_epi32(start_value, fors_eight_256);

		memcpy(curKeys, (__m256i*)PK_seed, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;

	}
	uint8_t(*psk)[FIPS205_N] = (uint8_t(*)[FIPS205_N])sk;
	convert_to_keys(psk, keysBlocks);

}


// pred
uint8_t * FIPS205_AVX_fors_sign__(uint8_t* SigFors, uint8_t* md,
	__m256i* in_block,
	const void* PK_seed, const void* BLOCK_PK_seed, const void* HASH_PK_seed
	//const void* PK_seed,		// 256_BLOCK
	//const void* PK_seed_n		// 256 or 512 singl

)
{
	ALIGN64 uint32_t ind[(FIPS205_K + 7) / 8 * 8] = { 0 };
	ALIGN64 uint32_t calc_ind[(FIPS205_K + 7) / 8 * 8] = { 0 };
	__m256i* pind = (__m256i*) ind;
	__m256i* pcalc_ind = (__m256i*) calc_ind;
	

	fors_base(ind, md, FIPS205_K);
	//memcpy(calc_ind, ind, sizeof(ind));
	__m256i begin_ind = _mm256_setr_epi32(
		0 * (1 << FIPS205_A), 1 * (1 << FIPS205_A), 2 * (1 << FIPS205_A), 3 * (1 << FIPS205_A),
		4 * (1 << FIPS205_A), 5 * (1 << FIPS205_A), 6 * (1 << FIPS205_A), 7 * (1 << FIPS205_A));
	__m256i step_ind = _mm256_set1_epi32(8 * (1 << FIPS205_A));
	for (int i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		pcalc_ind[i] = _mm256_add_epi32(pind[i], begin_ind);
		begin_ind = _mm256_add_epi32(begin_ind, step_ind);
	}

	uint8_t* pSigFors = SigFors;
	uint8_t* p_path = SigFors + FIPS205_K * FIPS205_N;
	uint8_t sk[FIPS205_K][FIPS205_N];

	FIPS205_AVX_fors_sks((uint8_t*)sk, in_block, BLOCK_PK_seed, calc_ind);
	//FIPS205_AVX_fors_sks((uint8_t*)sk, in_block, PK_seed, calc_ind);
	
	int count = 0;
	for (int i = 0; i < FIPS205_K; ++i)
	{
		/*if (i == 0x15)
			printf("");*/
#ifdef FORS_FILE
		sprintf(fn, "FORS_FILE_%d.txt", i);
		f = fopen(fn, "wt");
		fprintf(f, "ind[i] = %d\n", ind[i]);
		fprintf(f, "sk\n");
		for (int k = 0; k < FIPS205_N; ++k)
			fprintf(f, "%x ", sk[i][k]);
		fprintf(f, "\n");
#endif
		//char fn[256];
		//FILE* f;
		
		

		
		memcpy(pSigFors, sk[i], FIPS205_N);
		/*++count;
		if (count == 316 || count == 317 || (pSigFors[0] == 0xEF && pSigFors[1] == 0x76 && pSigFors[2] == 0x80 ))
			printf("");*/
		pSigFors += FIPS205_N;
		//uint8_t node[FIPS205_N];
		for (int j = 0; j < FIPS205_A; ++j)
		{
			/*if (i == 16 && j == 0)
				printf("");*/
			uint32_t s = (ind[i] >> j) ^ 1;
#ifdef FORS_FILE

			fprintf(f, "i = %d j = %d\n", i, j);
			fprintf(f, "s = %d\n", s);
			fprintf(f, "call FIPS205_AVX_fors_node for %d\n", i * (1 << (FIPS205_A - j)));

#endif

			FIPS205_AVX_fors_node(pSigFors, PK_seed, HASH_PK_seed, in_block, i * (1 << (FIPS205_A - j)) + s, j);
			//FIPS205_AVX_fors_node(pSigFors, PK_seed, PK_seed_n, in_block, i * (1 << (FIPS205_A - j)) + s, j);
			/*if (pSigFors[0] == 0xfc && pSigFors[1] == 0xc1)
				printf("");*/
#ifdef FORS_FILE
			fprintf(f, "i = %d j = %d auth \n", i, j);
			for (int k = 0; k < FIPS205_N; ++k)
				fprintf(f, "%x ", pSigFors[k]);
			fprintf(f, "\n");


#endif
			/*++count;
			{
				
				
				if ( 
					count == 316 || count == 317 || (pSigFors[0] == 0xEF && pSigFors[1] == 0x76 && pSigFors[2] == 0x80))
					printf("");
			}*/
			
			pSigFors += FIPS205_N;
		}
#ifdef FORS_FILE
		fclose(f);
#endif
	}
	
	return SigFors + FIPS205_K * FIPS205_N * (1 + FIPS205_A);;

}

/// <summary>
/// /////////////////////////
/// </summary>
/// <param name="sk"></param>
/// <param name="in_block"></param>
/// <param name="PK_seed_"></param>
/// <param name="ind256"></param>
void fors_get_node_sk(uint8_t sk[][FIPS205_N], const  __m256i* in_block, const void* PK_seed_, __m256i* ind256)
//void fors_get_node_sk(/*uint8_t sk[][FIPS205_N]*/__m256i keysBlocks[(FIPS205_K + 7) / 8 * 8 ], const  __m256i* in_block, const void* PK_seed_, __m256i* ind256)
{
	__m256i in64[16];
	__m256i blocks[64];
	__m256i keysBlocks[(FIPS205_K + 7) / 8 * 8];
	in64[0] = in_block[0];
	in64[1] = in_block[1];
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);
	// type
	blocks[2] = _mm256_or_si256(
		_mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]),
		_mm256_set1_epi32(FORS_PRF << 16));

	// treeheight
	blocks[3] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[3]);
	//blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks[4]);
	__m256i* curKeys = keysBlocks;
	//__m256i start_value = fors_step1_sll16;

	uint32_t i;
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[4]);
		blocks[4] = _mm256_or_si256(
			blocks[4], _mm256_srli_epi32(*ind256, 16));
		blocks[5] = _mm256_and_si256(blocks[5], _mm256_set1_epi32(0x0000FFFF));
		blocks[5] = _mm256_or_si256(
			blocks[5], _mm256_slli_epi32(*ind256++, 16));

		//start_value = _mm256_add_epi32(start_value, fors_eight_256);

		memcpy(curKeys, (__m256i*)PK_seed_, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;

	}
	
	convert_to_keys(sk, keysBlocks);

}

void fors_get_node_sk_(__m256i keysBlocks[(FIPS205_K + 7) / 8 * 8], const  __m256i* in_block, const void* PK_seed_, __m256i* ind256)
//void fors_get_node_sk(/*uint8_t sk[][FIPS205_N]*/__m256i keysBlocks[(FIPS205_K + 7) / 8 * 8 ], const  __m256i* in_block, const void* PK_seed_, __m256i* ind256)
{
	__m256i in64[16];
	__m256i blocks[64];
	//__m256i keysBlocks[(FIPS205_K + 7) / 8 * 8];
	in64[0] = in_block[0];
	in64[1] = in_block[1];
	memcpy(in64 + 2, in64, 2 * sizeof(__m256));
	memcpy(in64 + 4, in64, 4 * sizeof(__m256));
	memcpy(in64 + 8, in64, 8 * sizeof(__m256));

	create_blocks_for_in64(blocks, in64);
	// type
	blocks[2] = _mm256_or_si256(
		_mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]),
		_mm256_set1_epi32(FORS_PRF << 16));

	// treeheight
	blocks[3] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[3]);
	//blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks[4]);
	__m256i* curKeys = keysBlocks;
	//__m256i start_value = fors_step1_sll16;

	uint32_t i;
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[4]);
		blocks[4] = _mm256_or_si256(
			blocks[4], _mm256_srli_epi32(*ind256, 16));
		blocks[5] = _mm256_and_si256(blocks[5], _mm256_set1_epi32(0x0000FFFF));
		blocks[5] = _mm256_or_si256(
			blocks[5], _mm256_slli_epi32(*ind256++, 16));

		//start_value = _mm256_add_epi32(start_value, fors_eight_256);

		memcpy(curKeys, (__m256i*)PK_seed_, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;

	}

	//convert_to_keys(sk, keysBlocks);

}

///////////////////////////////////////////////////
void fors_get_node_z0__(__m256i* keysBlocks,  const  __m256i* in_block, const void* PK_seed_, const __m256i* ind256)
{
	__m256i in64[16];
	__m256i blocks[64];

	in64[0] = in_block[0];
	in64[1] = in_block[1];
	uint8_t* in8 = (uint8_t*)in64;
	setTreeHeight(in8, 0);
	setType1(in8, FORS_PRF);
	

	{

		//__m256i temp[16];

		in64[0] = _mm256_shuffle_epi8(in64[0], maska_for_shuffle_32);	// key after shuffle
		in64[1] = _mm256_shuffle_epi8(in64[1], maska_for_shuffle_32);	// key after shuffle
		memcpy(in64 + 2, in64, 2 * sizeof(__m256));
		memcpy(in64 + 4, in64, 4 * sizeof(__m256));
		memcpy(in64 + 8, in64, 8 * sizeof(__m256));

		uint32_t* temp32 = (uint32_t*)in64;

		for (int i = 0; i < 16; ++i)
		{
			blocks[i] = _mm256_i32gather_epi32((const int*)temp32, idx16, 4);
			++temp32;
		}

	}


	__m256i* curKeys = keysBlocks;

	__m256i cur_ind[(FIPS205_K + 7) / 8];// = ind256;
	memcpy(cur_ind, ind256, (FIPS205_K + 7) / 8 * sizeof(__m256i));

	uint32_t i;
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[4]);
		blocks[4] = _mm256_or_si256(
			blocks[4], _mm256_srli_epi32(cur_ind[i], 16));
		blocks[5] = _mm256_and_si256(blocks[5], _mm256_set1_epi32(0x0000FFFF));
		blocks[5] = _mm256_or_si256(
			blocks[5], _mm256_slli_epi32(cur_ind[i], 16));

		memcpy(curKeys, (__m256i*)PK_seed_, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;

	}

	//memcpy(cur_ind, ind256, (FIPS205_K + 7) / 8 * sizeof(__m256i));

	blocks[2] = _mm256_or_si256(
		_mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]),
		_mm256_set1_epi32(FORS_TREE << 16));


	curKeys = keysBlocks;


	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[4]);
		blocks[4] = _mm256_or_si256(
			blocks[4], _mm256_srli_epi32(cur_ind[i], 16));

		blocks[5] = _mm256_and_si256(blocks[5], _mm256_set1_epi32(0x0000FFFF));
		blocks[5] = _mm256_or_si256(
			blocks[5], _mm256_slli_epi32(cur_ind[i], 16));

		replace_blocks_key8__(blocks, curKeys);

		memcpy(curKeys, (__m256i*)PK_seed_, 8 * sizeof(__m256i));

		AVX_sha256_compress8(curKeys, blocks);

		curKeys += 8;
	}




}

// It is for Hash
/////////////////////////////////////////////////////////////
void fors_get_node_z0_(__m256i* keysBlocks, /*uint8_t node [][FIPS205_N],*/ const  __m256i* in_block, const void* PK_seed_, const __m256i *ind256)
{
	
	fors_get_node_z0__(keysBlocks, in_block, PK_seed_, ind256);
	
#if FIPS205_N != 16
	__m256i temp[8];
	for (uint32_t i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		memcpy(temp, keysBlocks, 8 * sizeof(__m256i));
		convert_32_64(keysBlocks, temp);
		keysBlocks += 8;
	}

#endif
}

// It is for main function



/////////////////////////////////////////////////////////////////
void FIPS205_AVX_fors_node_(__m256i * keysBlocks, const __m256i *in_block, const __m256i *in_block_for_H, const void* BLOCK_PK_seed, const void* BLOCK_HASH_PK_seed, const __m256i *cur_ind, uint32_t z)
{
	
	
	
	if (z == 0)
	{

		fors_get_node_z0_(keysBlocks, in_block, BLOCK_PK_seed, cur_ind);
		
	}
	else
	{
		__m256i keysBlocks1[(FIPS205_K + 7) / 8 * 8], keysBlocks2[(FIPS205_K + 7) / 8 * 8];
		__m256i cur_ind_[(FIPS205_K + 7) / 8];
		for (int k = 0; k < (FIPS205_K + 7) / 8; ++k)
			cur_ind_[k] = _mm256_slli_epi32(cur_ind[k], 1);
				
		FIPS205_AVX_fors_node_(keysBlocks1, in_block , in_block_for_H, BLOCK_PK_seed, BLOCK_HASH_PK_seed, cur_ind_, /*2 * i, */z - 1);
		for (int k = 0; k < (FIPS205_K + 7) / 8; ++k)
			cur_ind_[k] = _mm256_add_epi32(cur_ind_[k], _mm256_set1_epi32 (1));
		FIPS205_AVX_fors_node_ (keysBlocks2, in_block, in_block_for_H, BLOCK_PK_seed, BLOCK_HASH_PK_seed, cur_ind_, /*2 * i + 1, */z - 1);
		FIPS205_AVX_fors_H_(keysBlocks, in_block_for_H, BLOCK_HASH_PK_seed, keysBlocks1, keysBlocks2, cur_ind, z);
			
	}
	
}

/////////////////////////////////////////////////////////////
// next
uint8_t* FIPS205_AVX_fors_sign(
	uint8_t* SigFors, 
	const uint8_t* md,
	//__m256i* in_block,
	const uint8_t *SK_seed, 
	//const void* PK_seed_,		// one for 256 / 512  
	const void* PK_seed,		// block for 256
	const void* PK_seed_n,		// block for 256/512
	uint8_t *adr)
{
	ALIGN32 uint32_t ind[(FIPS205_K + 7) / 8 * 8] = { 0 };
	__m256i* ind256 = (__m256i*)ind;
	fors_base(ind, md, FIPS205_K);
	
	__m256i in_block[2];
#if FIPS205_N == 16
	__m256i in_block_for_H[2];
#else
	__m256i in_block_for_H[4];
#endif
	FIPS205_AVX_fors_init(in_block, SK_seed, adr);
	FIPS205_AVX_fors_init_in_block0 (in_block_for_H, adr);
	uint8_t* pSigFors = SigFors;
	uint8_t* p_path = SigFors + FIPS205_K * FIPS205_N;
	uint8_t sk[FIPS205_K][FIPS205_N];
	uint32_t i, j;
	__m256i start_value =
		_mm256_setr_epi32(
			0 * ((1 << (FIPS205_A))),
			1 * ((1 << (FIPS205_A))),
			2 * ((1 << (FIPS205_A))),
			3 * ((1 << (FIPS205_A))),
			4 * ((1 << (FIPS205_A))),
			5 * ((1 << (FIPS205_A))),
			6 * ((1 << (FIPS205_A))),
			7 * ((1 << (FIPS205_A)))
		);
	
	__m256i h_value = _mm256_set1_epi32(8 * (1 << (FIPS205_A)));

	__m256i cur_value = start_value;

	__m256i cur_ind [(FIPS205_K + 7) / 8 ];
	
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		cur_ind[i] = _mm256_or_si256(cur_value, ind256[i]);
		cur_value = _mm256_add_epi32(cur_value, h_value);
	}
	
	__m256i sk_256[(FIPS205_K + 7) / 8 * 8];
	//fors_get_node_sk(sk, in_block, PK_seed, cur_ind);
	fors_get_node_sk_(sk_256, in_block, PK_seed, cur_ind);
	convert_to_keys(sk, sk_256);
		
		
	for (i = 0; i < FIPS205_K; ++i)
	{
		memcpy(pSigFors, sk[i], FIPS205_N);
		pSigFors += FIPS205_N + FIPS205_A * FIPS205_N;
	}
	
	uint8_t *pAuth = SigFors + FIPS205_N;
	
	ind256 = (__m256i*)ind;
	
	for (j = 0; j < FIPS205_A; ++j)
	{
		__m256i node[(FIPS205_K + 7) / 8 * 16];
		
		uint8_t* curpAuth = pAuth;
		ind256 = (__m256i*)ind;
		__m256i start_value =
			_mm256_setr_epi32(
				0 * ((1 << (FIPS205_A - j))),
				1 * ((1 << (FIPS205_A - j))),
				2 * ((1 << (FIPS205_A - j))),
				3 * ((1 << (FIPS205_A - j))),
				4 * ((1 << (FIPS205_A - j))),
				5 * ((1 << (FIPS205_A - j))),
				6 * ((1 << (FIPS205_A - j))),
				7 * ((1 << (FIPS205_A - j)))
			);
		cur_value = start_value;
		__m256i step_value = _mm256_set1_epi32(8 * ((1 << (FIPS205_A - j))));

		__m256i s256[(FIPS205_K + 7) / 8];

		for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
		{
			s256[i] = _mm256_xor_si256(_mm256_srli_epi32(ind256[i], j), _mm256_set1_epi32(1));
			cur_ind[i] = _mm256_or_si256(cur_value, s256[i]);
			cur_value = _mm256_add_epi32(cur_value, step_value);
		}
		
		
		uint32_t t = j;
		//uint32_t iter = 1;
		uint32_t cvt_type32;
		if (t == 0)
		{
			cvt_type32 = 1;
			fors_get_node_z0__(node, in_block, PK_seed, cur_ind);
				
		}
		else
		{
			cvt_type32 = 0;
			FIPS205_AVX_fors_node_(
					node, in_block, in_block_for_H, PK_seed, PK_seed_n, cur_ind, /*iter, */t);
		}
		if (cvt_type32)
			convert_to_keys(sk, node);
		else
		{
#if FIPS205_N == 16
			convert_to_keys(sk, node);
#else
			
			convert_to_keys_64_(sk, node);
#endif	
		}

		for (i = 0; i < FIPS205_K; ++i)
		{
			memcpy(curpAuth, sk[i], FIPS205_N);

			curpAuth += FIPS205_N + FIPS205_A * FIPS205_N;
		}
		
		pAuth += FIPS205_N;
	}



	return SigFors + FIPS205_K * FIPS205_N * (1 + FIPS205_A);
	

}


	


void FIPS205_AVX_read_sk(__m256i sk[(FIPS205_K + 7)/8 * 8], const uint8_t* SigFors)
{
	uint8_t* pSigFors = (uint8_t*)SigFors;
	uint32_t i, j;
	
	__m256i temp[(FIPS205_K + 7) / 8 * 8] = {0};
	for (i = 0; i < FIPS205_K; ++i)
	{
		memcpy(&temp[i], pSigFors, FIPS205_N);
		temp[i] = _mm256_shuffle_epi8(temp[i], maska_for_shuffle_32);
		pSigFors += FIPS205_N + FIPS205_A * FIPS205_N;
	}

	uint32_t* temp32 = (uint32_t*)temp;

	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		temp32 = (uint32_t*)(temp + 8 * i);
		for (j = 0; j < 8; ++j)
		{
			sk[i * 8 + j]  = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
			
		}
		
	}
}


#if FIPS205_N == 16
void FIPS205_AVX_read_auth(__m256i auth[FIPS205_A][(FIPS205_K + 7)/8*8], const uint8_t* SigFors)
#else
void FIPS205_AVX_read_auth(__m256i auth[FIPS205_A][((FIPS205_K + 7) / 8 * 8)], const uint8_t* SigFors)
#endif
{
	//memset(auth, 0, FIPS205_A * FIPS205_K * sizeof(__m256i));
	uint32_t i, j, k;
	uint64_t offset1 = FIPS205_N, offset2;

	__m256i temp[FIPS205_A][(FIPS205_K + 7)/8 * 8] = {0}, temp_;


	for (i = 0; i < FIPS205_K; ++i)
	{
		offset2 = offset1;
		for (j = 0; j < FIPS205_A; ++j)
		{
			//if (i == 10 && j == 0)
			//	printf("");
			memcpy(&temp[j][i], SigFors + offset2, FIPS205_N);
			//temp[j][i] = _mm256_shuffle_epi8(temp[j][i], maska_for_shuffle_32);
			//auth[j][i] = temp;
			offset2 += FIPS205_N;
		}
		offset1 += (FIPS205_A + 1) * FIPS205_N;
	}

#if FIPS205_N == 16
	
	for (i = 0; i < FIPS205_A; ++i)
	{
		uint32_t* temp32;
		for (j = 0; j < (FIPS205_K + 7) / 8; ++j)
		{
			temp32 = (uint32_t*)&temp[i][8 * j];

			for (k = 0; k < 8; ++k) {
				temp_ = _mm256_i32gather_epi32((const int*)temp32++, idx8, 4);
				auth[i][j * 8 + k] = _mm256_shuffle_epi8(temp_, maska_for_shuffle_32);
			}

		}
		//sk += 8;
	}
#else
	__m128i idx = _mm_setr_epi32(0, 4, 8, 12);
	uint64_t* temp64;
	for (i = 0; i < FIPS205_A; ++i)
	{
		
		
		for (j = 0; j < (FIPS205_K + 7) / 8; ++j)
		{

			temp64 = (uint64_t*)&temp[i][8 * j];
			for (k = 0; k < 4; ++k)
			{

				temp_ = _mm256_i32gather_epi64((const int64_t*)temp64++, idx, 8);
				auth[i][8 * j + k] = _mm256_shuffle_epi8(temp_, maska_for_shuffle_64);
			}

			temp64 = (uint64_t*)&temp[i] [8 * j + 4];

			for (k = 4; k < 8; ++k)
			{
				// temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
				// _mm256_i32gather_epi64((__int64 const*)temp, idx, 8);
				temp_ = _mm256_i32gather_epi64((const int64_t*)temp64++, idx, 8);
				//temp = _mm256_shuffle_epi8(temp, maska_for_shuffle_32);
				auth[i][8 * j + k] = _mm256_shuffle_epi8(temp_, maska_for_shuffle_64);

			}
			//block_keys += 4;
		}
	}
#endif

}

void FIPS205_AVX_calc_node0(__m256i node0[], __m256i *PK_seed, __m256i blocks[], __m256i* ind, __m256i *sk)
{
	__m256i* psk_256 = (__m256i*)sk;
	uint32_t i;
	//__m256i temp_block2 = blocks[2];
	
	/*blocks[2] = _mm256_or_si256(
		_mm256_andnot_si256(_mm256_set1_epi32(0x00FF0000), blocks[2]),
		_mm256_set1_epi32(FORS_PRF << 16));*/
	__m256i* pnode0 = node0;
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		blocks[4] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[4]);
		blocks[4] = _mm256_or_si256(
			blocks[4], _mm256_srli_epi32(ind[i], 16));
		blocks[5] = _mm256_and_si256(blocks[5], _mm256_set1_epi32(0x0000FFFF));
		blocks[5] = _mm256_or_si256(
			blocks[5], _mm256_slli_epi32(ind[i], 16));

		replace_blocks_key8__(blocks, sk);

		memcpy(node0, PK_seed, 8 * sizeof(__m256i));

		AVX_sha256_compress8(node0, blocks);

#if FIPS205_N < 32
		node0[6] = node0 [7] = _mm256_setzero_si256();
#endif
#if FIPS205_N < 24
		node0[4] = node0[5] = _mm256_setzero_si256();
#endif
		node0 += 8;

		sk += 8;
	}

#if FIPS205_N != 16
	__m256i temp[8];
	//for (i = 0; i < FIPS205_A; ++i)
	//{
		//__m256i* pauth = pnode0;
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
			memcpy(temp, pnode0, 8 * sizeof(__m256i));
			convert_32_64(pnode0, temp);
			pnode0 += 8;
		
	}

#endif
	
}


void FIPS205_AVX_calc_node1(
	__m256i node1_blocks[2 * (FIPS205_K + 7) / 8 * 8], 
	const __m256i *predcalc_pk,			// block 128 or 256
	const __m256i *blocks, 
	uint32_t j, 
	const __m256i* ind, 
	__m256i* cur_ind, 
	const __m256i* node0, 
	const __m256i* auth )
{
	
//#if FIPS205_N == 16
	__m256i ind_2j[(FIPS205_K + 7) / 8 /** 8*/], odd/*, temp[8]*/;
	__m256i temp_node1 [2 * (FIPS205_K + 7) / 8 * 8], temp_node2[(FIPS205_K + 7) / 8 * 8];
	uint32_t i, k;
	for (i = 0; i < (FIPS205_K + 7) / 8 ; ++i)
	{
		ind_2j[i] = _mm256_srli_epi32(ind[i], j);
		odd = _mm256_sub_epi32(_mm256_setzero_si256(), _mm256_and_si256(ind_2j[i], _mm256_set1_epi32(1)));
		cur_ind[i] = _mm256_srli_epi32(_mm256_add_epi32(cur_ind[i], odd), 1);
		// set Tree Index (cur_ind);
#if FIPS205_N == 16
		for (k = 0; k < 8; ++k)
		{
			temp_node1[i * 8 + k] = _mm256_blendv_epi32(node0[i * 8 + k], auth[i * 8 + k], odd);
			temp_node2[i * 8 + k] = _mm256_blendv_epi32(auth [i * 8 + k], node0[i * 8 + k], odd);
		}
#else
		__m256i odd0 = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(odd, 0));
		__m256i odd1 = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(odd, 1));
				
		for (k = 0; k < 4; ++k)
		{
			 temp_node1 [i * 8  + k ] = _mm256_blendv_epi64(node0 [i * 8 + k], auth [i * 8 + k], odd0);
			 temp_node2 [i * 8  + k ] = _mm256_blendv_epi64(auth  [i * 8 + k], node0[i * 8 + k], odd0);
			 temp_node1[i * 8 + 4 + k] = _mm256_blendv_epi64(node0[i * 8 + 4 + k], auth[i * 8 + 4 + k], odd1);
			 temp_node2[i * 8 + 4 + k] = _mm256_blendv_epi64(auth[i * 8 + 4 + k], node0[i * 8 + 4 + k], odd1);
		}
#endif
	}


	FIPS205_AVX_fors_H_(node1_blocks, blocks, predcalc_pk, temp_node1, temp_node2, cur_ind, j + 1);
}


void FIPS205_AVX_fors_pkFromSig(
	uint8_t *pkFromSig,
	const uint8_t* SigFors,
	const uint8_t* md,
	const void* PK_seed_,		// one 256 0r 512
	const void* PK_seed,		// block 256
	const void* PK_seed_n,		// block 512
	uint8_t* adr)
{
	
	
	const uint8_t* pSigFors = SigFors;
	

	
	
	__m256i node0[(FIPS205_K + 7) / 8 * 8], node1[(FIPS205_K + 7) / 8 * 8];
	
	__m256i *sk_256 = node0;

	__m256i auth[FIPS205_A][(FIPS205_K + 7) / 8 * 8];

	FIPS205_AVX_read_sk(sk_256, SigFors);  // sk_256 in block format

	FIPS205_AVX_read_auth(auth, SigFors);

	uint32_t i, j, k = 0;
	
	__m256i start_value =
		_mm256_setr_epi32(
			0 * ((1 << (FIPS205_A))),
			1 * ((1 << (FIPS205_A))),
			2 * ((1 << (FIPS205_A))),
			3 * ((1 << (FIPS205_A))),
			4 * ((1 << (FIPS205_A))),
			5 * ((1 << (FIPS205_A))),
			6 * ((1 << (FIPS205_A))),
			7 * ((1 << (FIPS205_A)))
		);

	__m256i h_value = _mm256_set1_epi32(8 * (1 << (FIPS205_A)));

	ALIGN32 uint32_t ind[(FIPS205_K + 7) / 8 * 8] = { 0 };
	fors_base(ind, md, FIPS205_K);

	__m256i cur_value = start_value;

	__m256i cur_ind[(FIPS205_K + 7) / 8] = {0};


	__m256i* ind256 = (__m256i*)ind;

	
	for (i = 0; i < (FIPS205_K + 7) / 8; ++i)
	{
		cur_ind[i] = _mm256_or_si256(cur_value, ind256[i]);
		cur_value = _mm256_add_epi32(cur_value, h_value);
	}
	
	__m256i in_block[64];

#if FIPS205_N == 16
	__m256i in_block_for_H[2];
#else
	__m256i in_block_for_H[4];
#endif

	FIPS205_AVX_fors_init_in_block0(in_block_for_H, adr);
	
	in_block[0] = _mm256_setzero_si256();
	in_block[1] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)in_block;
	memcpy(p, adr, ADR_SIZE);
	p[ADR_SIZE + FIPS205_N] = 0x80;
	int bytes = (64 + ADR_SIZE + FIPS205_N);
	p[62] = (uint8_t)(bytes >> 5);
	p[63] = (uint8_t)(bytes << 3);

	in_block[0] = _mm256_shuffle_epi8(in_block[0], maska_for_shuffle_32);
	in_block[1] = _mm256_shuffle_epi8(in_block[1], maska_for_shuffle_32);

	__m256i blocks[64];
	memcpy(in_block + 2, in_block, 2 * sizeof(__m256));
	memcpy(in_block + 4, in_block, 4 * sizeof(__m256));
	memcpy(in_block + 8, in_block, 8 * sizeof(__m256));

	uint32_t* temp32 = (uint32_t*)in_block;


	for (int i = 0; i < 16; ++i)
	{
		blocks[i] = _mm256_i32gather_epi32((const int*)temp32, idx16, 4);
		++temp32;
	}
	

	blocks[3] = _mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks[3]); // tree_height

	FIPS205_AVX_calc_node0(node0, PK_seed, blocks, cur_ind, sk_256);
	
	for (j = 0; j < FIPS205_A; ++j)
	{

		
		FIPS205_AVX_calc_node1(node0, PK_seed_n, in_block_for_H, j, ind256, cur_ind, node0, auth[j]);

		
	}
	uint8_t forspkADRS[ADR_SIZE];
	memcpy(forspkADRS, adr, ADR_SIZE);
	setType1(forspkADRS, FORS_ROOTS);

#if FIPS205_N == 16
	convert_to_keys_64_256(node1, node0);
#else
	convert_to_keys_128_256(node1, node0);
#endif
	AVX_Tl(pkFromSig, PK_seed_, forspkADRS, node1, FIPS205_K);

}

//in_block_for_H;
uint8_t * FIPS205_AVX_fors_sign_new(uint8_t *sign, uint8_t *md, /*auth[FIPS205_K][FIPS205_A][FIPS205_N], */const uint8_t * SK_seed, const void* PK_256, const void* PK_256_512, /*__m256i in64[2], */uint8_t * adr)
{
	int i;
	//omp_set_num_threads(8);
	ALIGN32 uint32_t ind[FIPS205_K ] = { 0 };
	
	fors_base(ind, md, FIPS205_K);

	
	
	#pragma omp parallel for
		for (i = 0; i < FIPS205_K; ++i)
		{
			__m256i perenos = _mm256_set1_epi32((i * (1 << FIPS205_A) >> 16));
			__m256i start_value = _mm256_add_epi32(step1_sll16, _mm256_set1_epi32((i * (1 << FIPS205_A)) << 16));
			uint8_t* psign = sign + i * FIPS205_N * (1 + FIPS205_A);
			uint32_t cur_ind = ind[i]; // _mm256_set1_epi32(ind[i] * (1 << i));
			__m256i in_block_for_prf[2];
			__m256i in_block_for_tree[2];
			uint32_t j;
#if FIPS205_N == 16
			__m256i in_block_for_H[2];
			__m256i state;
#else
			__m256i in_block_for_H[4];
			__m256i state[2];
#endif

			__m256i blocks_64_prf[64];
			__m256i blocks_64_tree[64];

//#if FIPS205_N > 16
//			__m256i blocks_128[80];
//#endif

			FIPS205_AVX_fors_init_for_prf(in_block_for_prf, SK_seed, adr);
			FIPS205_AVX_fors_init_for_tree(in_block_for_tree, adr);
			FIPS205_AVX_fors_init_in_block0(in_block_for_H, adr);

			
			__m256i temp[16];

			memcpy(temp, in_block_for_prf, 2 * sizeof(__m256i));
			memcpy(temp + 2, temp, 2 * sizeof(__m256i));
			memcpy(temp + 4, temp, 4 * sizeof(__m256i));
			memcpy(temp + 8, temp, 8 * sizeof(__m256i));

			uint32_t* temp32 = (uint32_t*)temp;
			for (j = 0; j < 16; ++j)
			{
				blocks_64_prf[j] = _mm256_i32gather_epi32((const int*)temp32++, idx16, 4);

			}
			temp32 = (uint32_t*)temp;

			memcpy(temp, in_block_for_tree, 2 * sizeof(__m256i));
			memcpy(temp + 2, temp, 2 * sizeof(__m256i));
			memcpy(temp + 4, temp, 4 * sizeof(__m256i));
			memcpy(temp + 8, temp, 8 * sizeof(__m256i));

			for (j = 0; j < 16; ++j)
			{
				blocks_64_tree[j] = _mm256_i32gather_epi32((const int*)temp32++, idx16, 4);

			}



			//__m256i blocks[64];
#if FIPS205_N == 16
			__m256i blocks_[64];
#else
			__m256i blocks_[80];
#endif
			
			
			
			uint8_t *pblocks = (uint8_t*)in_block_for_H;
#if 0
			__m256i temp1[1 << FIPS205_A];
			__m256i temp2[1 << FIPS205_A];
#else
			__m256i* temp1 = (__m256i*)_aligned_malloc(((1 << (FIPS205_A + 1)) * sizeof(__m256i)), 32);
			if (!temp1) {
				// Handle allocation error
				//return NULL;
			}
			__m256i* temp2 = temp1 + (1 << FIPS205_A);
#endif
			
			uint32_t k = 0, l = 0, r = FIPS205_A;
			
			
			//__m256i curKeys [8];
			__m256i t;
			uint32_t need_j = ind[i] / 8;
			uint32_t need_k = ind[i] % 8;
			uint32_t need_k_ = need_k ^ 1;
			uint32_t* block_keys_32;
			
			for (j = 0; j < (1 << FIPS205_A) / 8; ++j)
			{
				/*blocks_64_prf[4] = _mm256_or_si256(
					_mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks_64_prf[4]),
					perenos);*/
				blocks_64_prf[4] = perenos;
				blocks_64_prf[5] = _mm256_or_si256(
					_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_prf[5]),
					start_value);

				
				memcpy(temp1 + 8 * j, (__m256i*)PK_256, 8 * sizeof(__m256i));

				
				AVX_sha256_compress8(temp1 + 8 * j, blocks_64_prf);

				/*blocks_64_tree[4] = _mm256_or_si256(
					_mm256_and_si256(_mm256_set1_epi32(0xFFFF0000), blocks_64_tree[4]),
					perenos);*/
				blocks_64_tree[4] = perenos;

				blocks_64_tree[5] = _mm256_or_si256(
					_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_tree[5]),
					start_value);
				replace_blocks_key8__(blocks_64_tree, temp1 + j * 8);

				memcpy(temp2 + j * 8, (__m256i*)PK_256, 8 * sizeof(__m256i));
				//memcpy(blocks, blocks_64_tree, 64 * sizeof(__m256i));
				AVX_sha256_compress8(temp2 + j * 8, blocks_64_tree);

				start_value = _mm256_add_epi32(start_value, eight_256);
				
						
			}
			
			
			
			block_keys_32 = (uint32_t*)(temp1 + 8 * need_j);
			for (k = 0; k < need_k; ++k)
			{
				t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
				//t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
				/*memcpy(dest, &t, FIPS205_N);
				dest += sizeof(__m256i);*/
			}
			t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
			t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
			memcpy(psign, &t, FIPS205_N);
			psign += FIPS205_N;
						

			block_keys_32 = (uint32_t*)(temp2);
			uint8_t* dest = (uint8_t*)temp1;
			for (j = 0; j < (1 << FIPS205_A) / 8; ++j)
			{
				
				block_keys_32 = (uint32_t*)(temp2 + 8 * j);
				
				for (k = 0; k < 8; ++k)
				{
					t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
					t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
					memcpy(dest, &t, FIPS205_N);
					dest += sizeof(__m256i);
				}
				
			}
			
			
			memcpy(psign, temp1 + 8 * need_j + need_k_, FIPS205_N);
			psign += FIPS205_N;

						
			r = 1 << FIPS205_A;
			uint32_t th = 1;
			//uint32_t s = ind[i] ^ 1;
			
			
			while (r != 2)
			{
				ind[i] /= 2;
				setTreeHeight(pblocks, th);
				uint32_t tree_ind_const = i * (1 << (FIPS205_A - th));
				for (k = 0; k < r / 2; ++k)
				{
					/*if (k == 64)
						printf("");*/
					//uint32_t tree_ind_const = 1 << (FIPS205_A - th);
					setTreeIndex(pblocks, tree_ind_const + k);
					memcpy(pblocks + ADR_SIZE, &temp1[2 * k], FIPS205_N);
					memcpy(pblocks + ADR_SIZE + FIPS205_N, &temp1[2 * k + 1], FIPS205_N);
					

					#if FIPS205_N == 16
						blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
						blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);
						memcpy(&state, (uint8_t*)PK_256_512, sizeof(state));
						AVX_sha256_compress((uint32_t*)&state, blocks_);
						temp1 [k] = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
						//memcpy(temp[k], &state, FIPS205_N);
					#else
						blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
						blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
						blocks_[2] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
						blocks_[3] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);
						memcpy(state, (uint8_t*)PK_256_512, sizeof(state));
						AVX_sha512_compress((uint64_t*)state, blocks_);
						temp1[k] = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);
						
					#endif
				}
				memcpy(psign, &temp1[(ind[i] ^ 1)], FIPS205_N);
				psign += FIPS205_N;
				
				++th;
				//s /= 2;
				r /= 2;
			}
			_aligned_free(temp1);
//#endif

		}
		return sign + FIPS205_K * (1 + FIPS205_A) * FIPS205_N;
}
#if 0
/// <summary>
/// //Part sign
/// </summary>

#ifndef FAST 
#if FIPS205 == 16
#define STEP  5
#else
#define STEP  6
#endif
#else
#define STEP  0
#endif

#define por_counts	(1 << STEP)
#define	por_size	(1 << (FIPS205_A - STEP))

uint8_t *part_sign_ (
	//uint8_t *psign, 
	__m256i *dest,
	__m256i *PK_256,
	__m256i *PK_256_512,
	uint32_t i, 
	//uint32_t  indi, 
	int por_number, 
	__m256i *blocks_64_prf, 
	__m256i *blocks_64_tree,
	__m256i* in_block_for_H,
	__m256i perenos, 
	__m256i *start_value)
{

	
	__m256i temp1[por_size], temp2[por_size];
	
	//__m256i temp[8];
	uint32_t j, k = 0, l = 0;

	uint32_t* block_keys_32;
	uint32_t start_j = por_number * por_size;
	uint32_t end_j  = start_j + por_size;
	__m256i t;
	
	for (j = 0; j < por_size / 8; ++j)   // level 0
	{
		blocks_64_prf[4] = perenos;											// PRF
		blocks_64_prf[5] = _mm256_or_si256(
			_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_prf[5]),
			*start_value);

		memcpy(temp1 + 8 * j, (__m256i*)PK_256, 8 * sizeof(__m256i));	

		AVX_sha256_compress8(temp1 + 8 * j, blocks_64_prf);						

		blocks_64_tree[4] = perenos;										// F		

		blocks_64_tree[5] = _mm256_or_si256(
			_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_tree[5]),
			*start_value);
		replace_blocks_key8__(blocks_64_tree, temp1 + j * 8);

		memcpy(temp2 + j * 8, (__m256i*)PK_256, 8 * sizeof(__m256i));
	
		AVX_sha256_compress8(temp2 + j * 8, blocks_64_tree);

		*start_value = _mm256_add_epi32(*start_value, eight_256);
	}

	// nodes for level 0
	block_keys_32 = (uint32_t*)(temp2);
	__m256i *ptemp1 = (__m256i*)temp1;
	for (j = 0; j < por_size / 8; ++j)
	{
		block_keys_32 = (uint32_t*)(temp2 + 8 * j);

		for (k = 0; k < 8; ++k)
		{
			t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
			t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
			memcpy(ptemp1, &t, FIPS205_N);
			//ptemp1 += sizeof(__m256i);
			++ptemp1;
		}

	}
	
	// for levels 1 .. FIPS205_A - STEP
#if FIPS205_N == 16
	//__m256i in_block_for_H[2];
	__m256i state;
#else
	//__m256i in_block_for_H[4];
	__m256i state[2];
#endif

	uint8_t* pblocks = (uint8_t*)in_block_for_H;
	uint32_t th = 1;
//	uint32_t s = ind_i ^ 1;
	uint32_t r = por_size;
#ifndef FAST
	while (r != 1)
#else
	while (r != 2)
#endif
	{
		//ind_i /= 2;

		setTreeHeight(pblocks, th);
		uint32_t tree_ind_const = i * (1 << (FIPS205_A - th)) +
			/*(th != STEP ? */(por_number * (por_size >> th)) /*: 0)*/;
			
#if FIPS205_N == 16
		__m256i blocks_[64];
#else
		__m256i blocks_[80];
#endif
		for (k = 0; k < r / 2; ++k)
		{
			
			setTreeIndex(pblocks, tree_ind_const + k);
			memcpy(pblocks + ADR_SIZE, &temp1[2 * k], FIPS205_N);
			memcpy(pblocks + ADR_SIZE + FIPS205_N, &temp1[2 * k + 1], FIPS205_N);

			#if FIPS205_N == 16
				blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);
				memcpy(&state, (uint8_t*)PK_256_512, sizeof(state));
				AVX_sha256_compress((uint32_t*)&state, blocks_);
				temp1[k] = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
				//memcpy(temp[k], &state, FIPS205_N);
			#else
				blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				blocks_[2] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				blocks_[3] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);
				memcpy(state, (uint8_t*)PK_256_512, sizeof(state));
				AVX_sha512_compress((uint64_t*)state, blocks_);
				temp1[k] = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);

			#endif
		}

		++th;
		//s /= 2;
		r /= 2;
	}
	//free(temp1);
//#endif
	*dest = temp1[0];
	//*indi = ind_i;
	//return psign;
}

uint8_t* part_sign(
	uint8_t* psign,
	__m256i* dest,
	__m256i* PK_256,
	__m256i* PK_256_512,
	uint32_t i,
	uint32_t  indi,
	int por_number,
	__m256i* blocks_64_prf,
	__m256i* blocks_64_tree,
	__m256i* in_block_for_H,
	__m256i perenos,
	__m256i* start_value)
{


	__m256i temp1[por_size], temp2[por_size];

	//__m256i temp[8];
	uint32_t j, k = 0, l = 0;
	uint32_t ind_i = indi;

	uint32_t need_j = ind_i / por_size; // parts number 
	uint32_t need_k = ind_i % por_size;	// in part number
	uint32_t need_k1 = need_k / 8; //in block = 8
	uint32_t need_k2 = need_k % 8; //in block = 8
	uint32_t need_k_ = need_k2 ^ 1;
	uint32_t* block_keys_32;
	uint32_t start_j = por_number * por_size;
	uint32_t end_j = start_j + por_size;
	__m256i t;

	for (j = 0; j < por_size / 8; ++j)   // level 0
	{
		blocks_64_prf[4] = perenos;											// PRF
		blocks_64_prf[5] = _mm256_or_si256(
			_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_prf[5]),
			*start_value);

		memcpy(temp1 + 8 * j, (__m256i*)PK_256, 8 * sizeof(__m256i));

		AVX_sha256_compress8(temp1 + 8 * j, blocks_64_prf);

		blocks_64_tree[4] = perenos;										// F		

		blocks_64_tree[5] = _mm256_or_si256(
			_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_tree[5]),
			*start_value);
		replace_blocks_key8__(blocks_64_tree, temp1 + j * 8);

		memcpy(temp2 + j * 8, (__m256i*)PK_256, 8 * sizeof(__m256i));

		AVX_sha256_compress8(temp2 + j * 8, blocks_64_tree);

		*start_value = _mm256_add_epi32(*start_value, eight_256);
	}
	// node [0]
	//if (need_j == por_number)										// if part with i
	{
		block_keys_32 = (uint32_t*)(temp1 + 8 * need_k1 );
		for (k = 0; k < need_k2; ++k)
		{
			t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		}
		t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
		memcpy(psign, &t, FIPS205_N);
		psign += FIPS205_N;
	}

	// nodes for level 0
	block_keys_32 = (uint32_t*)(temp2);
	__m256i* ptemp1 = (__m256i*)temp1;
	for (j = 0; j < por_size / 8; ++j)
	{
		block_keys_32 = (uint32_t*)(temp2 + 8 * j);

		for (k = 0; k < 8; ++k)
		{
			t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
			t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
			memcpy(ptemp1, &t, FIPS205_N);
			//ptemp1 += sizeof(__m256i);
			++ptemp1;
		}

	}

//	if (need_j == por_number)					//auth for level [0]
	{
		memcpy(psign, temp1 + 8 * need_k1 + need_k_, FIPS205_N);
		psign += FIPS205_N;
	}

	// for levels 1 .. FIPS205_A - STEP
#if FIPS205_N == 16
	//__m256i in_block_for_H[2];
	__m256i state;
#else
	//__m256i in_block_for_H[4];
	__m256i state[2];
#endif

	uint8_t* pblocks = (uint8_t*)in_block_for_H;
	uint32_t th = 1;
	//	uint32_t s = ind_i ^ 1;
	uint32_t r = por_size;
#ifndef FAST
	while (r != 1)
#else
	while (r != 2)
#endif
	{
		//ind_i /= 2;

		setTreeHeight(pblocks, th);
		uint32_t tree_ind_const = i * (1 << (FIPS205_A - STEP)) +
			/*(th != STEP ? */(por_number * (por_size >> th)) /*: 0)*/;

#if FIPS205_N == 16
		__m256i blocks_[64];
#else
		__m256i blocks_[80];
#endif
		need_k = ind_i - por_number * por_size;
		for (k = 0; k < r / 2; ++k)
		{

			setTreeIndex(pblocks, tree_ind_const + k);
			memcpy(pblocks + ADR_SIZE, &temp1[2 * k], FIPS205_N);
			memcpy(pblocks + ADR_SIZE + FIPS205_N, &temp1[2 * k + 1], FIPS205_N);

#if FIPS205_N == 16
			blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
			blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);
			memcpy(&state, (uint8_t*)PK_256_512, sizeof(state));
			AVX_sha256_compress((uint32_t*)&state, blocks_);
			temp1[k] = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
			//memcpy(temp[k], &state, FIPS205_N);
#else
			blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
			blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
			blocks_[2] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
			blocks_[3] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);
			memcpy(state, (uint8_t*)PK_256_512, sizeof(state));
			AVX_sha512_compress((uint64_t*)state, blocks_);
			temp1[k] = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);

#endif
		}
		
		//need_k >> th
		//need_j = (ind_i ^ 1)/ por_size;
		//need_k = (ind_i ^ 1) % por_size;
		if (th != STEP)
		{
			memcpy(psign, &temp1[(need_k >> th) ^ 1], FIPS205_N);
			psign += FIPS205_N;
		}
		++th;
		//s /= 2;
		r /= 2;
	}
	//free(temp1);
//#endif
	*dest = temp1[0];
	//*indi = ind_i;
	return psign;
}





uint8_t* FIPS205_AVX_fors_sign_new_(uint8_t* sign, uint8_t* md, /*auth[FIPS205_K][FIPS205_A][FIPS205_N], */const uint8_t* SK_seed, const void* PK_256, const void* PK_256_512, /*__m256i in64[2], */uint8_t* adr)
{
	int i;
	ALIGN32 uint32_t ind[FIPS205_K] = { 0 };

	fors_base(ind, md, FIPS205_K);
	//uint8_t* psign = sign;


#pragma omp parallel for 
	for (i = 0; i < FIPS205_K; ++i)
	{
		__m256i perenos = _mm256_set1_epi32((i * (1 << FIPS205_A) >> 16));
		__m256i start_value = _mm256_add_epi32(step1_sll16, _mm256_set1_epi32((i * (1 << FIPS205_A)) << 16));
		uint8_t* psign = sign + i * FIPS205_N * (1 + FIPS205_A);
		uint32_t cur_ind = ind[i]; // _mm256_set1_epi32(ind[i] * (1 << i));
		__m256i in_block_for_prf[2];
		__m256i in_block_for_tree[2];
		uint32_t j;
#if FIPS205_N == 16
		__m256i in_block_for_H[2];
		__m256i state;
#else
		__m256i in_block_for_H[4];
		__m256i state[2];
#endif

		__m256i blocks_64_prf[64];
		__m256i blocks_64_tree[64];

		//#if FIPS205_N > 16
		//			__m256i blocks_128[80];
		//#endif

		FIPS205_AVX_fors_init_for_prf(in_block_for_prf, SK_seed, adr);
		FIPS205_AVX_fors_init_for_tree(in_block_for_tree, adr);
		FIPS205_AVX_fors_init_in_block0(in_block_for_H, adr);


		__m256i temp[16];

		memcpy(temp, in_block_for_prf, 2 * sizeof(__m256i));
		memcpy(temp + 2, temp, 2 * sizeof(__m256i));
		memcpy(temp + 4, temp, 4 * sizeof(__m256i));
		memcpy(temp + 8, temp, 8 * sizeof(__m256i));

		uint32_t* temp32 = (uint32_t*)temp;
		for (j = 0; j < 16; ++j)
		{
			blocks_64_prf[j] = _mm256_i32gather_epi32((const int*)temp32++, idx16, 4);

		}
		temp32 = (uint32_t*)temp;

		memcpy(temp, in_block_for_tree, 2 * sizeof(__m256i));
		memcpy(temp + 2, temp, 2 * sizeof(__m256i));
		memcpy(temp + 4, temp, 4 * sizeof(__m256i));
		memcpy(temp + 8, temp, 8 * sizeof(__m256i));

		for (j = 0; j < 16; ++j)
		{
			blocks_64_tree[j] = _mm256_i32gather_epi32((const int*)temp32++, idx16, 4);

		}
		__m256i dest[1 << STEP];
		
		uint32_t num_por_for_ind = ind[i] / por_size;
		//for (j = 0; j < (1 << STEP); ++j)
		for (j = 0; j < num_por_for_ind; ++j)
		{
			part_sign_(
				//psign,
				&dest[j],
				PK_256,
				PK_256_512,
				i,
				//ind[i],
				j,
				blocks_64_prf,
				blocks_64_tree,
				in_block_for_H,
				perenos,
				&start_value);

		}
		psign = part_sign(
			psign,
			&dest[j],
			PK_256,
			PK_256_512,
			i,
			ind[i],
			num_por_for_ind,
			blocks_64_prf,
			blocks_64_tree,
			in_block_for_H,
			perenos,
			&start_value);

		for (j = num_por_for_ind + 1; j < (1 << STEP); ++j)
		{
			part_sign_(
				//psign,
				&dest[j],
				PK_256,
				PK_256_512,
				i,
				//ind[i],
				j,
				blocks_64_prf,
				blocks_64_tree,
				in_block_for_H,
				perenos,
				&start_value);
		}
		memcpy(psign, &dest[num_por_for_ind ^ 1], FIPS205_N);
		psign += FIPS205_N;

#ifndef FAST
		//__m256i dest[1 << STEP];
		ind[i] >>= (STEP);
		uint8_t* pblocks = (uint8_t*)in_block_for_H;
		uint32_t th = (STEP + 1);
		uint32_t r = 1 << STEP;
		while (r != 2)
		{
			ind[i] /= 2;

			setTreeHeight(pblocks, th);
			uint32_t tree_ind_const = i * (1 << (FIPS205_A - th));
#if FIPS205_N == 16
			__m256i blocks_[64];
#else
			__m256i blocks_[80];
#endif
			for (uint32_t k = 0; k < r / 2; ++k)
			{

				setTreeIndex(pblocks, tree_ind_const + k);
				memcpy(pblocks + ADR_SIZE, &dest[2 * k], FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, &dest[2 * k + 1], FIPS205_N);

#if FIPS205_N == 16
				blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);
				memcpy(&state, (uint8_t*)PK_256_512, sizeof(state));
				AVX_sha256_compress((uint32_t*)&state, blocks_);
				dest[k] = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
				//memcpy(temp[k], &state, FIPS205_N);
#else
				blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				blocks_[2] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				blocks_[3] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);
				memcpy(state, (uint8_t*)PK_256_512, sizeof(state));
				AVX_sha512_compress((uint64_t*)state, blocks_);
				dest[k] = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);

#endif
			}

			memcpy(psign, &dest[ind[i] ^ 1], FIPS205_N);
			psign += FIPS205_N;

			++th;

			r /= 2;
		}
#endif
	}
	return sign + FIPS205_K * (1 + FIPS205_A) * FIPS205_N;
}
#endif

uint8_t* FIPS205_AVX_fors_sign_new__(uint8_t* sign, uint8_t* md, /*auth[FIPS205_K][FIPS205_A][FIPS205_N], */const uint8_t* SK_seed, const void* PK_256, const void* PK_256_512, /*__m256i in64[2], */uint8_t* adr)
{
	int i;
	//omp_set_num_threads(8);
	ALIGN32 uint32_t ind[FIPS205_K] = { 0 };

	fors_base(ind, md, FIPS205_K);



#pragma omp parallel for
	for (i = 0; i < FIPS205_K; ++i)
	{
		__m256i perenos = _mm256_set1_epi32((i * (1 << FIPS205_A) >> 16));
		__m256i start_value = _mm256_add_epi32(step1_sll16, _mm256_set1_epi32((i * (1 << FIPS205_A)) << 16));
		uint8_t* psign = sign + i * FIPS205_N * (1 + FIPS205_A);
		uint32_t cur_ind = ind[i]; // _mm256_set1_epi32(ind[i] * (1 << i));
		__m256i in_block_for_prf[2];
		__m256i in_block_for_tree[2];
		uint32_t j;
#if FIPS205_N == 16
		__m256i in_block_for_H[2];
		__m256i state;
#else
		__m256i in_block_for_H[4];
		__m256i state[2];
#endif

		__m256i blocks_64_prf[64];
		__m256i blocks_64_tree[64];
#if FIPS205_N == 16
		__m256i blocks_H[64];
#else 
		__m256i blocks_H[80];
#endif
		//#if FIPS205_N > 16
		//			__m256i blocks_128[80];
		//#endif

		FIPS205_AVX_fors_init_for_prf(in_block_for_prf, SK_seed, adr);
		FIPS205_AVX_fors_init_for_tree(in_block_for_tree, adr);
		FIPS205_AVX_fors_init_in_block0(in_block_for_H, adr);

		__m256i temp[16];

		memcpy(temp, in_block_for_prf, 2 * sizeof(__m256i));
		memcpy(temp + 2, temp, 2 * sizeof(__m256i));
		memcpy(temp + 4, temp, 4 * sizeof(__m256i));
		memcpy(temp + 8, temp, 8 * sizeof(__m256i));

		uint32_t* temp32 = (uint32_t*)temp;
		for (j = 0; j < 16; ++j)
		{
			blocks_64_prf[j] = _mm256_i32gather_epi32((const int*)temp32++, idx16, 4);

		}
		temp32 = (uint32_t*)temp;

		memcpy(temp, in_block_for_tree, 2 * sizeof(__m256i));
		memcpy(temp + 2, temp, 2 * sizeof(__m256i));
		memcpy(temp + 4, temp, 4 * sizeof(__m256i));
		memcpy(temp + 8, temp, 8 * sizeof(__m256i));

		for (j = 0; j < 16; ++j)
		{
			blocks_64_tree[j] = _mm256_i32gather_epi32((const int*)temp32++, idx16, 4);

		}

#if FIPS205_N == 16
		temp32 = (uint32_t*)temp;

		memcpy(temp, in_block_for_H, 2 * sizeof(__m256i));
		memcpy(temp + 2, temp, 2 * sizeof(__m256i));
		memcpy(temp + 4, temp, 4 * sizeof(__m256i));
		memcpy(temp + 8, temp, 8 * sizeof(__m256i));

		for (j = 0; j < 16; ++j)
		{
			blocks_H[j] = _mm256_i32gather_epi32((const int*)temp32++, idx16, 4);
			blocks_H[j] = _mm256_shuffle_epi8(blocks_H[j], maska_for_shuffle_32);

		}
#else
		uint64_t* temp64 = (uint64_t*)temp;
		__m128i idx = _mm_setr_epi32(0, 4, 8, 12);
		//uint64_t* temp64 = (uint64_t*)temp;
		memcpy(temp, in_block_for_H, 4 * sizeof(__m256i));
		memcpy(temp + 4, temp, 4 * sizeof(__m256i));
		memcpy(temp + 8, temp, 8 * sizeof(__m256i));

		//temp = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, idx, 8);
		temp64 = (uint64_t*)temp;
		
		for (j = 0; j < 16; ++j)
		{
			blocks_H[j] = _mm256_i32gather_epi64((const int64_t*)temp64++, idx, 8);
			blocks_H[j] = _mm256_shuffle_epi8(blocks_H[j], maska_for_shuffle_64);
		}
		


#endif

		//__m256i blocks[64];
#if FIPS205_N == 16
		__m256i blocks_[64];
#else
		__m256i blocks_[80];
#endif



		uint8_t* pblocks = (uint8_t*)in_block_for_H;
		
		//__m256i* temp1 = malloc(((1 << (FIPS205_A + 1)) * sizeof(__m256i))), * temp2 = temp1 + (1 << (FIPS205_A));
		__m256i* temp1 = (__m256i*)_aligned_malloc(((1 << (FIPS205_A + 1)) * sizeof(__m256i)), 32);
		if (!temp1) {
			// Handle allocation error
			//return NULL;
		}
		__m256i* temp2 = temp1 + (1 << FIPS205_A);

		uint32_t k = 0, l = 0, r = FIPS205_A;



		__m256i t;
		uint32_t need_j = ind[i] / 8;
		uint32_t need_k = ind[i] % 8;
		uint32_t need_k_ = need_k ^ 1;
		uint32_t* block_keys_32;

		for (j = 0; j < (1 << FIPS205_A) / 8; ++j)
		{
			blocks_64_prf[4] = perenos;
			blocks_64_prf[5] = _mm256_or_si256(
				_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_prf[5]),
				start_value);


			memcpy(temp1 + 8 * j, (__m256i*)PK_256, 8 * sizeof(__m256i));


			AVX_sha256_compress8(temp1 + 8 * j, blocks_64_prf);


			blocks_64_tree[4] = perenos;

			blocks_64_tree[5] = _mm256_or_si256(
				_mm256_and_si256(_mm256_set1_epi32(0x0000FFFF), blocks_64_tree[5]),
				start_value);
			replace_blocks_key8__(blocks_64_tree, temp1 + j * 8);

			memcpy(temp2 + j * 8, (__m256i*)PK_256, 8 * sizeof(__m256i));
			//memcpy(blocks, blocks_64_tree, 64 * sizeof(__m256i));
			AVX_sha256_compress8(temp2 + j * 8, blocks_64_tree);

			start_value = _mm256_add_epi32(start_value, eight_256);


		}



		block_keys_32 = (uint32_t*)(temp1 + 8 * need_j);
		for (k = 0; k < need_k; ++k)
		{
			t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		}
		t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
		t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
		memcpy(psign, &t, FIPS205_N);
		psign += FIPS205_N;


		block_keys_32 = (uint32_t*)(temp2);
		uint8_t* dest = (uint8_t*)temp1;
		for (j = 0; j < (1 << FIPS205_A) / 8; ++j)
		{

			block_keys_32 = (uint32_t*)(temp2 + 8 * j);

			for (k = 0; k < 8; ++k)
			{
				t = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
				t = _mm256_shuffle_epi8(t, maska_for_shuffle_32);
				memcpy(dest, &t, FIPS205_N);
				dest += sizeof(__m256i);
			}

		}


		memcpy(psign, temp1 + 8 * need_j + need_k_, FIPS205_N);

		psign += FIPS205_N;


		r = 1 << FIPS205_A;
		uint32_t th = 1;
		//uint32_t s = ind[i] ^ 1;
#if FIPS205_N != 16
		__m256i  PK_512_[8];
		uint64_t* PK = PK_256_512;
		PK_512_[0] = _mm256_set1_epi64x(PK[0]);
		PK_512_[1] = _mm256_set1_epi64x(PK[1]);
		PK_512_[2] = _mm256_set1_epi64x(PK[2]);
		PK_512_[3] = _mm256_set1_epi64x(PK[3]);
		PK_512_[4] = _mm256_set1_epi64x(PK[4]);
		PK_512_[5] = _mm256_set1_epi64x(PK[5]);
		PK_512_[6] = _mm256_set1_epi64x(PK[6]);
		PK_512_[7] = _mm256_set1_epi64x(PK[7]);
#endif

		
		uint32_t tree_ind_const = i * (1 << (FIPS205_A ));
		uint32_t indi = ind[i];
		__m256i* start_temp1, * start_temp2, *dest_temp1;
		while (r >= 16)
		{
			
			setTreeHeight(pblocks, th);
			indi >>= 1;
			tree_ind_const >>= 1;
			r = r / 2;
			++th;
			start_temp1 = temp1;
			dest_temp1 = temp1;
			start_temp2 = temp2;

			for (k = 0; k < r ; k += 8)
			{
				
#if FIPS205_N == 16
				
				setTreeIndex(pblocks, tree_ind_const + k);
				memcpy(pblocks + ADR_SIZE, start_temp1, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 1, FIPS205_N);
				start_temp1[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);



				setTreeIndex(pblocks, tree_ind_const + k + 1);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 2, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 3, FIPS205_N);
				start_temp1[2] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[3] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);

				setTreeIndex(pblocks, tree_ind_const + k + 2);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 4, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 5, FIPS205_N);
				start_temp1[4] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[5] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);

				setTreeIndex(pblocks, tree_ind_const + k + 3);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 6, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 7, FIPS205_N);
				start_temp1[6] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[7] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);

				setTreeIndex(pblocks, tree_ind_const + k + 4);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 8, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 9, FIPS205_N);
				start_temp1[8] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[9] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);

				setTreeIndex(pblocks, tree_ind_const + k + 5);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 10, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 11, FIPS205_N);
				start_temp1[10] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[11] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);

				setTreeIndex(pblocks, tree_ind_const + k + 6);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 12, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 13, FIPS205_N);
				start_temp1[12] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[13] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);

				setTreeIndex(pblocks, tree_ind_const + k + 7);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 14, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 15, FIPS205_N);
				start_temp1[14] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				start_temp1[15] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);
				block_keys_32 = (uint32_t*)(start_temp1);
				
				for (j = 0; j < 16; ++j)
				{
					blocks_[j] = _mm256_i32gather_epi32((const int*)block_keys_32++, idx16, 4);

				}
				
				memcpy(start_temp2, PK_256, 8 * sizeof(__m256i));
				
				AVX_sha256_compress8((uint32_t*)(start_temp2), blocks_);

				block_keys_32 = (uint32_t*)(start_temp2);

				for (int l = 0; l < 8; ++l)
				{

					dest_temp1[l] = _mm256_i32gather_epi32((const int*)block_keys_32++, idx8, 4);
					dest_temp1[l] = _mm256_shuffle_epi8(dest_temp1[l], maska_for_shuffle_32);
				
				}
				start_temp1 += 16;
				start_temp2 += 8;
				dest_temp1 += 8;
				
				
				
				
				//memcpy(temp[k], &state, FIPS205_N);
#else
				uint64_t *block_keys_64;
				setTreeIndex(pblocks, tree_ind_const + k);
				memcpy(pblocks + ADR_SIZE, start_temp1, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 1, FIPS205_N);
				start_temp2[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[2] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[3] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);

				setTreeIndex(pblocks, tree_ind_const + k + 1);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 2, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 3, FIPS205_N);
				start_temp2[4] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[5] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[6] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[7] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);

				setTreeIndex(pblocks, tree_ind_const + k + 2);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 4, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 5, FIPS205_N);
				start_temp2[8] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[9] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[10] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[11] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);

				setTreeIndex(pblocks, tree_ind_const + k + 3);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 6, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 7, FIPS205_N);
				start_temp2[12] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[13] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[14] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[15] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);

				// //blocks[0] = _mm256_i32gather_epi64((const long long*)in128_64++, _mm_setr_epi32(0, 16, 32, 48), 8);
				block_keys_64 = (uint64_t*)start_temp2;
				for (l = 0; l < 16; ++l)
				{
					// _mm256_i32gather_epi64((__int64 const*)temp, idx, 8);
					blocks_[l] = _mm256_i32gather_epi64(
						(const int64_t*)block_keys_64++, 
						_mm_setr_epi32(0, 16, 32, 48), 8);
					
					
				}

				memcpy(start_temp2, (uint8_t*)PK_512_, 8 * sizeof(__m256i));
				AVX_sha512_compress4(start_temp2, blocks_);
				__m128i idx = _mm_setr_epi32(0, 4, 8, 12);
				block_keys_64 = (uint64_t*)start_temp2;
				dest_temp1[0] = _mm256_shuffle_epi8 (
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
				dest_temp1[1] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
				dest_temp1[2] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
				dest_temp1[3] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
												
				setTreeIndex(pblocks, tree_ind_const + k + 4);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 8, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 9, FIPS205_N);
				start_temp2[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[2] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[3] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);

				setTreeIndex(pblocks, tree_ind_const + k + 5);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 10, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 11, FIPS205_N);
				start_temp2[4] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[5] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[6] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[7] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);

				setTreeIndex(pblocks, tree_ind_const + k + 6);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 12, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 13, FIPS205_N);
				start_temp2[8] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[9] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[10] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[11] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);

				setTreeIndex(pblocks, tree_ind_const + k + 7);
				memcpy(pblocks + ADR_SIZE, start_temp1 + 14, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 15, FIPS205_N);
				start_temp2[12] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				start_temp2[13] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				start_temp2[14] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				start_temp2[15] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);
				block_keys_64 = (uint64_t*)start_temp2;
				for (l = 0; l < 16; ++l)
				{
					// _mm256_i32gather_epi64((__int64 const*)temp, idx, 8);
					blocks_[l] = _mm256_i32gather_epi64((const int64_t*)block_keys_64++, 
						_mm_setr_epi32(0, 16, 32, 48), 8);

				}

				memcpy(start_temp2, (uint8_t*)PK_512_, 8 * sizeof(__m256i));
				AVX_sha512_compress4((uint64_t*)start_temp2, blocks_);
				idx = _mm_setr_epi32(0, 4, 8, 12);
				block_keys_64 = (uint64_t*)start_temp2;
				dest_temp1[4] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
				dest_temp1[5] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
				dest_temp1[6] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
				dest_temp1[7] = _mm256_shuffle_epi8(
					_mm256_i32gather_epi64(block_keys_64++, idx, 8), maska_for_shuffle_64);
				start_temp1 += 16;
				dest_temp1 += 8;
#endif
			}
			memcpy(psign, &temp1[(indi ^ 1)], FIPS205_N);
			psign += FIPS205_N;
		}
		while (r != 2)
		{
			tree_ind_const >>= 1;
			start_temp1 = temp1;
			dest_temp1 = temp1;
			//start_temp2 = temp2;

			//ind[i] /= 2;
			indi >>= 1;
			setTreeHeight(pblocks, th);
			++th;
			//uint32_t tree_ind_const = i * (1 << (FIPS205_A - th));
			for (k = 0; k < r / 2; ++k)
			{
				/*if (k == 64)
					printf("");*/
					//uint32_t tree_ind_const = 1 << (FIPS205_A - th);
				setTreeIndex(pblocks, tree_ind_const + k);
				memcpy(pblocks + ADR_SIZE, start_temp1, FIPS205_N);
				memcpy(pblocks + ADR_SIZE + FIPS205_N, start_temp1 + 1, FIPS205_N);
				start_temp1 += 2;


#if FIPS205_N == 16
				blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_32);
				blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_32);
				memcpy(&state, (uint8_t*)PK_256_512, sizeof(state));
				AVX_sha256_compress((uint32_t*)&state, blocks_);
				*dest_temp1++ = _mm256_shuffle_epi8(state, maska_for_shuffle_32);
				//memcpy(temp[k], &state, FIPS205_N);
#else
				blocks_[0] = _mm256_shuffle_epi8(in_block_for_H[0], maska_for_shuffle_64);
				blocks_[1] = _mm256_shuffle_epi8(in_block_for_H[1], maska_for_shuffle_64);
				blocks_[2] = _mm256_shuffle_epi8(in_block_for_H[2], maska_for_shuffle_64);
				blocks_[3] = _mm256_shuffle_epi8(in_block_for_H[3], maska_for_shuffle_64);
				memcpy(state, (uint8_t*)PK_256_512, sizeof(state));
				AVX_sha512_compress((uint64_t*)state, blocks_);
				*dest_temp1++ = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);
				//start_temp1 += 2;
				
#endif
			}
			memcpy(psign, &temp1[(indi ^ 1)], FIPS205_N);
			psign += FIPS205_N;

			//++th;
			//s /= 2;
			r /= 2;
		}
		//free(temp1);
		_aligned_free(temp1);
		//#endif

	}
	return sign + FIPS205_K * (1 + FIPS205_A) * FIPS205_N;
}

void FIPS205_AVX_fors_pkFromSig_new__(
	uint8_t* pkFromSig,
	const uint8_t* SigFors,
	const uint8_t* md,
	const void* PK_seed_,		// one 256 0r 512
	const void* PK_seed,		// one 256
	//const void* PK_seed_n,		// block 512
	uint8_t* adr)
{

	int i;
	//omp_set_num_threads(8);
	ALIGN32 uint32_t ind[FIPS205_K] = { 0 };

	fors_base(ind, md, FIPS205_K);


	__m256i in_block_for_tree[2];
	in_block_for_tree[0] = _mm256_setzero_si256();
	in_block_for_tree[1] = _mm256_setzero_si256();
	uint8_t* p = (uint8_t*)in_block_for_tree;
	memcpy(p, adr, ADR_SIZE);
	setType1(p, FORS_TREE);
	memset(p + ADR_SIZE - 8, 0, 8);
	p[ADR_SIZE + FIPS205_N] = 0x80;
	int bytes = (64 + ADR_SIZE + FIPS205_N);
	p[62] = (uint8_t)(bytes >> 5);
	p[63] = (uint8_t)(bytes << 3);

#if FIPS205_N == 16
	__m256i in_block_for_H[2] = {0};
	
#else
	__m256i in_block_for_H[4] = {0};
	
#endif
	FIPS205_AVX_fors_init_in_block0(in_block_for_H, adr);

	__m256i dest[FIPS205_K];
#pragma omp parallel for
	for (i = 0; i < FIPS205_K; ++i)
	{
		__m256i local_sk = { 0 };
		__m256i local_auth[FIPS205_A] = { 0 };
		const uint8_t* cur_sk = SigFors + i * (FIPS205_N + FIPS205_A * FIPS205_N);

		memcpy(&local_sk, cur_sk, FIPS205_N);
		for (int j = 0; j < FIPS205_A; ++j)
		{
			memcpy(&local_auth[j], cur_sk + FIPS205_N, FIPS205_N);
			cur_sk += FIPS205_N;

		}

#if FIPS205_N == 16
		__m256i blocks_H[64];
		//__m256i initblocks_H[2];

#else 
		__m256i blocks_H[80];
		//__m256i initblocks_H[4];
		//__m256i state;
#endif
		//memcpy(initblocks_H, in_block_for_H, sizeof(in_block_for_H));

		__m256i blocks_64_tree[64];

		memcpy(blocks_64_tree, in_block_for_tree, 2 * sizeof(__m256i));
		uint8_t* p = (uint8_t*)blocks_64_tree;
		setTreeIndex(p, (i * (1 << FIPS205_A) + ind[i]));
		memcpy(p + 22, &local_sk, FIPS205_N);
		blocks_64_tree[0] = _mm256_shuffle_epi8(blocks_64_tree[0], maska_for_shuffle_32);
		blocks_64_tree[1] = _mm256_shuffle_epi8(blocks_64_tree[1], maska_for_shuffle_32);

		memcpy(&local_sk, PK_seed, sizeof(__m256i));
		AVX_sha256_compress((uint32_t*)&local_sk, blocks_64_tree);
		local_sk = _mm256_shuffle_epi8(local_sk, maska_for_shuffle_32);
			
		p = (uint8_t*)blocks_H;
		__m256i first = local_sk;
		uint32_t indi = ind[i];
		uint32_t tree_ind_const = i * (1 << (FIPS205_A));
		__m256i* padrs[2];
		for (int j = 0; j < FIPS205_A; ++j)
		{
			memcpy(blocks_H, in_block_for_H, sizeof(in_block_for_H));
			//uint32_t r = 1 << FIPS205_A;
			uint32_t th = j + 1;

			//__m256i next = local_auth[j];
			setTreeHeight(p, th);
			//setTreeIndex(p, (tree_ind_const + indi));
			padrs[indi & 1] = &first;
			padrs[(indi & 1) ^ 1] = local_auth + j;
			indi >>= 1;
			tree_ind_const >>= 1;
			setTreeIndex(p, (tree_ind_const + indi));
			memcpy(p + ADR_SIZE, padrs[0], FIPS205_N);
			memcpy(p + ADR_SIZE + FIPS205_N, padrs[1], FIPS205_N);
#if FIPS205_N == 16
			blocks_H[0] = _mm256_shuffle_epi8(blocks_H[0], maska_for_shuffle_32);
			blocks_H[1] = _mm256_shuffle_epi8(blocks_H[1], maska_for_shuffle_32);
				
				memcpy(&first, PK_seed_, sizeof(__m256i));

				AVX_sha256_compress((uint32_t*)&first, blocks_H);

				first = _mm256_shuffle_epi8(first, maska_for_shuffle_32);


#else

				__m256i state[2];
				blocks_H[0] = _mm256_shuffle_epi8(blocks_H[0], maska_for_shuffle_64);
				blocks_H[1] = _mm256_shuffle_epi8(blocks_H[1], maska_for_shuffle_64);
				blocks_H[2] = _mm256_shuffle_epi8(blocks_H[2], maska_for_shuffle_64);
				blocks_H[3] = _mm256_shuffle_epi8(blocks_H[3], maska_for_shuffle_64);

				
				memcpy(state, PK_seed_, sizeof(state));

				AVX_sha512_compress((uint64_t*)state, blocks_H);

				first = _mm256_shuffle_epi8(state[0], maska_for_shuffle_64);


#endif
			

		}
		dest[i] = first;
	}
		
	uint8_t forspkADRS[ADR_SIZE];
	memcpy(forspkADRS, adr, ADR_SIZE);
	setType1(forspkADRS, FORS_ROOTS);
	memset(forspkADRS + ADR_SIZE - 8, 0, 8);

	AVX_Tl(pkFromSig, PK_seed_, forspkADRS, dest, FIPS205_K);
}
