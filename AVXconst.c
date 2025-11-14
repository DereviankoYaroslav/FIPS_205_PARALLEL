#include "AVXconst.h"
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


ALIGN64
const uint8_t u8_maska[32] = {
3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28 };
const uint8_t u8_maska_512[32] = {
7, 6, 5, 4, 3, 2, 1, 0,
15, 14, 13, 12, 11, 10, 9, 8,
23, 22, 21, 20, 19, 18, 17, 16,
31, 30, 29, 28, 27, 26, 25, 24
};

__m256i maska_for_shuffle_32;
__m256i maska_for_shuffle_64;
__m256i idx16;
__m256i idx8;
__m256i ChainAddressClearMaska;
__m256i ChainAddressOne;
__m256i HashAddressClearMaska;
__m256i HashAddressOne;
__m256i maska_for_N;
__m256i step1_sll16;
__m256i eight_256 ;
__m256i one256;
__m256i NotHashAddressClear;
__m256i NotChainAndHashAddressClear;
__m256i ChainAddressInc;
__m256i HashAddressInc;
__m256i maska_for_bytes;

__m256i TYPE_MASKA;
__m256i CHANGE_MASKA;
__m256i HASH_MASKA;
__m256i KEY_MASKA0_, KEY_MASKA1_;
__m256i KeyParaMaska;
__m256i TreeHeightMaska;
__m256i TreeIndexMaskaLow;
__m256i TreeIndexMaskaHigh;
__m256i fors_step1_sll16;
__m256i fors_eight_256;


void SetAVXConst()
{
	one256 = _mm256_set1_epi32(1 << 16);
	maska_for_bytes = _mm256_setr_epi32(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	// 4
	KeyParaMaska = _mm256_setr_epi8(
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
		// 1
	TreeHeightMaska = _mm256_setr_epi8(
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	
	// 4
	/*TreeIndexMaska = _mm256_setr_epi8(
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF,
		0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);*/

	TreeIndexMaskaLow = _mm256_setr_epi8(
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	TreeIndexMaskaHigh = _mm256_setr_epi8(
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);


	//TreeHeightMaska = _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000FFFF, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);
	//TreeIndexMaska =  _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000FFFF, 0xFFFF0000,  0xFFFFFFFF, 0xFFFFFFFF);
	maska_for_shuffle_32 = _mm256_setr_epi8(
		3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
		19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28);
	maska_for_shuffle_64 = _mm256_setr_epi8(
		7, 6, 5, 4, 3, 2, 1, 0,
		15, 14, 13, 12, 11, 10, 9, 8,
		23, 22, 21, 20, 19, 18, 17, 16,
		31, 30, 29, 28, 27, 26, 25, 24);
	idx8 = _mm256_setr_epi32(0, 8, 16, 24, 32, 40, 48, 56);
	idx16 = _mm256_setr_epi32(0, 16, 32, 48, 64, 80, 96, 112);

	// chainAddress - hashAddress 14 - 18
	HashAddressClearMaska = _mm256_setr_epi8(
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0xFF, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0);
	
	NotChainAndHashAddressClear = _mm256_setr_epi8(
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0);
	HashAddressInc = _mm256_setr_epi8(
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0);
	ChainAddressInc = _mm256_setr_epi8(
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0x1, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0);



	step1_sll16 = _mm256_slli_epi32(_mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7), 16);
	eight_256 = _mm256_set1_epi32(8 << 16);

	fors_step1_sll16 = _mm256_slli_epi32(
		_mm256_setr_epi32(0 * (1 << FIPS205_A), 
			1 * (1 << FIPS205_A), 
			2 * (1 << FIPS205_A), 
			3 * (1 << FIPS205_A),
			4 * (1 << FIPS205_A), 
			5 * (1 << FIPS205_A), 
			6 * (1 << FIPS205_A), 
			7 * (1 << FIPS205_A)), 16);
	fors_eight_256 = _mm256_slli_epi32 (_mm256_set1_epi32(8 * (1 << FIPS205_A)), 16);
		
	ChainAddressClearMaska = _mm256_setr_epi32(0, 0, 0, 0x00FF0000, 0, 0, 0, 0);
	ChainAddressOne = _mm256_setr_epi32(0, 0, 0, 1 << 16, 0, 0, 0, 0);
	//HashAddressClearMaska = _mm256_setr_epi32(0, 0, 0, 0, 0x00FF0000, 0, 0, 0);
	HashAddressClearMaska = _mm256_set1_epi32(0xFFFF0000);
	HashAddressOne = _mm256_setr_epi32(0, 0, 0, 0, 1 << 16, 0, 0, 0);
#if FIPS205_N == 16
	maska_for_N = _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0);
#elif FIPS205_N == 24
	maska_for_N = _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0);
#else
	maska_for_N = _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);
#endif

	TYPE_MASKA = _mm256_setr_epi32(0, 0, 0x0000FF00, 0, 0, 0, 0, 0);
	CHANGE_MASKA = _mm256_setr_epi32(0, 0, 0, 0, 0x0000FF00, 0, 0, 0);
	HASH_MASKA = _mm256_setr_epi32(0, 0, 0, 0, 0, 0x0000FF00, 0, 0);
	KEY_MASKA0_ = _mm256_setr_epi32(0, 0, 0, 0, 0, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF); // false
	
#if FIPS205_N == 16
	KEY_MASKA1_ = _mm256_setr_epi32(0xFFFFFFFF, 0x00FFFF, 0, 0, 0, 0, 0, 0);
	

#elif FIPS205_N == 24
	KEY_MASKA1_ = _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00FFFF, 0, 0, 0, 0);
	
#else
	KEY_MASKA1_ = _mm256_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00FFFF, 0, 0);
	

#endif

}

//__declspec (align (64))
//const uint32_t ChainAddressClearMaska[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00FFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
//const uint32_t ChainAddressOne [8] = { 0, 0, 0, 1 << 16, 0, 0, 0, 0 };
//const uint32_t HashAddressClearMaska[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00FFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
//const uint32_t HashAddressOne[8] = { 0, 0, 0, 0, 1 << 16, 0, 0, 0 };

