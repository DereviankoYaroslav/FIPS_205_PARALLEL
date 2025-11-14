#ifndef AVXconst_h
#define AVXconst_h
#include <inttypes.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include "FIPS_205_Params.h"

static uint32_t bswap(uint32_t value)
{
	uint32_t res = ((value & 0xFF) << 24) |
		(((value >> 8) & 0xFF) << 16) |
		((((value >> 16) & 0xFF) << 8)) |
		(value >> 24);
	return res;
}

extern __m256i maska_for_bytes;
extern __m256i maska_for_shuffle_32;
extern __m256i maska_for_shuffle_64;
extern __m256i idx16;
extern __m256i idx8;
extern const uint8_t u8_maska[32];
extern __m256i ChainAddressClearMaska;
extern __m256i ChainAddressOne;
extern __m256i HashAddressClearMaska;
extern __m256i HashAddressOne;
extern __m256i maska_for_N;
extern __m256i step1_sll16;
extern __m256i eight_256;
extern __m256i one256;
extern __m256i KeyParaMaska;
extern __m256i TreeHeightMaska;
extern __m256i TreeIndexMaskaLow;
extern __m256i TreeIndexMaskaHigh;

extern __m256i NotHashAddressClear;
extern __m256i NotChainAndHashAddressClear;
extern __m256i ChainAddressInc;
extern __m256i HashAddressInc;

extern __m256i TYPE_MASKA;
extern __m256i CHANGE_MASKA;
extern __m256i HASH_MASKA;
extern __m256i KEY_MASKA0_, KEY_MASKA1_;

extern __m256i fors_step1_sll16;
extern __m256i fors_eight_256;

void SetAVXConst();

const uint8_t u8_maska_512[32];
inline __m256i AVX2_srl2(__m256i src)
{
#if FIPS205_N == 16
	__m256i r1 = _mm256_srli_si256(src, 2);
#else
	__m256i maska = _mm256_setr_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0000FFFFFFFFFFFF);
	__m256i r1 = _mm256_srli_si256(src, 2);
	__m256i r2 = _mm256_slli_si256(src, 14);
	r2 = _mm256_permute2f128_si256(r2, r2, 0x3);
	r1 = _mm256_or_si256(r1, _mm256_and_si256(r2, maska));
#endif
	return r1;
}



inline __m256i AVX2_srl8(__m256i src)
{

	__m256i maska = _mm256_setr_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0000000000000000);
	__m256i r1 = _mm256_srli_si256(src, 8);
	__m256i r2 = _mm256_slli_si256(src, 8);
	r2 = _mm256_permute2f128_si256(r2, r2, 0x3);
	r1 = _mm256_or_si256(r1, _mm256_and_si256(r2, maska));
	return r1;
}

inline __m256i AVX2_sll22(__m256i src)
{
	//__m256i dest = _mm256_setzero_si256();
	__m256i dest = _mm256_permute2f128_si256(src, src, 0x08);
	//dest = _mm256_alignr_epi8(dest, src, 24);
	dest = _mm256_bslli_epi128(dest, 6);	//low * 256
	return dest;
}

#define SetTypeValue(dest, type) {	\
		dest = __mm256_or_si256 (__mm256_set1_epi32 (type << 16), __mm256_andnot_si256(__mm256_sll_epi32(maska_for_bytes, 16), dest))


#define AVXSetValue(dest, maska, value) \
(dest = _mm256_or_si256(	\
	_mm256_andnot_si256 (maska, dest),\
	_mm256_and_si256 (maska, _mm256_set1_epi8 (value))))  

#define AVXSetValue4(adr256, maska, value) \
(adr256 = _mm256_or_si256(_mm256_and_si256(adr256, maska),			\
_mm256_andnot_si256(maska,					\
	_mm256_set1_epi64x(((uint64_t)bswap(value)) << 16))))

#define AVXSetValue1(adr256, maska, value) \
(adr256 = _mm256_or_si256(_mm256_and_si256(adr256, maska),			\
_mm256_andnot_si256(maska,					\
	_mm256_set1_epi8(value))))


#define AVXSetKeyPara(dest, value) AVXSetValue4(dest, KeyParaMaska, value)
#define AVXSetTreeHeight(dest, value) AVXSetValue1(dest, TreeHeightMaska, value)
#define AVXSetTreeIndex(dest, value) AVXSetValue4(dest, TreeIndexMaska, value)
#endif 