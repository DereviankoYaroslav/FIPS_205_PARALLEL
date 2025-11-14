#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "Common.h"
#include "FIPS_205_Params.h"
#include "SHA256_device.h"

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

#if defined(_MSC_VER)
  #include <intrin.h>
#else
  #include <cpuid.h>
  #define __cpuidex(info, func, subfunc) \
  __cpuid_count(func, subfunc, (info)[0], (info)[1], (info)[2], (info)[3])
#endif

int check_properties(int fun, uint32_t index, uint32_t bit) {
    uint32_t r[4];
    uint32_t mask = 1 << bit;
    __cpuidex((int*)r, fun, 0);
    return (r[index] & mask) == mask;
}
int check_sha256()
{
	return check_properties(7, 1, 29);
		
}

int check_sha512()
{
	return check_properties(7, 0, 0);

}

// https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
#define     CONST1      _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL)
#define     CONST2      _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL)
#define     CONST3      _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL)
#define     CONST4      _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL)
#define     CONST5      _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL)
#define     CONST6      _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL)
#define     CONST7      _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL)  
#define     CONST8      _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL)
#define     CONST9      _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL)
#define     CONST10     _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL)
#define     CONST11     _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL)
#define     CONST12     _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL)
#define     CONST13     _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL)
#define     CONST14     _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL)
#define     CONST15     _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL)
#define     CONST16     _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL)
#define BLOCK                                               \
ABEF_SAVE = STATE0;                                         \
CDGH_SAVE = STATE1;                                         \
                                                            \
/* Rounds 0-3 */                                            \
MSG = _mm_loadu_si128((const __m128i*) (data + 0));         \
MSG0 = _mm_shuffle_epi8(MSG, MASK);                         \
MSG = _mm_add_epi32(MSG0, CONST1);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
                                                            \
/* Rounds 4-7 */                                            \
MSG1 = _mm_loadu_si128((const __m128i*) (data + 16));       \
MSG1 = _mm_shuffle_epi8(MSG1, MASK);                        \
MSG = _mm_add_epi32(MSG1, CONST2);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);                    \
                                                            \
/* Rounds 8-11 */                                           \
MSG2 = _mm_loadu_si128((const __m128i*) (data + 32));       \
MSG2 = _mm_shuffle_epi8(MSG2, MASK);                        \
MSG = _mm_add_epi32(MSG2, CONST3);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);                    \
                                                            \
/* Rounds 12-15 */                                          \
MSG3 = _mm_loadu_si128((const __m128i*) (data + 48));       \
MSG3 = _mm_shuffle_epi8(MSG3, MASK);                        \
MSG = _mm_add_epi32(MSG3, CONST4);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG3, MSG2, 4);                       \
MSG0 = _mm_add_epi32(MSG0, TMP);                            \
MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);                    \
                                                            \
/* Rounds 16-19 */                                          \
MSG = _mm_add_epi32(MSG0, CONST5);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG0, MSG3, 4);                       \
MSG1 = _mm_add_epi32(MSG1, TMP);                            \
MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);                    \
                                                            \
/* Rounds 20-23 */                                          \
MSG = _mm_add_epi32(MSG1, CONST6);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG1, MSG0, 4);                       \
MSG2 = _mm_add_epi32(MSG2, TMP);                            \
MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);                    \
                                                            \
/* Rounds 24-27 */                                          \
MSG = _mm_add_epi32(MSG2, CONST7);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG2, MSG1, 4);                       \
MSG3 = _mm_add_epi32(MSG3, TMP);                            \
MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);                    \
                                                            \
/* Rounds 28-31 */                                          \
MSG = _mm_add_epi32(MSG3, CONST8);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG3, MSG2, 4);                       \
MSG0 = _mm_add_epi32(MSG0, TMP);                            \
MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);                    \
                                                            \
/* Rounds 32-35 */                                          \
MSG = _mm_add_epi32(MSG0, CONST9);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG0, MSG3, 4);                       \
MSG1 = _mm_add_epi32(MSG1, TMP);                            \
MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);                    \
                                                            \
/* Rounds 36-39 */                                          \
MSG = _mm_add_epi32(MSG1, CONST10);                         \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG1, MSG0, 4);                       \
MSG2 = _mm_add_epi32(MSG2, TMP);                            \
MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);                    \
                                                            \
/* Rounds 40-43 */                                          \
MSG = _mm_add_epi32(MSG2, CONST11);                         \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG2, MSG1, 4);                       \
MSG3 = _mm_add_epi32(MSG3, TMP);                            \
MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);                    \
                                                            \
/* Rounds 44-47 */                                          \
MSG = _mm_add_epi32(MSG3, CONST12);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG3, MSG2, 4);                       \
MSG0 = _mm_add_epi32(MSG0, TMP);                            \
MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);                    \
                                                            \
/* Rounds 48-51 */                                          \
MSG = _mm_add_epi32(MSG0, CONST13);                         \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG0, MSG3, 4);                       \
MSG1 = _mm_add_epi32(MSG1, TMP);                            \
MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);                    \
                                                            \
/* Rounds 52-55 */                                          \
MSG = _mm_add_epi32(MSG1, CONST14);                         \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG1, MSG0, 4);                       \
MSG2 = _mm_add_epi32(MSG2, TMP);                            \
MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
/* Rounds 56-59 */                                          \
MSG = _mm_add_epi32(MSG2, CONST15);                         \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG2, MSG1, 4);                       \
MSG3 = _mm_add_epi32(MSG3, TMP);                            \
MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
                                                            \
/* Rounds 60-63 */                                          \
MSG = _mm_add_epi32(MSG3, CONST16);                         \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);        \
                                                            \
/* Combine state  */                                        \
STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);                  \
STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE)                  

void funBlock(__m128i* STATE0_, __m128i* STATE1_, uint8_t* data, uint32_t length)
{
    __m128i STATE0 = *STATE0_;
    __m128i STATE1 = *STATE1_;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    __m128i ABEF_SAVE = STATE0;
    __m128i CDGH_SAVE = STATE1;

    /* Rounds 0-3 */
    __m128i MSG = _mm_loadu_si128((const __m128i*) (data + 0));
    __m128i MSG0 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(MSG0, CONST1);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 4-7 */
    __m128i MSG1 = _mm_loadu_si128((const __m128i*) (data + 16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    MSG = _mm_add_epi32(MSG1, CONST2);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    __m128i MSG2 = _mm_loadu_si128((const __m128i*) (data + 32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    MSG = _mm_add_epi32(MSG2, CONST3);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    __m128i MSG3 = _mm_loadu_si128((const __m128i*) (data + 48));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    MSG = _mm_add_epi32(MSG3, CONST4);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    __m128i TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    MSG = _mm_add_epi32(MSG0, CONST5);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 20-23 */
    MSG = _mm_add_epi32(MSG1, CONST6);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 24-27 */
    MSG = _mm_add_epi32(MSG2, CONST7);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 28-31 */
    MSG = _mm_add_epi32(MSG3, CONST8);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 32-35 */
    MSG = _mm_add_epi32(MSG0, CONST9);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 36-39 */
    MSG = _mm_add_epi32(MSG1, CONST10);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 40-43 */
    MSG = _mm_add_epi32(MSG2, CONST11);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 44-47 */
    MSG = _mm_add_epi32(MSG3, CONST12);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 48-51 */
    MSG = _mm_add_epi32(MSG0, CONST13);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 52-55 */
    MSG = _mm_add_epi32(MSG1, CONST14);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    /* Rounds 56-59 */
    MSG = _mm_add_epi32(MSG2, CONST15);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 60-63 */
    MSG = _mm_add_epi32(MSG3, CONST16);
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Combine state  */
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
    *STATE0_ = STATE0;
    *STATE1_ = STATE1;
}

void AVX_sha256_device(uint8_t* out, const uint8_t *data_, uint32_t length_, uint32_t out_len)
{


    __m128i STATE0 = _mm_setr_epi32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a),
        STATE1 = _mm_setr_epi32(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);

    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Load initial values */
    //TMP = _mm_loadu_si128((const __m128i*) & state[0]);
    //STATE1 = _mm_loadu_si128((const __m128i*) & state[4]);


    //TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
    TMP = _mm_shuffle_epi32(STATE0, 0xB1);          /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */
    uint32_t length = length_;
    const uint8_t* data = data_;

    while (length >= 64)
    {
        BLOCK;
        //funBlock(&STATE0, &STATE1, data, length);
        data += 64;
        length -= 64;
    }

    uint64_t bits = (uint64_t)length_ * 8;

    uint8_t padded[128];
    for (uint32_t i = 0; i < length; ++i) padded[i] = data[i];
    padded[length] = 0x80;

    if (length < 56) {
        for (int i = length + 1; i < 56; ++i) padded[i] = 0;
        padded[56] = (uint8_t)(bits >> 56);
        padded[57] = (uint8_t)(bits >> 48);
        padded[58] = (uint8_t)(bits >> 40);
        padded[59] = (uint8_t) (bits >> 32);
        padded[60] = (uint8_t) (bits >> 24);
        padded[61] = (uint8_t)(bits >> 16);
        padded[62] = (uint8_t)(bits >> 8);
        padded[63] = (uint8_t)bits;
        data = padded;
        BLOCK;

        //funBlock(&STATE0, &STATE1, data, length);
    }
    else {

        for (int i = length + 1; i < 120; ++i) padded[i] = 0;
        padded[120] = (uint8_t)(bits >> 56);
        padded[121] = (uint8_t)(bits >> 48);
        padded[122] = (uint8_t)(bits >> 40);
        padded[123] = (uint8_t)(bits >> 32);
        padded[124] = (uint8_t)(bits >> 24);
        padded[125] = (uint8_t)(bits >> 16);
        padded[126] = (uint8_t)(bits >> 8);
        padded[127] = (uint8_t)(bits);

        //blocks(h, padded, 128);
        data = padded;
        BLOCK;
        //funBlock(&STATE0, &STATE1, data, length);
        data = padded + 64;
        BLOCK;
        //funBlock(&STATE0, &STATE1, data, length);
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF */

    STATE0 = _mm_shuffle_epi8(STATE0, MASK);
    STATE1 = _mm_shuffle_epi8(STATE1, MASK);

    uint8_t temp[32];
    _mm_storeu_si128((__m128i*) temp, STATE0);
    _mm_storeu_si128((__m128i*) (temp+16), STATE1);
    memcpy(out, temp, out_len);

}


__m128i _mm_sha256rnds2_epu32_emu(__m128i  a, __m128i  b, __m128i k)
{
    __m128i dest;
    uint32_t t1, t2;

#ifdef _MSC_VER
    uint32_t A =  b.m128i_i32[3] ;
    uint32_t B =  b.m128i_i32[2] ;
    uint32_t C =  a.m128i_i32[3] ;
    uint32_t D =  a.m128i_i32[2] ;
    uint32_t E =  b.m128i_i32[1] ;
    uint32_t F =  b.m128i_i32[0] ;
    uint32_t G =  a.m128i_i32[1] ;
    uint32_t H =  a.m128i_i32[0] ;

    /*printf("ABCD: %x %x %x %x\n", A, B, C, D);
    printf("EFGH: %x %x %x %x\n", E, F, G, H);*/

    uint32_t W_K_[2] = { k.m128i_i32[0], k.m128i_i32[1] };
#else
    int32_t A =  ((int32_t*)&b)[3] ;
    uint32_t B =  ((int32_t*)&b)[2] ;
    uint32_t C =  ((int32_t*)&a)[3] ;
    uint32_t D =  ((int32_t*)&a)[2] ;
    uint32_t E =  ((int32_t*)&b)[1] ;
    uint32_t F =  ((int32_t*)&b)[0] ;
    uint32_t G =  ((int32_t*)&a)[1] ;
    uint32_t H =  ((int32_t*)&a)[0] ;

    /*printf("ABCD: %x %x %x %x\n", A, B, C, D);
    printf("EFGH: %x %x %x %x\n", E, F, G, H);*/

    uint32_t W_K_[2] = { ((int32_t*)&k)[0], ((int32_t*)&k)[1] };
#endif

    /*
    FOR i := 0 to 1
	A[i+1] := Ch(E[i], F[i], G[i]) + sum1(E[i]) + W_K[i] + H[i] + Maj(A[i], B[i], C[i]) + sum0(A[i])
	B[i+1] := A[i]
	C[i+1] := B[i]
	D[i+1] := C[i]
	E[i+1] := Ch(E[i], F[i], G[i]) + sum1(E[i]) + W_K[i] + H[i] + D[i]
	F[i+1] := E[i]
	G[i+1] := F[i]
	H[i+1] := G[i]
ENDFOR
    

    */
    // A[i+1] := Ch(E[i], F[i], G[i]) + sum1(E[i]) + W_K[i] + H[i] + Maj(A[i], B[i], C[i]) + sum0(A[i])
    t1 = ch(E, F, G) + S1(E) + W_K_[0] + H ;
    t2 = S0(A) + maj(A, B, C);
    /*printf("t1_t2_: %x %x\n", t1, t2);*/

    
    H = G;
    G = F;
    F = E;
    E = t1 + D;
    D = C;
    C = B;
    B = A;
    A = t1 + t2;

    /*printf("ABCD: %x %x %x %x\n", A, B, C, D);
    printf("EFGH: %x %x %x %x\n", E, F, G, H);*/

    t1 = ch(E, F, G) + S1(E) + W_K_[1] + H;
    t2 = S0(A) + maj(A, B, C);
    /*printf("t1_t2_: %x %x\n", t1, t2);*/

    H = G;
    G = F;
    F = E;
    E = t1 + D;
    D = C;
    C = B;
    B = A;
    A = t1 + t2;
    /*printf("ABCD: %x %x %x %x\n", A, B, C, D);
    printf("EFGH: %x %x %x %x\n", E, F, G, H);*/

    dest = _mm_set_epi32(A, B, E, F);
    /*printf("dest: %x %x %x %x\n", dest.m128i_u32[0], dest.m128i_u32[1], dest.m128i_u32[2], dest.m128i_u32[3]);
#ifndef _DEBUG
    printf("*********RELEASE**************************\n");
#else
    printf("*********DEBUG**************************\n");
#endif*/
    return dest;

}

int test_mm_sha256rnds2_epu32_emu()
{
    __m128i A, B, C, R1, R2;
    srand(0);
    A = _mm_set_epi32(1, 2, 3, 4);
    B = _mm_set_epi32(5, 6, 7, 8);
    C = _mm_set_epi32(9, 10, 11, 12);
    R1 = _mm_sha256rnds2_epu32(A, B, C);
    R2 = _mm_sha256rnds2_epu32_emu(A, B, C);
#ifdef _MSC_VER
    printf("R1: %x %x %x %x\n", R1.m128i_u32[0], R1.m128i_u32[1], R1.m128i_u32[2], R1.m128i_u32[3]);
    printf("R2: %x %x %x %x\n", R2.m128i_u32[0], R2.m128i_u32[1], R2.m128i_u32[2], R2.m128i_u32[3]);
    int res = (R1.m128i_i32[0] != R2.m128i_i32[0]) |
        (R1.m128i_i32[1] != R2.m128i_i32[1]) |
        (R1.m128i_i32[2] != R2.m128i_i32[2]) |
        (R1.m128i_i32[3] != R2.m128i_i32[3]);
    return res;
#else
    printf("R1: %x %x %x %x\n", ((uint32_t*)&R1)[0], ((uint32_t*)&R1)[1], ((uint32_t*)&R1)[2], ((uint32_t*)&R1)[3]);
    printf("R2: %x %x %x %x\n", ((uint32_t*)&R2)[0], ((uint32_t*)&R2)[1], ((uint32_t*)&R2)[2], ((uint32_t*)&R2)[3]);
    int res = (((int32_t*)&R1)[0] != ((int32_t*)&R2)[0]) |
              (((int32_t*)&R1)[1] != ((int32_t*)&R2)[1]) |
              (((int32_t*)&R1)[2] != ((int32_t*)&R2)[2]) |
              (((int32_t*)&R1)[3] != ((int32_t*)&R2)[3]);
    return res;
#endif

}


__m128i _mm_sha256msg1_epu32_emu(__m128i a, __m128i b)
{

    /*
    W4 := b[31:0]
W3 := a[127:96]
W2 := a[95:64]
W1 := a[63:32]
W0 := a[31:0]
dst[127:96] := W3 + sigma0(W4)
dst[95:64] := W2 + sigma0(W3)
dst[63:32] := W1 + sigma0(W2)
dst[31:0] := W0 + sigma0(W1)
    */
    //uint32_t W4 = b.m128i_i32[0];
    __m128i r;
    __m128i W_ = _mm_slli_si128(b, 12);
    __m128i W = _mm_add_epi32(_mm_srli_si128(a, 4), W_);   // W1, W2, W3, W4
    W = s0_128(W);
    r = _mm_add_epi32(a, W);

    /*uint32_t w[5] = { a.m128i_u32[0], a.m128i_u32[1], a.m128i_u32[2], a.m128i_u32[3], b.m128i_u32[0] };
    uint32_t dst[4];
    dst[0] = w[0] + s0(w[1]);
    dst[1] = w[1] + s0(w[2]);
    dst[2] = w[2] + s0(w[3]);
    dst[3] = w[3] + s0(w[4]);*/
    return r;
}


int test_mm_sha256msg1_epu32_emu()
{
    __m128i a = _mm_set_epi32(rand(), rand(), rand(), rand());
    __m128i b = _mm_set_epi32(rand(), rand(), rand(), rand());
    __m128i R1, R2;
    R1 = _mm_sha256msg1_epu32(a, b);
    R2 = _mm_sha256msg1_epu32_emu(a, b);
#ifdef _MSC_VER
    int res = (R1.m128i_i32[0] != R2.m128i_i32[0]) |
        (R1.m128i_i32[1] != R2.m128i_i32[1]) |
        (R1.m128i_i32[2] != R2.m128i_i32[2]) |
        (R1.m128i_i32[3] != R2.m128i_i32[3]);
    return res;
#else
    int res = (((int32_t*)&R1)[0] != ((int32_t*)&R2)[0]) |
              (((int32_t*)&R1)[1] != ((int32_t*)&R2)[1]) |
              (((int32_t*)&R1)[2] != ((int32_t*)&R2)[2]) |
              (((int32_t*)&R1)[3] != ((int32_t*)&R2)[3]);
    return res;
#endif
}

__m128i  _mm_sha256msg2_epu32_emu(__m128i a, __m128i b)
{
    //W14: = b[95:64]
    //W15 : = b[127:96]
    //W16 : = a[31:0] + sigma1(W14)
    //W17 : = a[63:32] + sigma1(W15)
    //W18 : = a[95:64] + sigma1(W16)
    //W19 : = a[127:96] + sigma1(W17)
    //dst[127:96] : = W19
    //dst[95:64] : = W18
    //dst[63:32] : = W17
    //dst[31:0] : = W16

        
    ALIGN64 uint32_t w[4] ;
        
    _mm_store_si128((__m128i*)(w ), _mm_add_epi32(a, s1_128(_mm_srli_si128(b, 8))));
        
    __m128i t1 = _mm_load_si128( (const __m128i*)w );
    
    t1 = _mm_add_epi32(t1, s1_128(_mm_slli_si128(t1, 8)));
    
    return t1;

}

int test_mm_sha256msg2_epu32_emu()
{
    __m128i a = _mm_setr_epi32(1, 2, 3, 4);
    __m128i b = _mm_setr_epi32(5, 6, 7, 8);
    __m128i R1 = _mm_sha256msg2_epu32(a, b);
    __m128i R2 = _mm_sha256msg2_epu32_emu(a, b);
#ifdef _MSC_VER
    int res = (R1.m128i_i32[0] != R2.m128i_i32[0]) |
        (R1.m128i_i32[1] != R2.m128i_i32[1]) |
        (R1.m128i_i32[2] != R2.m128i_i32[2]) |
        (R1.m128i_i32[3] != R2.m128i_i32[3]);
    return res;
#else
    int res = (((int32_t*)&R1)[0] != ((int32_t*)&R2)[0]) |
              (((int32_t*)&R1)[1] != ((int32_t*)&R2)[1]) |
              (((int32_t*)&R1)[2] != ((int32_t*)&R2)[2]) |
              (((int32_t*)&R1)[3] != ((int32_t*)&R2)[3]);
    return res;
#endif

}

#define BLOCK_EMU                                           \
ABEF_SAVE = STATE0;                                         \
CDGH_SAVE = STATE1;                                         \
                                                            \
/* Rounds 0-3 */                                            \
MSG = _mm_loadu_si128((const __m128i*) (data + 0));         \
MSG0 = _mm_shuffle_epi8(MSG, MASK);                         \
MSG = _mm_add_epi32(MSG0, CONST1);                          \
STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
                                                            \
/* Rounds 4-7 */                                            \
MSG1 = _mm_loadu_si128((const __m128i*) (data + 16));       \
MSG1 = _mm_shuffle_epi8(MSG1, MASK);                        \
MSG = _mm_add_epi32(MSG1, CONST2);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);                    \
                                                            \
/* Rounds 8-11 */                                           \
MSG2 = _mm_loadu_si128((const __m128i*) (data + 32));       \
MSG2 = _mm_shuffle_epi8(MSG2, MASK);                        \
MSG = _mm_add_epi32(MSG2, CONST3);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG1 = _mm_sha256msg1_epu32_emu(MSG1, MSG2);                    \
                                                            \
/* Rounds 12-15 */                                          \
MSG3 = _mm_loadu_si128((const __m128i*) (data + 48));       \
MSG3 = _mm_shuffle_epi8(MSG3, MASK);                        \
MSG = _mm_add_epi32(MSG3, CONST4);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG3, MSG2, 4);                       \
MSG0 = _mm_add_epi32(MSG0, TMP);                            \
MSG0 = _mm_sha256msg2_epu32_emu(MSG0, MSG3);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG2 = _mm_sha256msg1_epu32_emu(MSG2, MSG3);                    \
                                                            \
/* Rounds 16-19 */                                          \
MSG = _mm_add_epi32(MSG0, CONST5);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG0, MSG3, 4);                       \
MSG1 = _mm_add_epi32(MSG1, TMP);                            \
MSG1 = _mm_sha256msg2_epu32_emu(MSG1, MSG0);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG3 = _mm_sha256msg1_epu32_emu(MSG3, MSG0);                    \
                                                            \
/* Rounds 20-23 */                                          \
MSG = _mm_add_epi32(MSG1, CONST6);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG1, MSG0, 4);                       \
MSG2 = _mm_add_epi32(MSG2, TMP);                            \
MSG2 = _mm_sha256msg2_epu32_emu(MSG2, MSG1);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG0 = _mm_sha256msg1_epu32_emu(MSG0, MSG1);                    \
                                                            \
/* Rounds 24-27 */                                          \
MSG = _mm_add_epi32(MSG2, CONST7);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG2, MSG1, 4);                       \
MSG3 = _mm_add_epi32(MSG3, TMP);                            \
MSG3 = _mm_sha256msg2_epu32_emu(MSG3, MSG2);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG1 = _mm_sha256msg1_epu32_emu(MSG1, MSG2);                    \
                                                            \
/* Rounds 28-31 */                                          \
MSG = _mm_add_epi32(MSG3, CONST8);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG3, MSG2, 4);                       \
MSG0 = _mm_add_epi32(MSG0, TMP);                            \
MSG0 = _mm_sha256msg2_epu32_emu(MSG0, MSG3);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG2 = _mm_sha256msg1_epu32_emu(MSG2, MSG3);                    \
                                                            \
/* Rounds 32-35 */                                          \
MSG = _mm_add_epi32(MSG0, CONST9);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG0, MSG3, 4);                       \
MSG1 = _mm_add_epi32(MSG1, TMP);                            \
MSG1 = _mm_sha256msg2_epu32_emu(MSG1, MSG0);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG3 = _mm_sha256msg1_epu32_emu(MSG3, MSG0);                    \
                                                            \
/* Rounds 36-39 */                                          \
MSG = _mm_add_epi32(MSG1, CONST10);                         \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG1, MSG0, 4);                       \
MSG2 = _mm_add_epi32(MSG2, TMP);                            \
MSG2 = _mm_sha256msg2_epu32_emu(MSG2, MSG1);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG0 = _mm_sha256msg1_epu32_emu(MSG0, MSG1);                    \
                                                            \
/* Rounds 40-43 */                                          \
MSG = _mm_add_epi32(MSG2, CONST11);                         \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG2, MSG1, 4);                       \
MSG3 = _mm_add_epi32(MSG3, TMP);                            \
MSG3 = _mm_sha256msg2_epu32_emu(MSG3, MSG2);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG1 = _mm_sha256msg1_epu32_emu(MSG1, MSG2);                    \
                                                            \
/* Rounds 44-47 */                                          \
MSG = _mm_add_epi32(MSG3, CONST12);                          \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG3, MSG2, 4);                       \
MSG0 = _mm_add_epi32(MSG0, TMP);                            \
MSG0 = _mm_sha256msg2_epu32_emu(MSG0, MSG3);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG2 = _mm_sha256msg1_epu32_emu(MSG2, MSG3);                    \
                                                            \
/* Rounds 48-51 */                                          \
MSG = _mm_add_epi32(MSG0, CONST13);                         \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG0, MSG3, 4);                       \
MSG1 = _mm_add_epi32(MSG1, TMP);                            \
MSG1 = _mm_sha256msg2_epu32_emu(MSG1, MSG0);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
MSG3 = _mm_sha256msg1_epu32_emu(MSG3, MSG0);                    \
                                                            \
/* Rounds 52-55 */                                          \
MSG = _mm_add_epi32(MSG1, CONST14);                         \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG1, MSG0, 4);                       \
MSG2 = _mm_add_epi32(MSG2, TMP);                            \
MSG2 = _mm_sha256msg2_epu32_emu(MSG2, MSG1);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
/* Rounds 56-59 */                                          \
MSG = _mm_add_epi32(MSG2, CONST15);                         \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
TMP = _mm_alignr_epi8(MSG2, MSG1, 4);                       \
MSG3 = _mm_add_epi32(MSG3, TMP);                            \
MSG3 = _mm_sha256msg2_epu32_emu(MSG3, MSG2);                    \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
                                                            \
/* Rounds 60-63 */                                          \
MSG = _mm_add_epi32(MSG3, CONST16);                         \
STATE1 = _mm_sha256rnds2_epu32_emu(STATE1, STATE0, MSG);        \
MSG = _mm_shuffle_epi32(MSG, 0x0E);                         \
STATE0 = _mm_sha256rnds2_epu32_emu(STATE0, STATE1, MSG);        \
                                                            \
/* Combine state  */                                        \
STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);                  \
STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE)                  


void sha256_device_emu(uint8_t* dest, const uint8_t* data_, uint32_t length_)
{


    __m128i STATE0 = _mm_setr_epi32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a),
        STATE1 = _mm_setr_epi32(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);

    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Load initial values */
    //TMP = _mm_loadu_si128((const __m128i*) & state[0]);
    //STATE1 = _mm_loadu_si128((const __m128i*) & state[4]);


    //TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
    TMP = _mm_shuffle_epi32(STATE0, 0xB1);          /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */
    uint32_t length = length_;
    const uint8_t* data = data_;

    while (length >= 64)
    {
        BLOCK_EMU;
        //funBlock(&STATE0, &STATE1, data, length);
        data += 64;
        length -= 64;
    }

    uint64_t bits = (uint64_t)length_ * 8;

    uint8_t padded[128];
    for (uint32_t i = 0; i < length; ++i) padded[i] = data[i];
    padded[length] = 0x80;

    if (length < 56) {
        for (int i = length + 1; i < 56; ++i) padded[i] = 0;
        padded[56] = (uint8_t)(bits >> 56);
        padded[57] = (uint8_t)(bits >> 48);
        padded[58] = (uint8_t)(bits >> 40);
        padded[59] = (uint8_t)(bits >> 32);
        padded[60] = (uint8_t)(bits >> 24);
        padded[61] = (uint8_t)(bits >> 16);
        padded[62] = (uint8_t)(bits >> 8);
        padded[63] = (uint8_t)bits;
        data = padded;
        BLOCK_EMU;

        //funBlock(&STATE0, &STATE1, data, length);
    }
    else {

        for (int i = length + 1; i < 120; ++i) padded[i] = 0;
        padded[120] = (uint8_t)(bits >> 56);
        padded[121] = (uint8_t)(bits >> 48);
        padded[122] = (uint8_t)(bits >> 40);
        padded[123] = (uint8_t)(bits >> 32);
        padded[124] = (uint8_t)(bits >> 24);
        padded[125] = (uint8_t)(bits >> 16);
        padded[126] = (uint8_t)(bits >> 8);
        padded[127] = (uint8_t)(bits);

        //blocks(h, padded, 128);
        data = padded;
        BLOCK_EMU;
        //funBlock(&STATE0, &STATE1, data, length);
        data = padded + 64;
        BLOCK_EMU;
        //funBlock(&STATE0, &STATE1, data, length);
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF */

    STATE0 = _mm_shuffle_epi8(STATE0, MASK);
    STATE1 = _mm_shuffle_epi8(STATE1, MASK);

    _mm_storeu_si128((__m128i*) dest, STATE0);
    _mm_storeu_si128((__m128i*) (dest + 16), STATE1);

}

void AVX_MGF1_sha256_device(unsigned char* out, unsigned long outlen,
    const unsigned char* in, unsigned long inlen)
{
    unsigned char* inbuf = (unsigned char*)malloc(inlen + 4);
    unsigned char outbuf[32];
    unsigned long i;

    //memcpy(inbuf, in, inlen);
    for (i = 0; i < inlen; ++i)
    {
        inbuf[i] = in[i];
    }

    /* While we can fit in at least another full block of sha256 output.. */
    for (i = 0; (i + 1) * 32 <= outlen; i++) {
        toByte32_(inbuf + inlen, i);
        AVX_sha256_device(out, inbuf, inlen + 4, 32);
        out += 32;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i * 32) {
        toByte32_(inbuf + inlen, i);
        AVX_sha256_device(outbuf, inbuf, inlen + 4, 32);
        memcpy(out, outbuf, outlen - i * 32);
    }
    free(inbuf);
}

void AVX_HMAC_device(uint8_t* dest, uint8_t* sk, uint32_t sk_len, uint8_t* src, uint32_t len)
{

#define	BLOCKSIZE	64

    uint32_t i;
    uint8_t buf[BLOCKSIZE + BLOCKSIZE / 2]; // oKey
    uint8_t* temp = malloc(BLOCKSIZE + len);    //      ikey
    if (temp)
    {

        for (i = 0; i < sk_len; ++i)
        {
            temp[i] = sk[i] ^ 0x36;
        }

        for (i = 0; i < BLOCKSIZE - sk_len; ++i)
        {
            temp[sk_len + i] = 0x36;
        }
        /*memset(temp, 0x36, BLOCKSIZE);

        for (i = 0; i < N; ++i)
        {
            temp[i] ^= sk[i];
        }*/

        for (i = 0; i < len; i++)
            temp[BLOCKSIZE + i] = src[i];

        for (i = 0; i < sk_len; ++i)
        {
            buf[i] = sk[i] ^ 0x5C;
        }

        for (i = 0; i < BLOCKSIZE - sk_len; ++i)
        {
            buf[sk_len + i] = 0x5C;
        }
        memset(buf, 0x5C, BLOCKSIZE);
        for (i = 0; i < sk_len; ++i)
        {
            buf[i] ^= sk[i];
        }


        //cur += BLOCKSIZE - N;


        AVX_sha256_device(buf + BLOCKSIZE, temp, BLOCKSIZE + len, 32);

        AVX_sha256_device(temp, buf, BLOCKSIZE + BLOCKSIZE / 2, 32);


        for (i = 0; i < sk_len; ++i)
        {
            dest[i] = temp[i];
        }
        free(temp);
    }


}