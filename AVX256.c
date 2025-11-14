#include <stdio.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>   // covers AVX, SSE, FMA, etc.
#endif
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "AVXconst.h"
#include "SHA256_device.h"
#include "FIPS_205_Params.h"

#include "FIPS_205_Adr.h"
#include "Common.h"


#ifndef _DEBUG
static uint64_t tacts, min_tacts;
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

ALIGN64 static uint32_t HInit[8] =
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};


ALIGN64 static const uint32_t k[] =
{
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

};


#define DO(w) \
    temp1 = h + S1(e) + ch(e, f, g) + w;    \
    temp2 = S0(a) + maj(a, b, c);           \
    h = g;  \
    g = f;  \
    f = e;  \
    e = d + temp1;\
    d = c;\
    c = b;\
    b = a;\
    a = temp1 + temp2

#define DO_128(w, cns) \
        \
    temp1 = _mm_add_epi32 (                                 \
                _mm_add_epi32 (h, S1_128 (e)),              \
                _mm_add_epi32(                              \
                    _mm_add_epi32 (ch_128 (e, f, g), w),    \
                    _mm_set1_epi32 (cns)                      \
                ));                                         \
     temp2 = _mm_add_epi32(S0_128(a), maj_128(a, b, c));    \
    \
    h = g;  \
    g = f;  \
    f = e;  \
    e = _mm_add_epi32 (d ,temp1 );\
    d = c;\
    c = b;\
    b = a;\
    a = _mm_add_epi32 (temp1 , temp2);


#define DO_256(w, cns) \
        \
    temp1 = _mm256_add_epi32 (                                 \
                _mm256_add_epi32 (h, S1_256 (e)),              \
                _mm256_add_epi32(                              \
                    _mm256_add_epi32 (ch_256 (e, f, g), w),    \
                    _mm256_set1_epi32 (cns)                      \
                ));                                         \
     temp2 = _mm256_add_epi32(S0_256(a), maj_256(a, b, c));    \
    \
    h = g;  \
    g = f;  \
    f = e;  \
    e = _mm256_add_epi32 (d ,temp1 );\
    d = c;\
    c = b;\
    b = a;\
    a = _mm256_add_epi32 (temp1 , temp2);


void AVX_sha256_calc_w(__m256i* w256)
{
    uint32_t* w = (uint32_t*)w256;
    uint32_t t;
    for (t = 16; t < 64; t += 16)
    {


        w[t] = w[t - 16] + s0(w[t - 15]) + w[t - 7] + s1(w[t - 2]);
        w[t + 1] = w[t - 15] + s0(w[t - 14]) + w[t - 6] + s1(w[t - 1]);
        w[t + 2] = w[t - 14] + s0(w[t - 13]) + w[t - 5] + s1(w[t]);
        w[t + 3] = w[t - 13] + s0(w[t - 12]) + w[t - 4] + s1(w[t + 1]);

        w[t + 4] = w[t - 12] + s0(w[t - 11]) + w[t - 3] + s1(w[t + 2]);
        w[t + 5] = w[t - 11] + s0(w[t - 10]) + w[t - 2] + s1(w[t + 3]);
        w[t + 6] = w[t - 10] + s0(w[t - 9]) + w[t - 1] + s1(w[t + 4]);
        w[t + 7] = w[t - 9] + s0(w[t - 8]) + w[t - 0] + s1(w[t + 5]);

        w[t + 8] = w[t - 8] + s0(w[t - 7]) + w[t + 1] + s1(w[t + 6]);
        w[t + 9] = w[t - 7] + s0(w[t - 6]) + w[t + 2] + s1(w[t + 7]);
        w[t + 10] = w[t - 6] + s0(w[t - 5]) + w[t + 3] + s1(w[t + 8]);
        w[t + 11] = w[t - 5] + s0(w[t - 4]) + w[t + 4] + s1(w[t + 9]);

        w[t + 12] = w[t - 4] + s0(w[t - 3]) + w[t + 5] + s1(w[t + 10]);
        w[t + 13] = w[t - 3] + s0(w[t - 2]) + w[t + 6] + s1(w[t + 11]);
        w[t + 14] = w[t - 2] + s0(w[t - 1]) + w[t + 7] + s1(w[t + 12]);
        w[t + 15] = w[t - 1] + s0(w[t]) + w[t + 8] + s1(w[t + 13]);

    }
    const __m256i* k256 = (const __m256i*)k;
    w256[0] = _mm256_add_epi32(k256[0], w256[0]);
    w256[1] = _mm256_add_epi32(k256[1], w256[1]);
    w256[2] = _mm256_add_epi32(k256[2], w256[2]);
    w256[3] = _mm256_add_epi32(k256[3], w256[3]);
    w256[4] = _mm256_add_epi32(k256[4], w256[4]);
    w256[5] = _mm256_add_epi32(k256[5], w256[5]);
    w256[6] = _mm256_add_epi32(k256[6], w256[6]);
    w256[7] = _mm256_add_epi32(k256[7], w256[7]);

}

void AVX_sha256_calc_state(uint32_t* state, const uint32_t* w)
{
    uint32_t a = state[0];    //a[0]
    uint32_t b = state[1];    //  a[1]
    uint32_t c = state[2];    //  a[2]
    uint32_t d = state[3];    //  a[3]
    uint32_t e = state[4];    //  a[4]
    uint32_t f = state[5];    //  a[5]
    uint32_t g = state[6];    //  a[6]
    uint32_t h = state[7];    //  a[7]

    uint32_t temp1, temp2;
    DO(w[0]);
    DO(w[1]);
    DO(w[2]);
    DO(w[3]);
    DO(w[4]);
    DO(w[5]);
    DO(w[6]);
    DO(w[7]);
    DO(w[8]);
    DO(w[9]);
    DO(w[10]);
    DO(w[11]);
    DO(w[12]);
    DO(w[13]);
    DO(w[14]);
    DO(w[15]);
    //
    DO(w[16]);
    DO(w[17]);
    DO(w[18]);
    DO(w[19]);
    DO(w[20]);
    DO(w[21]);
    DO(w[22]);
    DO(w[23]);
    DO(w[24]);
    DO(w[25]);
    DO(w[26]);
    DO(w[27]);
    DO(w[28]);
    DO(w[29]);
    DO(w[30]);
    DO(w[31]);
    //
    DO(w[32]);
    DO(w[33]);
    DO(w[34]);
    DO(w[35]);
    DO(w[36]);
    DO(w[37]);
    DO(w[38]);
    DO(w[39]);
    DO(w[40]);
    DO(w[41]);
    DO(w[42]);
    DO(w[43]);
    DO(w[44]);
    DO(w[45]);
    DO(w[46]);
    DO(w[47]);
    //
    DO(w[48]);
    DO(w[49]);
    DO(w[50]);
    DO(w[51]);
    DO(w[52]);
    DO(w[53]);
    DO(w[54]);
    DO(w[55]);
    DO(w[56]);
    DO(w[57]);
    DO(w[58]);
    DO(w[59]);
    DO(w[60]);
    DO(w[61]);
    DO(w[62]);
    DO(w[63]);


    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}


void AVX_sha256_compress(uint32_t* state, /*__m256i *block256*/__m256i *w256)
{
    AVX_sha256_calc_w(w256);
    
    AVX_sha256_calc_state(state, (const uint32_t*)w256);
}

void AVX_sha256_calc_w4(__m128i* w)
{
    for (uint32_t t = 16; t < 64; t += 16)
    {


        //w[t] = w[t - 16] + s0(w[t - 15]) + w[t - 7] + s1(w[t - 2]);
        w[t] = _mm_add_epi32(
            _mm_add_epi32(w[t - 16], s0_128(w[t - 15])),
            _mm_add_epi32(w[t - 7], s1_128(w[t - 2])));

        //w[t + 1] = w[t - 15] + s0(w[t - 14]) + w[t - 6] + s1(w[t - 1]);
        w[t + 1] = _mm_add_epi32(
            _mm_add_epi32(w[t - 15], s0_128(w[t - 14])),
            _mm_add_epi32(w[t - 6], s1_128(w[t - 1])));

        //w[t + 2] = w[t - 14] + s0(w[t - 13]) + w[t - 5] + s1(w[t]);
        w[t + 2] = _mm_add_epi32(
            _mm_add_epi32(w[t - 14], s0_128(w[t - 13])),
            _mm_add_epi32(w[t - 5], s1_128(w[t])));

        //w[t + 3] = w[t - 13] + s0(w[t - 12]) + w[t - 4] + s1(w[t + 1]);
        w[t + 3] = _mm_add_epi32(
            _mm_add_epi32(w[t - 13], s0_128(w[t - 12])),
            _mm_add_epi32(w[t - 4], s1_128(w[t + 1])));

        //w[t + 4] = w[t - 12] + s0(w[t - 11]) + w[t - 3] + s1(w[t + 2]);
        w[t + 4] = _mm_add_epi32(
            _mm_add_epi32(w[t - 12], s0_128(w[t - 11])),
            _mm_add_epi32(w[t - 3], s1_128(w[t + 2])));

        //w[t + 5] = w[t - 11] + s0(w[t - 10]) + w[t - 2] + s1(w[t + 3]);
        w[t + 5] = _mm_add_epi32(
            _mm_add_epi32(w[t - 11], s0_128(w[t - 10])),
            _mm_add_epi32(w[t - 2], s1_128(w[t + 3])));

        //w[t + 6] = w[t - 10] + s0(w[t - 9]) + w[t - 1] + s1(w[t + 4]);
        w[t + 6] = _mm_add_epi32(
            _mm_add_epi32(w[t - 10], s0_128(w[t - 9])),
            _mm_add_epi32(w[t - 1], s1_128(w[t + 4])));

        //w[t + 7] = w[t - 9] + s0(w[t - 8]) + w[t - 0] + s1(w[t + 5]);
        w[t + 7] = _mm_add_epi32(
            _mm_add_epi32(w[t - 9], s0_128(w[t - 8])),
            _mm_add_epi32(w[t - 0], s1_128(w[t + 5])));

        //w[t + 8] = w[t - 8] + s0(w[t - 7]) + w[t + 1] + s1(w[t + 6]);
        w[t + 8] = _mm_add_epi32(
            _mm_add_epi32(w[t - 8], s0_128(w[t - 7])),
            _mm_add_epi32(w[t + 1], s1_128(w[t + 6])));

        //w[t + 9] = w[t - 7] + s0(w[t - 6]) + w[t + 2] + s1(w[t + 7]);
        w[t + 9] = _mm_add_epi32(
            _mm_add_epi32(w[t - 7], s0_128(w[t - 6])),
            _mm_add_epi32(w[t + 2], s1_128(w[t + 7])));

        //w[t + 10] = w[t - 6] + s0(w[t - 5]) + w[t + 3] + s1(w[t + 8]);
        w[t + 10] = _mm_add_epi32(
            _mm_add_epi32(w[t - 6], s0_128(w[t - 5])),
            _mm_add_epi32(w[t + 3], s1_128(w[t + 8])));

        //w[t + 11] = w[t - 5] + s0(w[t - 4]) + w[t + 4] + s1(w[t + 9]);
        w[t + 11] = _mm_add_epi32(
            _mm_add_epi32(w[t - 5], s0_128(w[t - 4])),
            _mm_add_epi32(w[t + 4], s1_128(w[t + 9])));

        //w[t + 12] = w[t - 4] + s0(w[t - 3]) + w[t + 5] + s1(w[t + 10]);
        w[t + 12] = _mm_add_epi32(
            _mm_add_epi32(w[t - 4], s0_128(w[t - 3])),
            _mm_add_epi32(w[t + 5], s1_128(w[t + 10])));

        //w[t + 13] = w[t - 3] + s0(w[t - 2]) + w[t + 6] + s1(w[t + 11]);
        w[t + 13] = _mm_add_epi32(
            _mm_add_epi32(w[t - 3], s0_128(w[t - 2])),
            _mm_add_epi32(w[t + 6], s1_128(w[t + 11])));

        //w[t + 14] = w[t - 2] + s0(w[t - 1]) + w[t + 7] + s1(w[t + 12]);
        w[t + 14] = _mm_add_epi32(
            _mm_add_epi32(w[t - 2], s0_128(w[t - 1])),
            _mm_add_epi32(w[t + 7], s1_128(w[t + 12])));

        //w[t + 15] = w[t - 1] + s0(w[t]) + w[t + 8] + s1(w[t + 13]);
        w[t + 15] = _mm_add_epi32(
            _mm_add_epi32(w[t - 1], s0_128(w[t])),
            _mm_add_epi32(w[t + 8], s1_128(w[t + 13])));

    }
}


void AVX_sha256_calc_state4(__m128i state[8], const __m128i* w)
{
    __m128i a = state[0];
    __m128i b = state[1];
    __m128i c = state[2];
    __m128i d = state[3];
    __m128i e = state[4];
    __m128i f = state[5];
    __m128i g = state[6];
    __m128i h = state[7];

    __m128i temp1, temp2;
    DO_128(w[0], k[0]);
    DO_128(w[1], k[1]);
    DO_128(w[2], k[2]);
    DO_128(w[3], k[3]);
    DO_128(w[4], k[4]);
    DO_128(w[5], k[5]);
    DO_128(w[6], k[6]);
    DO_128(w[7], k[7]);
    DO_128(w[8], k[8]);
    DO_128(w[9], k[9]);
    DO_128(w[10], k[10]);
    DO_128(w[11], k[11]);
    DO_128(w[12], k[12]);
    DO_128(w[13], k[13]);
    DO_128(w[14], k[14]);
    DO_128(w[15], k[15]);
    //
    DO_128(w[16], k[16]);
    DO_128(w[17], k[17]);
    DO_128(w[18], k[18]);
    DO_128(w[19], k[19]);
    DO_128(w[20], k[20]);
    DO_128(w[21], k[21]);
    DO_128(w[22], k[22]);
    DO_128(w[23], k[23]);
    DO_128(w[24], k[24]);
    DO_128(w[25], k[25]);
    DO_128(w[26], k[26]);
    DO_128(w[27], k[27]);
    DO_128(w[28], k[28]);
    DO_128(w[29], k[29]);
    DO_128(w[30], k[30]);
    DO_128(w[31], k[31]);
    //
    DO_128(w[32], k[32]);
    DO_128(w[33], k[33]);
    DO_128(w[34], k[34]);
    DO_128(w[35], k[35]);
    DO_128(w[36], k[36]);
    DO_128(w[37], k[37]);
    DO_128(w[38], k[38]);
    DO_128(w[39], k[39]);
    DO_128(w[40], k[40]);
    DO_128(w[41], k[41]);
    DO_128(w[42], k[42]);
    DO_128(w[43], k[43]);
    DO_128(w[44], k[44]);
    DO_128(w[45], k[45]);
    DO_128(w[46], k[46]);
    DO_128(w[47], k[47]);
    //
    DO_128(w[48], k[48]);
    DO_128(w[49], k[49]);
    DO_128(w[50], k[50]);
    DO_128(w[51], k[51]);
    DO_128(w[52], k[52]);
    DO_128(w[53], k[53]);
    DO_128(w[54], k[54]);
    DO_128(w[55], k[55]);
    DO_128(w[56], k[56]);
    DO_128(w[57], k[57]);
    DO_128(w[58], k[58]);
    DO_128(w[59], k[59]);
    DO_128(w[60], k[60]);
    DO_128(w[61], k[61]);
    DO_128(w[62], k[62]);
    DO_128(w[63], k[63]);


    state[0] = _mm_add_epi32(state[0], a);
    state[1] = _mm_add_epi32(state[1], b);
    state[2] = _mm_add_epi32(state[2], c);
    state[3] = _mm_add_epi32(state[3], d);
    state[4] = _mm_add_epi32(state[4], e);
    state[5] = _mm_add_epi32(state[5], f);
    state[6] = _mm_add_epi32(state[6], g);
    state[7] = _mm_add_epi32(state[7], h);

}

void AVX_sha256_calc_w8(__m256i* w)
{
    for (uint32_t t = 16; t < 64; t += 16)
    {


        
        w[t] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 16], s0_256(w[t - 15])),
            _mm256_add_epi32(w[t - 7], s1_256(w[t - 2])));

        
        w[t + 1] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 15], s0_256(w[t - 14])),
            _mm256_add_epi32(w[t - 6], s1_256(w[t - 1])));

        
        w[t + 2] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 14], s0_256(w[t - 13])),
            _mm256_add_epi32(w[t - 5], s1_256(w[t])));

        
        w[t + 3] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 13], s0_256(w[t - 12])),
            _mm256_add_epi32(w[t - 4], s1_256(w[t + 1])));

        
        w[t + 4] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 12], s0_256(w[t - 11])),
            _mm256_add_epi32(w[t - 3], s1_256(w[t + 2])));

        
        w[t + 5] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 11], s0_256(w[t - 10])),
            _mm256_add_epi32(w[t - 2], s1_256(w[t + 3])));

        
        w[t + 6] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 10], s0_256(w[t - 9])),
            _mm256_add_epi32(w[t - 1], s1_256(w[t + 4])));

        
        w[t + 7] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 9], s0_256(w[t - 8])),
            _mm256_add_epi32(w[t - 0], s1_256(w[t + 5])));

        
        w[t + 8] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 8], s0_256(w[t - 7])),
            _mm256_add_epi32(w[t + 1], s1_256(w[t + 6])));

        
        w[t + 9] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 7], s0_256(w[t - 6])),
            _mm256_add_epi32(w[t + 2], s1_256(w[t + 7])));

        
        w[t + 10] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 6], s0_256(w[t - 5])),
            _mm256_add_epi32(w[t + 3], s1_256(w[t + 8])));

        
        w[t + 11] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 5], s0_256(w[t - 4])),
            _mm256_add_epi32(w[t + 4], s1_256(w[t + 9])));

        
        w[t + 12] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 4], s0_256(w[t - 3])),
            _mm256_add_epi32(w[t + 5], s1_256(w[t + 10])));

        
        w[t + 13] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 3], s0_256(w[t - 2])),
            _mm256_add_epi32(w[t + 6], s1_256(w[t + 11])));

        
        w[t + 14] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 2], s0_256(w[t - 1])),
            _mm256_add_epi32(w[t + 7], s1_256(w[t + 12])));

        
        w[t + 15] = _mm256_add_epi32(
            _mm256_add_epi32(w[t - 1], s0_256(w[t])),
            _mm256_add_epi32(w[t + 8], s1_256(w[t + 13])));

    }
}

void AVX_sha256_calc_state8(__m256i state[8], const __m256i* w)
{
    __m256i a = state[0];

    __m256i b = state[1];

    __m256i c = state[2];

    __m256i d = state[3];

    __m256i e = state[4];

    __m256i f = state[5];

    __m256i g = state[6];

    __m256i h = state[7];

    __m256i temp1, temp2;
    DO_256(w[0], k[0]);
    DO_256(w[1], k[1]);
    DO_256(w[2], k[2]);
    DO_256(w[3], k[3]);
    DO_256(w[4], k[4]);
    DO_256(w[5], k[5]);
    DO_256(w[6], k[6]);
    DO_256(w[7], k[7]);
    DO_256(w[8], k[8]);
    DO_256(w[9], k[9]);
    DO_256(w[10], k[10]);
    DO_256(w[11], k[11]);
    DO_256(w[12], k[12]);
    DO_256(w[13], k[13]);
    DO_256(w[14], k[14]);
    DO_256(w[15], k[15]);
    //
    DO_256(w[16], k[16]);
    DO_256(w[17], k[17]);
    DO_256(w[18], k[18]);
    DO_256(w[19], k[19]);
    DO_256(w[20], k[20]);
    DO_256(w[21], k[21]);
    DO_256(w[22], k[22]);
    DO_256(w[23], k[23]);
    DO_256(w[24], k[24]);
    DO_256(w[25], k[25]);
    DO_256(w[26], k[26]);
    DO_256(w[27], k[27]);
    DO_256(w[28], k[28]);
    DO_256(w[29], k[29]);
    DO_256(w[30], k[30]);
    DO_256(w[31], k[31]);
    //
    DO_256(w[32], k[32]);
    DO_256(w[33], k[33]);
    DO_256(w[34], k[34]);
    DO_256(w[35], k[35]);
    DO_256(w[36], k[36]);
    DO_256(w[37], k[37]);
    DO_256(w[38], k[38]);
    DO_256(w[39], k[39]);
    DO_256(w[40], k[40]);
    DO_256(w[41], k[41]);
    DO_256(w[42], k[42]);
    DO_256(w[43], k[43]);
    DO_256(w[44], k[44]);
    DO_256(w[45], k[45]);
    DO_256(w[46], k[46]);
    DO_256(w[47], k[47]);
    //
    DO_256(w[48], k[48]);
    DO_256(w[49], k[49]);
    DO_256(w[50], k[50]);
    DO_256(w[51], k[51]);
    DO_256(w[52], k[52]);
    DO_256(w[53], k[53]);
    DO_256(w[54], k[54]);
    DO_256(w[55], k[55]);
    DO_256(w[56], k[56]);
    DO_256(w[57], k[57]);
    DO_256(w[58], k[58]);
    DO_256(w[59], k[59]);
    DO_256(w[60], k[60]);
    DO_256(w[61], k[61]);
    DO_256(w[62], k[62]);
    DO_256(w[63], k[63]);


    state[0] = _mm256_add_epi32(state[0], a);
    state[1] = _mm256_add_epi32(state[1], b);
    state[2] = _mm256_add_epi32(state[2], c);
    state[3] = _mm256_add_epi32(state[3], d);
    state[4] = _mm256_add_epi32(state[4], e);
    state[5] = _mm256_add_epi32(state[5], f);
    state[6] = _mm256_add_epi32(state[6], g);
    state[7] = _mm256_add_epi32(state[7], h);

}

void AVX_sha256_compress8(__m256i state[8], __m256i *w)
{
    //int t;
    AVX_sha256_calc_w8(w);
    AVX_sha256_calc_state8(state, w);
}

void blocks_sha256(uint32_t* state, uint8_t* in);

void AVX_sha256(uint8_t* out, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
    ALIGN64 uint32_t state[8];
       
    uint32_t bits = in_len * 8;
    memcpy(state, HInit, sizeof(HInit));
    __m256i in256[8];
    
    while (in_len >= 64)
    {
        in256[0] = _mm256_lddqu_si256((__m256i*)in);
        in256[1] = _mm256_lddqu_si256((__m256i*)(in + 32));
        in256[0] = _mm256_shuffle_epi8(in256[0], maska_for_shuffle_32);
        in256[1] = _mm256_shuffle_epi8(in256[1], maska_for_shuffle_32);
        AVX_sha256_compress(state, in256);
        in += 64;
        in_len -= 64;
    }
    
    ALIGN64 uint8_t temp[128];
    __m256i* temp256 = (__m256i*)temp;

    memcpy(temp, in, in_len);
    temp[in_len++] = 0x80;
    uint32_t end_pos = in_len > 56 ? 128 : 64;
    
    memset(temp + in_len, 0, end_pos - 8 - in_len);
        
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    
    //temp256[0] = _mm256_shuffle_epi8(temp256[0], maska);
    in256[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_32);
    //temp256[1] = _mm256_shuffle_epi8(temp256[1], maska);
    in256[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_32);
    
    AVX_sha256_compress(state, in256);
    if (end_pos > 64)
    {
        in256[0] = _mm256_shuffle_epi8(temp256[2], maska_for_shuffle_32);
        in256[1] = _mm256_shuffle_epi8(temp256[3], maska_for_shuffle_32);
        AVX_sha256_compress(state, in256);
    }
    /*const __m256i maska = _mm256_setr_epi32(0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
        0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F);*/
    
    __m256i *state_256 = (__m256i*) state;
    state_256[0] = _mm256_shuffle_epi8(state_256[0], maska_for_shuffle_32);
    memcpy(out, state, out_len);

    
}


void AVX_sha256_predcalc_pk(uint32_t* state, const uint8_t* in)
{
    memcpy(state, HInit, sizeof(HInit));
    ALIGN64 uint8_t temp[64 * 4];
    memcpy(temp, in, FIPS205_N);
    memset(temp + FIPS205_N, 0, 64 - FIPS205_N);
    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
    __m256i *temp256 = (__m256i*)temp;
    temp256[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_32);
    temp256[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_32);
    AVX_sha256_compress(state, temp256);
}

void AVX_sha256_predcalc_pk_(__m256i state256[8], const uint8_t* in)
{
    uint32_t state[8];
    memcpy(state, HInit, sizeof(HInit));
    ALIGN64 uint8_t temp[64 * 4];
    memcpy(temp, in, FIPS205_N);
    memset(temp + FIPS205_N, 0, 64 - FIPS205_N);
    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
    __m256i* temp256 = (__m256i*)temp;
    temp256[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_32);
    temp256[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_32);
    AVX_sha256_compress(state, temp256);
    state256[0] = _mm256_set1_epi32(state[0]);
    state256[1] = _mm256_set1_epi32(state[1]);
    state256[2] = _mm256_set1_epi32(state[2]);
    state256[3] = _mm256_set1_epi32(state[3]);
    state256[4] = _mm256_set1_epi32(state[4]);
    state256[5] = _mm256_set1_epi32(state[5]);
    state256[6] = _mm256_set1_epi32(state[6]);
    state256[7] = _mm256_set1_epi32(state[7]);
}


// for few block
void AVX_PREDCALC_sha256(uint8_t* out, const uint32_t *pk, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
    ALIGN64 uint32_t state[8];

    uint32_t bits = (in_len + 64) * 8;
    memcpy(state, pk, sizeof(state));
    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
    __m256i in256[8];
    //in256 [0] = _mm256_shuffle_epi8(in, maska);
    while (in_len >= 64)
    {
        in256[0] = _mm256_lddqu_si256((__m256i*)in);
        in256[1] = _mm256_lddqu_si256((__m256i*)(in + 32));
        in256[0] = _mm256_shuffle_epi8(in256[0], maska_for_shuffle_32);
        in256[1] = _mm256_shuffle_epi8(in256[1], maska_for_shuffle_32);
        AVX_sha256_compress(state, in256);
        in += 64;
        in_len -= 64;
    }

    ALIGN64 uint8_t temp[128];
    __m256i* temp256 = (__m256i*)temp;

    memcpy(temp, in, in_len);
    temp[in_len++] = 0x80;
    uint32_t end_pos = in_len > 56 ? 128 : 64;

    memset(temp + in_len, 0, end_pos - 8 - in_len);

    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;

    in256[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_32);
    in256[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_32);

    AVX_sha256_compress(state, in256);
    if (end_pos > 64)
    {
        in256[0] = _mm256_shuffle_epi8(temp256[2], maska_for_shuffle_32);
        in256[1] = _mm256_shuffle_epi8(temp256[3], maska_for_shuffle_32);
        AVX_sha256_compress(state, in256);
    }
    /*const __m256i maska = _mm256_setr_epi32(0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
        0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F);*/

    __m256i* state_256 = (__m256i*) state;
    state_256[0] = _mm256_shuffle_epi8(state_256[0], maska_for_shuffle_32);
    memcpy(out, state, out_len);


}

static void toConvert32(__m128i dest_ [16], uint32_t src [16 * 4], __m128i idx, uint32_t size)
{
    
    //__m128i idx = _mm_setr_epi32(0, 16, 32, 48);
    __m128i _1_128 = _mm_set1_epi32(1);
    //__m128i maska = _mm_load_si128((const __m128i*)u8_maska), temp;
    for (uint32_t i = 0; i < size; ++i)
    {
        dest_ [i] = /*_mm_shuffle_epi8(*/_mm_i32gather_epi32(src, idx, 4)/*, maska)*/;
        idx = _mm_add_epi32(idx, _1_128);
        
    }
  
}

uint32_t swap32(uint32_t value)
{
    uint32_t res = value  ;
    uint8_t* beg = (uint8_t*)&res;
    uint8_t* end = beg + 3;
    uint8_t r = *beg;
    *beg = *end;
    *end = r;
    r = *(beg + 1);
    *(beg + 1) = *(end - 1);
    *(end - 1) = r;
    return res;
    
}

// hash, state - align (32)
// one block;
void AVX_sha256_WITH_PREDCALC1(uint8_t* hash, const uint32_t *state, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
    ALIGN64 uint8_t temp[64];
    
    uint32_t bits = (in_len + 64) * 8;
    memcpy(temp, in, in_len);
    temp[in_len++] = 0x80;
    uint32_t end_pos = 64;
    __m256i in256[8];
    memset(temp + in_len, 0, end_pos - 8 - in_len);

    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;

    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
    __m256i* temp256 = (__m256i*)temp;
    in256[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_32);
    in256[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_32);

    uint32_t cur_state[8];
    memcpy(cur_state, state, sizeof(cur_state));
    AVX_sha256_compress(cur_state, in256);
    
    /*const __m256i maska = _mm256_setr_epi32(0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
        0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F);*/

    //__m256i* temp256 = (__m256i*)temp;
    __m256i* state_256 = (__m256i*) cur_state;
    temp256[0] = _mm256_shuffle_epi8(state_256[0], maska_for_shuffle_32);
    memcpy(hash, temp, out_len);

}

void AVX_MGF1_sha256(uint8_t* out, uint32_t outlen,
    const uint8_t* in, uint32_t inlen)
{
    uint8_t* inbuf = (uint8_t*)malloc(inlen + 4);
    uint8_t outbuf[32];
    unsigned i;

    memcpy(inbuf, in, inlen);
    
    /* While we can fit in at least another full block of SHA256 output.. */
    uint32_t blocks = outlen / 32;
    uint8_t* pend = inbuf + inlen;
    for (i = 0; i < blocks; i++) {
        toByte32_(pend, i);
        AVX_sha256 (out, inbuf, inlen + 4, 32);
        out += 32;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > blocks * 32) {
        toByte32_(pend, i);
        AVX_sha256(outbuf, inbuf, inlen + 4, 32);
        memcpy(out, outbuf, outlen - i * 32);
    }
    free(inbuf);
}

void AVX_HMAC256(uint8_t* dest, const  uint8_t* sk, uint32_t sk_len, const uint8_t* src, uint32_t len)
{

#define	BLOCKSIZE	64

    uint32_t i;
    uint8_t buf[BLOCKSIZE + BLOCKSIZE / 2]; // oKey
    uint8_t* temp = malloc(BLOCKSIZE + len);    //      ikey
    if (temp)
    {
    
        
        memset(temp, 0x36, BLOCKSIZE);
        
        for (i = 0; i < sk_len; ++i)
        {
            temp[i] ^= sk[i];
        }

        for (i = 0; i < len; i++)
            temp[BLOCKSIZE + i] = src[i];

        
        memset(buf, 0x5C, BLOCKSIZE);
        for (i = 0; i < 16; ++i)
        {
            buf[i] ^= sk[i] ;
        }


//#if FIPS205_N == 16
        AVX_sha256(buf + BLOCKSIZE, temp, BLOCKSIZE + len, 32);


//#if FIPS205_N == 16
        AVX_sha256 (dest, buf, BLOCKSIZE + BLOCKSIZE / 2, sk_len);
//#else
//        AVX_SHA512 (dest, buf, BLOCKSIZE + BLOCKSIZE / 2, FIPS205_N);
//#endif

        //for (i = 0; i < FIPS205_N; ++i)
        //{
        //    dest[i] = temp[i];
        //}
        free(temp);

    }


}

void AVX_sha256_WITH_PREDCALC8(uint8_t hash[8][FIPS205_N], const uint32_t state[8], const uint8_t in[8][FIPS205_N + ADR_SIZE])
{
    ALIGN64 uint8_t temp[8 * 64];
    uint32_t* temp32 = (uint32_t*)temp;
    __m256i *temp256  = (__m256i*)temp;

#if FIPS205_N == 16
    const __m256i __msk_256 = _mm256_setr_epi16(
        0xFFFF, 0xFFFF, 0xFFFF,
        0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0, 0, 0
    );
    const __m256i const_data = _mm256_setr_epi8(
        0, 0, 0, 0, 0, 0,              // 22 + 16 - 32 = 6 
        0x80,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // 23
        0x03, 0x30                                                              // 2                                 
    );
#elif FIPS205_N == 24
    const __m256i __msk_256 = _mm256_setr_epi16(
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        0, 0, 0, 0, 0, 0, 0, 0, 0 
    );
    const __m256i const_data = _mm256_setr_epi8(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 22 + 24 - 32 = 14 
        0x80,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,           // 15
        0x03, 0x70                                             // 2                                 
    );
#else
    const __m256i __msk_256 = _mm256_setr_epi16(
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        0, 0, 0, 0, 0
    );
    const __m256i const_data = _mm256_setr_epi8(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 22 + 32 - 32 = 22 
        0, 0, 0, 0, 0, 0, 0, 0,
        0x80,
        0, 0, 0, 0, 0, 0, 0,                                   // 7
        0x03, 0xB0                                             // 2                                 
    );
#endif

    memcpy(temp, in[0], FIPS205_N + ADR_SIZE);
    memcpy(temp + 64, in[1], FIPS205_N + ADR_SIZE);
    memcpy(temp + 128, in[2], FIPS205_N + ADR_SIZE);
    memcpy(temp + 192, in[3], FIPS205_N + ADR_SIZE);
    memcpy(temp + 256, in[4], FIPS205_N + ADR_SIZE);
    memcpy(temp + 320, in[5], FIPS205_N + ADR_SIZE);
    memcpy(temp + 384, in[6], FIPS205_N + ADR_SIZE);
    memcpy(temp + 448, in[7], FIPS205_N + ADR_SIZE);

    temp256[1] = _mm256_add_epi8(
        _mm256_and_si256(temp256[1], __msk_256), const_data);
    temp256[3] = _mm256_add_epi8(
        _mm256_and_si256(temp256[3], __msk_256), const_data);
    temp256[5] = _mm256_add_epi8(
        _mm256_and_si256(temp256[5], __msk_256), const_data);
    temp256[7] = _mm256_add_epi8(
        _mm256_and_si256(temp256[7], __msk_256), const_data);
    temp256[9] = _mm256_add_epi8(
        _mm256_and_si256(temp256[9], __msk_256), const_data);
    temp256[11] = _mm256_add_epi8(
        _mm256_and_si256(temp256[11], __msk_256), const_data);
    temp256[13] = _mm256_add_epi8(
        _mm256_and_si256(temp256[13], __msk_256), const_data);
    temp256[15] = _mm256_add_epi8(
        _mm256_and_si256(temp256[15], __msk_256), const_data);

#if 1
    temp256[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_32);
    temp256[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_32);
    temp256[2] = _mm256_shuffle_epi8(temp256[2], maska_for_shuffle_32);
    temp256[3] = _mm256_shuffle_epi8(temp256[3], maska_for_shuffle_32);
    temp256[4] = _mm256_shuffle_epi8(temp256[4], maska_for_shuffle_32);
    temp256[5] = _mm256_shuffle_epi8(temp256[5], maska_for_shuffle_32);
    temp256[6] = _mm256_shuffle_epi8(temp256[6], maska_for_shuffle_32);
    temp256[7] = _mm256_shuffle_epi8(temp256[7], maska_for_shuffle_32);
    temp256[8] = _mm256_shuffle_epi8(temp256[8], maska_for_shuffle_32);
    temp256[9] = _mm256_shuffle_epi8(temp256[9], maska_for_shuffle_32);
    temp256[10] = _mm256_shuffle_epi8(temp256[10], maska_for_shuffle_32);
    temp256[11] = _mm256_shuffle_epi8(temp256[11], maska_for_shuffle_32);
    temp256[12] = _mm256_shuffle_epi8(temp256[12], maska_for_shuffle_32);
    temp256[13] = _mm256_shuffle_epi8(temp256[13], maska_for_shuffle_32);
    temp256[14] = _mm256_shuffle_epi8(temp256[14], maska_for_shuffle_32);
    temp256[15] = _mm256_shuffle_epi8(temp256[15], maska_for_shuffle_32);

#endif
    __m256i temp_[64];
    const __m256i idx = idx16; //_mm256_setr_epi32(0, 16, 32, 48, 64, 80, 96, 112);
    //__m256i _1_256 = _mm256_set1_epi32(1);

    temp_[0] = _mm256_i32gather_epi32((const int*)temp, idx, 4);
    temp_[1] = _mm256_i32gather_epi32((const int*)temp + 1, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[2] = _mm256_i32gather_epi32((const int*)temp + 2, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[3] = _mm256_i32gather_epi32((const int*)temp + 3, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[4] = _mm256_i32gather_epi32((const int*)temp + 4, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[5] = _mm256_i32gather_epi32((const int*)temp + 5, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[6] = _mm256_i32gather_epi32((const int*)temp + 6, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[7] = _mm256_i32gather_epi32((const int*)temp + 7, idx, 4);

    temp_[8] = _mm256_i32gather_epi32((const int*)temp + 8, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[9] = _mm256_i32gather_epi32((const int*)temp + 9, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[10] = _mm256_i32gather_epi32((const int*)temp + 10, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[11] = _mm256_i32gather_epi32((const int*)temp + 11, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[12] = _mm256_i32gather_epi32((const int*)temp + 12, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[13] = _mm256_i32gather_epi32((const int*)temp + 13, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[14] = _mm256_i32gather_epi32((const int*)temp + 14, idx, 4);
    //idx = _mm256_add_epi32(idx, _1_256);
    temp_[15] = _mm256_i32gather_epi32((const int*)temp + 15, idx, 4);

    __m256i state256[8];
    
    state256[0] = _mm256_set1_epi32(state[0]);
    state256[1] = _mm256_set1_epi32(state[1]);
    state256[2] = _mm256_set1_epi32(state[2]);
    state256[3] = _mm256_set1_epi32(state[3]);
    state256[4] = _mm256_set1_epi32(state[4]);
    state256[5] = _mm256_set1_epi32(state[5]);
    state256[6] = _mm256_set1_epi32(state[6]);
    state256[7] = _mm256_set1_epi32(state[7]);
    //int32_t* state = (int32_t*)state256;
    AVX_sha256_compress8(state256, temp_);

    //const __m256i idx8 = _mm256_setr_epi32(0, 8, 16, 24, 32, 40, 48, 56);

    //__m128i step4 = _mm_set1_epi32(16);
    //__m256i step1 = _mm256_set1_epi32(1);
#if FIPS205_N == 32 
    _mm256_store_si256 ((__m256i*)hash[0], 
        _mm256_shuffle_epi8(
            _mm256_i32gather_epi32((int const*)state256, idx8, 4), 
            maska_for_shuffle_32));
    //idx8 = _mm256_add_epi32(idx8, step1);
    _mm256_store_si256 ((__m256i*)hash[1], _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 1, idx8, 4), maska_for_shuffle_32));
    //idx8 = _mm256_add_epi32(idx8, step1);
    _mm256_store_si256((__m256i*)hash[2], _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 2, idx8, 4), maska_for_shuffle_32));
    //idx8 = _mm256_add_epi32(idx8, step1);
    _mm256_store_si256((__m256i*)hash[3], _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 3, idx8, 4), maska_for_shuffle_32));
    //idx8 = _mm256_add_epi32(idx8, step1);

    _mm256_store_si256((__m256i*)hash[4], _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 4, idx8, 4), maska_for_shuffle_32));
    //idx8 = _mm256_add_epi32(idx8, step1);
    _mm256_store_si256((__m256i*)hash[5], _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 5, idx8, 4), maska_for_shuffle_32));
    //idx8 = _mm256_add_epi32(idx8, step1);
    _mm256_store_si256((__m256i*)hash[6], _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 6, idx8, 4), maska_for_shuffle_32));
    //idx8 = _mm256_add_epi32(idx8, step1);
    _mm256_store_si256((__m256i*)hash[7], _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 7, idx8, 4), maska_for_shuffle_32));
#else
    temp_[0] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256, idx8, 4), maska_for_shuffle_32);
    //idx8 = _mm256_add_epi32(idx8, step1);
    temp_[1] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 1, idx8, 4), maska_for_shuffle_32);
    //idx8 = _mm256_add_epi32(idx8, step1);
    temp_[2] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 2, idx8, 4), maska_for_shuffle_32);
    //idx8 = _mm256_add_epi32(idx8, step1);
    temp_[3] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 3, idx8, 4), maska_for_shuffle_32);
    //idx8 = _mm256_add_epi32(idx8, step1);

    temp_[4] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 4, idx8, 4), maska_for_shuffle_32);
    //idx8 = _mm256_add_epi32(idx8, step1);
    temp_[5] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 5, idx8, 4), maska_for_shuffle_32);
    //idx8 = _mm256_add_epi32(idx8, step1);
    temp_[6] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 6, idx8, 4), maska_for_shuffle_32);
    //idx8 = _mm256_add_epi32(idx8, step1);
    temp_[7] = _mm256_shuffle_epi8(_mm256_i32gather_epi32((int const*)state256 + 7, idx8, 4), maska_for_shuffle_32);

    memcpy(hash[0], temp_, FIPS205_N);
    memcpy(hash[1], temp_ + 1, FIPS205_N);
    memcpy(hash[2], temp_ + 2, FIPS205_N);
    memcpy(hash[3], temp_ + 3, FIPS205_N);
    memcpy(hash[4], temp_ + 4, FIPS205_N);
    memcpy(hash[5], temp_ + 5, FIPS205_N);
    memcpy(hash[6], temp_ + 6, FIPS205_N);
    memcpy(hash[7], temp_ + 7, FIPS205_N);
#endif

}


void AVX_sha256_one_block(uint8_t* out, uint32_t* predcalc, uint8_t* in, size_t inlen, size_t out_len)
{
    ALIGN64 uint32_t state[8];

    __m256i in256[8];
    uint8_t* pin = (uint8_t*)in256;
        
    
    size_t bits = (64 + inlen) * 8;

    memcpy(pin, in, inlen);
          
    pin[inlen] = 0x80;

    //for (i = inlen + 1; i < 61; ++i) pin[i] = 0;
    memset(pin + inlen + 1, 0, 61 - inlen);
            
    pin[61] = (uint8_t)(bits >> 16);
    pin[62] = (uint8_t)(bits >> 8);
    pin[63] = (uint8_t)bits;
        
    in256[0] = _mm256_shuffle_epi8(in256[0], maska_for_shuffle_32);
    in256[1] = _mm256_shuffle_epi8(in256[1], maska_for_shuffle_32);
    memcpy(state, predcalc, sizeof(state));
        
    AVX_sha256_compress(state, in256);
    
    __m256i* state_256 = (__m256i*) state;
    state_256[0] = _mm256_shuffle_epi8(state_256[0], maska_for_shuffle_32);
    memcpy(out, state, out_len);
}
