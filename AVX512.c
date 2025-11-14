#include <malloc.h>

#include "AVXconst.h"
#include "AVX512.h"
#include "SHA512_defined.h"
#include "SHA512.h"
#include "Common.h"

#if _WIN32
#else
    typedef long long __int64;
#endif

#ifndef _DEBUG
static uint64_t tacts, min_tacts;
#endif

#if defined(_MSC_VER)
#  define ALIGN128 __declspec(align(128))
#else
#  define ALIGN128 __attribute__((aligned(128)))
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

ALIGN64 static uint64_t HInit[8] =
{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
           0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};


ALIGN64 static const uint64_t k[] =
{
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
            0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 
            0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 
            0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 
            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 
            0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 
            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 
            0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 
            0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 
            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 
            0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 
            0x5fcb6fab3ad6faec, 0x6c44198c4a475817, 
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

#define DO_256(w) \
    temp1 = \
_mm256_add_epi64 (                              \
            _mm256_add_epi64 (h, S1_256(e)),            \
            _mm256_add_epi64 (ch_256(e, f, g) ,  w));   \
    temp2 = _mm256_add_epi64 (S0_256(a), maj_256(a, b, c)); \
    h = g;  \
    g = f;  \
    f = e;  \
    e = _mm256_add_epi64(d, temp1);\
    d = c;\
    c = b;\
    b = a;\
    a = _mm256_add_epi64(temp1 , temp2)


void do_fun_512(uint64_t* a_, uint64_t* b_, uint64_t* c_, uint64_t* d_,
    uint64_t* e_, uint64_t* f_, uint64_t* g_, uint64_t* h_,
    uint64_t w)
{
    uint64_t a = *a_, b = *b_, c = *c_, d = *d_;
    uint64_t e = *e_, f = *f_, g = *g_, h = *h_;
    uint64_t temp1 = h + S1(e) + ch(e, f, g) + w;
    uint64_t temp2 = S0(a) + maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
    *a_ = a; *b_ = b; *c_ = c; *d_ = d;
    *e_ = e; *f_ = f; *g_ = g; *h_ = h;
}


void AVX_sha512_compress(uint64_t* state, __m256i*w_)
{
    int t;
    //__declspec (align(64)) uint64_t w[80];

    uint64_t* w = (uint64_t*)w_;
    //memcpy(w, block256, 16 * 8);

    for (t = 16; t < 80; t += 16)
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

    __m256i* w256 = (__m256i*)w;

    const __m256i* k256 = (const __m256i*)k;
    w256[0] = _mm256_add_epi64(k256[0], w256[0]);
    w256[1] = _mm256_add_epi64(k256[1], w256[1]);
    w256[2] = _mm256_add_epi64(k256[2], w256[2]);
    w256[3] = _mm256_add_epi64(k256[3], w256[3]);
    w256[4] = _mm256_add_epi64(k256[4], w256[4]);
    w256[5] = _mm256_add_epi64(k256[5], w256[5]);
    w256[6] = _mm256_add_epi64(k256[6], w256[6]);
    w256[7] = _mm256_add_epi64(k256[7], w256[7]);

    w256[8] = _mm256_add_epi64(k256[8], w256[8]);
    w256[9] = _mm256_add_epi64(k256[9], w256[9]);
    w256[10] = _mm256_add_epi64(k256[10], w256[10]);
    w256[11] = _mm256_add_epi64(k256[11], w256[11]);
    w256[12] = _mm256_add_epi64(k256[12], w256[12]);
    w256[13] = _mm256_add_epi64(k256[13], w256[13]);
    w256[14] = _mm256_add_epi64(k256[14], w256[14]);
    w256[15] = _mm256_add_epi64(k256[15], w256[15]);

    w256[16] = _mm256_add_epi64(k256[16], w256[16]);
    w256[17] = _mm256_add_epi64(k256[17], w256[17]);
    w256[18] = _mm256_add_epi64(k256[18], w256[18]);
    w256[19] = _mm256_add_epi64(k256[19], w256[19]);
    


    // Initialize working variables

    uint64_t a = state[0];    //    a[0]5
    uint64_t b = state[1];    //    a[1]
    uint64_t c = state[2];    //    a[2]
    uint64_t d = state[3];    //    a[3]
    uint64_t e = state[4];    //    a[4]
    uint64_t f = state[5];    //    a[5]
    uint64_t g = state[6];    //    a[6]
    uint64_t h = state[7];    //    a[7]



    uint64_t temp1, temp2;
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

    DO(w[64]);
    DO(w[65]);
    DO(w[66]);
    DO(w[67]);
    DO(w[68]);
    DO(w[69]);
    DO(w[70]);
    DO(w[71]);
    DO(w[72]);
    DO(w[73]);
    DO(w[74]);
    DO(w[75]);
    DO(w[76]);
    DO(w[77]);
    DO(w[78]);
    DO(w[79]);



    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}



void AVX_sha512(uint8_t* out, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
    ALIGN64 uint64_t state[8];

    //uint8_t h[64];
    uint8_t padded[256];
    unsigned int i;
    uint64_t bytes = in_len;
    uint32_t bits = in_len * 8;

    memcpy(state, HInit, sizeof(HInit));
    

    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    //__m256i in256[4];
    __m256i w[20];
   
    while (in_len >= 128)
    {
#if 0
        in256[0] = _mm256_lddqu_si256((__m256i*)in);
        in256[1] = _mm256_lddqu_si256((__m256i*)(in + 32));
        in256[2] = _mm256_lddqu_si256((__m256i*)(in + 64));
        in256[3] = _mm256_lddqu_si256((__m256i*)(in + 96));

        in256[0] = _mm256_shuffle_epi8(in256[0], maska);
        in256[1] = _mm256_shuffle_epi8(in256[1], maska);
        in256[2] = _mm256_shuffle_epi8(in256[2], maska);
        in256[3] = _mm256_shuffle_epi8(in256[3], maska);
#else
        w[0] = _mm256_lddqu_si256((__m256i*)in);
        w[1] = _mm256_lddqu_si256((__m256i*)(in + 32));
        w[2] = _mm256_lddqu_si256((__m256i*)(in + 64));
        w[3] = _mm256_lddqu_si256((__m256i*)(in + 96));

        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);

#endif
        //AVX_sha512_compress(state, in256);
        AVX_sha512_compress(state, w);
        in += 128;
        in_len -= 128;
    }

    //uint8_t *padded = (uint8_t*)w;
    for (i = 0; i < in_len; ++i) padded[i] = in[i];
    padded[in_len] = 0x80;
    //__m256i *temp256 = (__m256i*)padded;
    if (in_len < 112) {
        for (i = in_len + 1; i < 119; ++i) padded[i] = 0;
        padded[119] = (uint8_t)(bytes >> 61);
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        //blocks(h, padded, 128);

        
#if 0
        temp256[0] = _mm256_shuffle_epi8(temp256[0], maska);
        temp256[1] = _mm256_shuffle_epi8(temp256[1], maska);
        temp256[2] = _mm256_shuffle_epi8(temp256[2], maska);
        temp256[3] = _mm256_shuffle_epi8(temp256[3], maska);
        AVX_sha512_compress(state, temp256);
#else
        memcpy(w, padded, 128);
        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);
        AVX_sha512_compress(state, w);
#endif
        
        
    }
    else {
        for (i = in_len + 1; i < 247; ++i) padded[i] = 0;
        padded[247] = (uint8_t)(bytes >> 61);
        padded[248] = (uint8_t)(bytes >> 53);
        padded[249] = (uint8_t)(bytes >> 45);
        padded[250] = (uint8_t)(bytes >> 37);
        padded[251] = (uint8_t)(bytes >> 29);
        padded[252] = (uint8_t)(bytes >> 21);
        padded[253] = (uint8_t)(bytes >> 13);
        padded[254] = (uint8_t)(bytes >> 5);
        padded[255] = (uint8_t)(bytes << 3);
        //blocks(h, padded, 256);
        //memcpy(w, padded , 128);
#if 0
        temp256[0] = _mm256_shuffle_epi8(temp256[0], maska);
        temp256[1] = _mm256_shuffle_epi8(temp256[1], maska);
        temp256[2] = _mm256_shuffle_epi8(temp256[2], maska);
        temp256[3] = _mm256_shuffle_epi8(temp256[3], maska);

        AVX_sha512_compress(state, temp256);
        temp256 = temp256 + 4;
        temp256[0] = _mm256_shuffle_epi8(temp256[0], maska);
        temp256[1] = _mm256_shuffle_epi8(temp256[1], maska);
        temp256[2] = _mm256_shuffle_epi8(temp256[2], maska);
        temp256[3] = _mm256_shuffle_epi8(temp256[3], maska);
        AVX_sha512_compress(state, temp256);

#else
        memcpy(w, padded , 128);
        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);

        AVX_sha512_compress(state, w);
        memcpy(w, padded + 128, 128);
        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);
        AVX_sha512_compress(state, w);

#endif
        
    }

    __m256i*state256 = (__m256i*) state;
#if 0
    temp256 = (__m256i*) state;
    temp256[0] = _mm256_shuffle_epi8(temp256[0], maska);
    temp256[1] = _mm256_shuffle_epi8(temp256[1], maska);
#else
    state256[0] = _mm256_shuffle_epi8(state256[0], maska_for_shuffle_64);
    state256[1] = _mm256_shuffle_epi8(state256[1], maska_for_shuffle_64);
#endif
    memcpy(out, state, out_len);
    
}

void AVX_PREDCALC_sha512(uint8_t* out, const uint64_t *pk, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
    ALIGN64 uint64_t state[8];
    

    __m256i w[20];
    uint8_t padded[256];
    unsigned int i;
    uint64_t bytes = (in_len + 128);
    //uint32_t bits = in_len + (FIPS205_N) * 8;

    memcpy(state, pk, sizeof(state));


    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    //__m256i in256[4];

    while (in_len >= 128)
    {
#if 0  
        in256[0] = _mm256_lddqu_si256((__m256i*)in);
        in256[1] = _mm256_lddqu_si256((__m256i*)(in + 32));
        in256[2] = _mm256_lddqu_si256((__m256i*)(in + 64));
        in256[3] = _mm256_lddqu_si256((__m256i*)(in + 96));

        in256[0] = _mm256_shuffle_epi8(in256[0], maska);
        in256[1] = _mm256_shuffle_epi8(in256[1], maska);
        in256[2] = _mm256_shuffle_epi8(in256[2], maska);
        in256[3] = _mm256_shuffle_epi8(in256[3], maska);
        AVX_sha512_compress(state, in256);
#else
        w[0] = _mm256_lddqu_si256((__m256i*)in);
        w[1] = _mm256_lddqu_si256((__m256i*)(in + 32));
        w[2] = _mm256_lddqu_si256((__m256i*)(in + 64));
        w[3] = _mm256_lddqu_si256((__m256i*)(in + 96));

        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);
        AVX_sha512_compress(state, w);
#endif
        
        in += 128;
        in_len -= 128;
    }


    for (i = 0; i < in_len; ++i) padded[i] = in[i];
    padded[in_len] = 0x80;
    //__m256i* temp256 = (__m256i*)padded;
    if (in_len < 112) {
        for (i = in_len + 1; i < 119; ++i) padded[i] = 0;
        padded[119] = (uint8_t)(bytes >> 61);
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        //blocks(h, padded, 128);
        memcpy(w, padded, 128);
        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);

        AVX_sha512_compress(state, w);

    }
    else {
        for (i = in_len + 1; i < 247; ++i) padded[i] = 0;
        padded[247] = (uint8_t)(bytes >> 61);
        padded[248] = (uint8_t)(bytes >> 53);
        padded[249] = (uint8_t)(bytes >> 45);
        padded[250] = (uint8_t)(bytes >> 37);
        padded[251] = (uint8_t)(bytes >> 29);
        padded[252] = (uint8_t)(bytes >> 21);
        padded[253] = (uint8_t)(bytes >> 13);
        padded[254] = (uint8_t)(bytes >> 5);
        padded[255] = (uint8_t)(bytes << 3);

        //blocks(h, padded, 256);
        memcpy(w, padded , 128);
        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);

        AVX_sha512_compress(state, w);
        //temp256 = temp256 + 4;
        memcpy(w, padded + 128, 128);
        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);
        AVX_sha512_compress(state, w);
    }

    __m256i *state256 = (__m256i*) state;
    state256[0] = _mm256_shuffle_epi8(state256[0], maska_for_shuffle_64);
    state256[1] = _mm256_shuffle_epi8(state256[1], maska_for_shuffle_64);

    memcpy(out, state, out_len);

}

void AVX_sha512_calc_w4(__m256i w[80]/*, const __m256i* block256*/)
{
    //memcpy(w, block256, 16 * sizeof(__m256i));

    uint32_t t;
    for (t = 16; t < 80; t += 16)
    {

        //w[t] = w[t - 16] + s0(w[t - 15]) + w[t - 7] + s1(w[t - 2]);
        w[t] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 16], s0_256(w[t - 15])),
            _mm256_add_epi64(w[t - 7], s1_256(w[t - 2]))
        );
        //w[t + 1] = w[t - 15] + s0(w[t - 14]) + w[t - 6] + s1(w[t - 1]);
        w[t + 1] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 15], s0_256(w[t - 14])),
            _mm256_add_epi64(w[t - 6], s1_256(w[t - 1]))
        );

        //w[t + 2] = w[t - 14] + s0(w[t - 13]) + w[t - 5] + s1(w[t]);
        w[t + 2] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 14], s0_256(w[t - 13])),
            _mm256_add_epi64(w[t - 5], s1_256(w[t]))
        );

        //w[t + 3] = w[t - 13] + s0(w[t - 12]) + w[t - 4] + s1(w[t + 1]);
        w[t + 3] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 13], s0_256(w[t - 12])),
            _mm256_add_epi64(w[t - 4], s1_256(w[t + 1]))
        );

        //w[t + 4] = w[t - 12] + s0(w[t - 11]) + w[t - 3] + s1(w[t + 2]);
        w[t + 4] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 12], s0_256(w[t - 11])),
            _mm256_add_epi64(w[t - 3], s1_256(w[t + 2]))
        );
        //w[t + 5] = w[t - 11] + s0(w[t - 10]) + w[t - 2] + s1(w[t + 3]);
        w[t + 5] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 11], s0_256(w[t - 10])),
            _mm256_add_epi64(w[t - 2], s1_256(w[t + 3]))
        );

        //w[t + 6] = w[t - 10] + s0(w[t - 9]) + w[t - 1] + s1(w[t + 4]);
        w[t + 6] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 10], s0_256(w[t - 9])),
            _mm256_add_epi64(w[t - 1], s1_256(w[t + 4]))
        );
        //w[t + 7] = w[t - 9] + s0(w[t - 8]) + w[t - 0] + s1(w[t + 5]);
        w[t + 7] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 9], s0_256(w[t - 8])),
            _mm256_add_epi64(w[t], s1_256(w[t + 5]))
        );

        //w[t + 8] = w[t - 8] + s0(w[t - 7]) + w[t + 1] + s1(w[t + 6]);
        w[t + 8] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 8], s0_256(w[t - 7])),
            _mm256_add_epi64(w[t + 1], s1_256(w[t + 6]))
        );
        //w[t + 9] = w[t - 7] + s0(w[t - 6]) + w[t + 2] + s1(w[t + 7]);
        w[t + 9] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 7], s0_256(w[t - 6])),
            _mm256_add_epi64(w[t + 2], s1_256(w[t + 7]))
        );

        //w[t + 10] = w[t - 6] + s0(w[t - 5]) + w[t + 3] + s1(w[t + 8]);
        w[t + 10] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 6], s0_256(w[t - 5])),
            _mm256_add_epi64(w[t + 3], s1_256(w[t + 8]))
        );

        //w[t + 11] = w[t - 5] + s0(w[t - 4]) + w[t + 4] + s1(w[t + 9]);
        w[t + 11] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 5], s0_256(w[t - 4])),
            _mm256_add_epi64(w[t + 4], s1_256(w[t + 9]))
        );

        //w[t + 12] = w[t - 4] + s0(w[t - 3]) + w[t + 5] + s1(w[t + 10]);
        w[t + 12] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 4], s0_256(w[t - 3])),
            _mm256_add_epi64(w[t + 5], s1_256(w[t + 10]))
        );
        //w[t + 13] = w[t - 3] + s0(w[t - 2]) + w[t + 6] + s1(w[t + 11]);
        w[t + 13] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 3], s0_256(w[t - 2])),
            _mm256_add_epi64(w[t + 6], s1_256(w[t + 11]))
        );

        //w[t + 14] = w[t - 2] + s0(w[t - 1]) + w[t + 7] + s1(w[t + 12]);
        w[t + 14] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 2], s0_256(w[t - 1])),
            _mm256_add_epi64(w[t + 7], s1_256(w[t + 12]))
        );

        //w[t + 15] = w[t - 1] + s0(w[t]) + w[t + 8] + s1(w[t + 13]);
        w[t + 15] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 1], s0_256(w[t])),
            _mm256_add_epi64(w[t + 8], s1_256(w[t + 13]))
        );

    }

    //const __m256i* k256 = (const __m256i*)k;
    for (t = 0; t < 80; t += 16)
    {
        w[t] = _mm256_add_epi64(_mm256_set1_epi64x(k[t]), w[t]);
        w[t + 1] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 1]), w[t + 1]);
        w[t + 2] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 2]), w[t + 2]);
        w[t + 3] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 3]), w[t + 3]);
        w[t + 4] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 4]), w[t + 4]);
        w[t + 5] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 5]), w[t + 5]);
        w[t + 6] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 6]), w[t + 6]);
        w[t + 7] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 7]), w[t + 7]);
        w[t + 8] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 8]), w[t + 8]);
        w[t + 9] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 9]), w[t + 9]);
        w[t + 10] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 10]), w[t + 10]);
        w[t + 11] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 11]), w[t + 11]);
        w[t + 12] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 12]), w[t + 12]);
        w[t + 13] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 13]), w[t + 13]);
        w[t + 14] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 14]), w[t + 14]);
        w[t + 15] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 15]), w[t + 15]);
    }

}

void calc_state(uint64_t *state, const uint64_t *w)
{
// Initialize working variables

    uint64_t a = state[0];    //    a[0]
    uint64_t b = state[1];    //    a[1]
    uint64_t c = state[2];    //    a[2]
    uint64_t d = state[3];    //    a[3]
    uint64_t e = state[4];    //    a[4]
    uint64_t f = state[5];    //    a[5]
    uint64_t g = state[6];    //    a[6]
    uint64_t h = state[7];    //    a[7]



    uint64_t temp1, temp2;
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

    DO(w[64]);
    DO(w[65]);
    DO(w[66]);
    DO(w[67]);
    DO(w[68]);
    DO(w[69]);
    DO(w[70]);
    DO(w[71]);
    DO(w[72]);
    DO(w[73]);
    DO(w[74]);
    DO(w[75]);
    DO(w[76]);
    DO(w[77]);
    DO(w[78]);
    DO(w[79]);



    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void AVX_PREDCALC_W_sha512_(uint8_t* out, const uint64_t* pk, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
    ALIGN64 uint64_t state[8];

    const int64_t* in64 = (const int64_t*)in;
    //uint8_t padded[256];
    unsigned int i;
    uint64_t bytes = (in_len + 128);
    //uint32_t bits = in_len + (FIPS205_N) * 8;

    memcpy(state, pk, sizeof(state));

    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    //__m256i in256[16];
    __m256i temp256[80];
    
    __m256i idx = _mm256_setr_epi64x(0, 16, 32, 48);
    uint64_t* temp256_64 = (uint64_t*)temp256;
    uint8_t* padded = (uint8_t*)(temp256);
    __m256i w[80]/*, w_[80]*/;
    
    
    while (in_len > 128 * 4)
    {
        idx = _mm256_setr_epi64x(0, 16, 32, 48);

        in64 = (const int64_t*)in;
        //__m256i step = step_;
        //__m256i temp = _mm256_i64gather_epi64(in64++, idx, 8);
        #if 0
        in256[0] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        //temp = _mm256_i64gather_epi64(in64++, idx, 8);
        in256[1] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        //temp = _mm256_i64gather_epi64(in64++, idx, 8);
        in256[2] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[3] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[4] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[5] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[6] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[7] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[8] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[9] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[10] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[11] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[12] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[13] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[14] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
        in256[15] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska);
#else
        temp256[0] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        //temp = _mm256_i64gather_epi64(in64++, idx, 8);
        temp256[1] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        //temp = _mm256_i64gather_epi64(in64++, idx, 8);
        temp256[2] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[3] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[4] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[5] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[6] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[7] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[8] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[9] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[10] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[11] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[12] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[13] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[14] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
        temp256[15] = _mm256_shuffle_epi8(_mm256_i64gather_epi64(in64++, idx, 8), maska_for_shuffle_64);
#endif
        //AVX_calc_w4(temp256/*, in256*/);
        AVX_sha512_calc_w4(temp256);
        //__m256i stepj = step_;
        
        __m256i one = _mm256_setr_epi64x(1, 1, 1, 1);
        uint32_t j, k, l = 0;
        idx = _mm256_setr_epi64x(0, 4, 8, 12);
        __m256i idx_ = idx;
        __m256i* p = w;
        for (j = 0; j < 4; ++j)
        {
            k = 0;
            
            for (i = 0; i < 5; ++i)
            {
                
                /*for (j = 0; j < 4; ++j)
                w[k++] = _mm256_i64gather_epi64((__int64 const*)(temp256 + 4 * i + j ), idx, 1); */
                p [l++] = _mm256_i64gather_epi64((__int64 const*)(temp256 + k), idx_, 8);
                //idx_ = _mm256_add_epi64(idx_, one);
                p[l++] = _mm256_i64gather_epi64((__int64 const*)(temp256 + k + 4), idx_, 8);
                //idx_ = _mm256_add_epi64(idx_, one);
                p[l++] = _mm256_i64gather_epi64((__int64 const*)(temp256 + k + 8), idx_, 8);
                //idx_ = _mm256_add_epi64(idx_, one);
                p[l++] = _mm256_i64gather_epi64((__int64 const*)(temp256 + k + 12), idx_, 8);
                k += 16;
            }
            
            idx_ = _mm256_add_epi64(idx_, one);
        }

        
        uint64_t* w_64 = (uint64_t*)w;
        calc_state(state, w_64);
        calc_state(state, w_64 + 80);
        calc_state(state, w_64 + 160);
        calc_state(state, w_64 + 240);

        in += 512;
        in_len -= 512;
      }
    while (in_len >= 128)
    {
        w[0] = _mm256_lddqu_si256((__m256i*)in);
        w[1] = _mm256_lddqu_si256((__m256i*)(in + 32));
        w[2] = _mm256_lddqu_si256((__m256i*)(in + 64));
        w[3] = _mm256_lddqu_si256((__m256i*)(in + 96));

        w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);
        AVX_sha512_compress(state, w);
        in += 128;
        in_len -= 128;
    }


    for (i = 0; i < in_len; ++i) padded[i] = in[i];
    padded[in_len] = 0x80;
    //__m256i* temp256 = (__m256i*)padded;
    if (in_len < 112) {
        for (i = in_len + 1; i < 119; ++i) padded[i] = 0;
        padded[119] = (uint8_t)(bytes >> 61);
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        //blocks(h, padded, 128);
        w[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(temp256[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(temp256[3], maska_for_shuffle_64);

        AVX_sha512_compress(state, w);

    }
    else {
        for (i = in_len + 1; i < 247; ++i) padded[i] = 0;
        padded[247] = (uint8_t)(bytes >> 61);
        padded[248] = (uint8_t)(bytes >> 53);
        padded[249] = (uint8_t)(bytes >> 45);
        padded[250] = (uint8_t)(bytes >> 37);
        padded[251] = (uint8_t)(bytes >> 29);
        padded[252] = (uint8_t)(bytes >> 21);
        padded[253] = (uint8_t)(bytes >> 13);
        padded[254] = (uint8_t)(bytes >> 5);
        padded[255] = (uint8_t)(bytes << 3);
        //blocks(h, padded, 256);
        w[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(temp256[2], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(temp256[3], maska_for_shuffle_64);

        AVX_sha512_compress(state, w);
        //temp256 = temp256 + 4;
        w[0] = _mm256_shuffle_epi8(temp256[4], maska_for_shuffle_64);
        w[1] = _mm256_shuffle_epi8(temp256[5], maska_for_shuffle_64);
        w[2] = _mm256_shuffle_epi8(temp256[6], maska_for_shuffle_64);
        w[3] = _mm256_shuffle_epi8(temp256[7], maska_for_shuffle_64);
        AVX_sha512_compress(state, w);
    }

    __m256i *state256 = (__m256i*) state;
    state256[0] = _mm256_shuffle_epi8( state256 [0], maska_for_shuffle_64);
    state256[1] = _mm256_shuffle_epi8( state256 [1], maska_for_shuffle_64);

    memcpy(out, state256, out_len);

}

void AVX_sha512_device(uint8_t* hash, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
    // Not defined
}

// blocks
void AVX_sha512_predcalc_pk_(__m256i state256[8], const uint8_t* in)
{
    uint64_t state[8];
    memcpy(state, HInit, sizeof(HInit));
    ALIGN64 uint8_t temp[128];
    memcpy(temp, in, FIPS205_N);
    memset(temp + FIPS205_N, 0, 128 - FIPS205_N);
    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    __m256i w[20];
    memcpy(w, temp, 128);
    w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
    w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
    w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
    w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);
    AVX_sha512_compress(state, w);

    state256[0] = _mm256_set1_epi64x(state[0]);
    state256[1] = _mm256_set1_epi64x(state[1]);
    state256[2] = _mm256_set1_epi64x(state[2]);
    state256[3] = _mm256_set1_epi64x(state[3]);
    state256[4] = _mm256_set1_epi64x(state[4]);
    state256[5] = _mm256_set1_epi64x(state[5]);
    state256[6] = _mm256_set1_epi64x(state[6]);
    state256[7] = _mm256_set1_epi64x(state[7]);
    
}


void AVX_sha512_WITH_PREDCALC(uint8_t* hash, const uint64_t* state, const uint8_t* in, uint32_t in_len, uint32_t out_len)
{
#if 0
    ALIGN128 uint8_t temp[128];

    uint32_t bits = (in_len + 128) * 8;
    memcpy(temp, in, in_len);
    temp[in_len++] = 0x80;
    uint32_t end_pos = 128;

    memset(temp + in_len, 0, end_pos - 8 - in_len);

    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;

    const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    __m256i* temp256 = (__m256i*)temp;
    temp256[0] = _mm256_shuffle_epi8(temp256[0], maska);
    temp256[1] = _mm256_shuffle_epi8(temp256[1], maska);
    temp256[2] = _mm256_shuffle_epi8(temp256[2], maska);
    temp256[3] = _mm256_shuffle_epi8(temp256[3], maska);

    uint64_t cur_state[8];
    memcpy(cur_state, state, sizeof(cur_state));
    AVX_sha512_compress(cur_state, temp256);
#else
    ALIGN64 __m256i w[20];
    uint8_t *temp = (uint8_t*)w;

    uint32_t bits = (in_len + 128) * 8;
    memcpy(temp, in, in_len);
    temp[in_len++] = 0x80;
    uint32_t end_pos = 128;

    memset(temp + in_len, 0, end_pos - 8 - in_len);

    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;
    temp[--end_pos] = bits & 0xFF; bits >>= 8;

    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    //__m256i* temp256 = (__m256i*)temp;
    w[0] = _mm256_shuffle_epi8(w[0], maska_for_shuffle_64);
    w[1] = _mm256_shuffle_epi8(w[1], maska_for_shuffle_64);
    w[2] = _mm256_shuffle_epi8(w[2], maska_for_shuffle_64);
    w[3] = _mm256_shuffle_epi8(w[3], maska_for_shuffle_64);

    ALIGN64 uint64_t cur_state[8];
    memcpy(cur_state, state, sizeof(cur_state));
    AVX_sha512_compress(cur_state, w);
#endif
    /*const __m256i maska = _mm256_setr_epi32(0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
        0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F);*/

        //__m256i* temp256 = (__m256i*)temp;
    __m256i* state_256 = (__m256i*) cur_state;
    state_256[0] = _mm256_shuffle_epi8(state_256[0], maska_for_shuffle_64);
    state_256[1] = _mm256_shuffle_epi8(state_256[1], maska_for_shuffle_64);
    memcpy(hash, state_256, out_len);
}

void AVX_HMAC512(uint8_t* dest, const uint8_t* sk, uint32_t sk_len, const uint8_t* src, uint32_t len, uint32_t dest_len )
{
    #define	BLOCKSIZE	128
    
    uint8_t buf[BLOCKSIZE + BLOCKSIZE / 2]; // oKey
    //uint32_t blocks = (BLOCKSIZE + (len + 31) / 32 * 32) / 32;
    //_mm_malloc(a, b) _aligned_malloc(a, b)
    uint8_t* temp = malloc(BLOCKSIZE + len);    //      ikey
    //__m256i* buf256 = (__m256i*)buf, * temp256 = (__m256i*)temp;
    if (temp)
    {
        uint32_t i;
        
                
        memset(temp, 0x36, BLOCKSIZE + len);
        for (i = 0; i < sk_len; ++i)
        {
            temp[i]^= sk[i];
        }
                        
        for (i = 0; i < len; i++)
            temp[BLOCKSIZE + i] = src[i];

        memset(buf, 0x5c, BLOCKSIZE);

        for (i = 0; i < sk_len; ++i)
        {
            buf[i] ^= sk[i];
        }

        
        AVX_sha512(buf + BLOCKSIZE, temp, BLOCKSIZE + len, 64);
        AVX_sha512(dest, buf, BLOCKSIZE + BLOCKSIZE / 2, dest_len);


        /*for (i = 0; i < 64; ++i)
        {
            dest[i] = temp[i];
        }*/

        free(temp);
    }
#undef BLOCKSIZE

}

void AVX_MGF1_sha512(
    uint8_t* out,
    uint32_t outlen,
    const uint8_t* in,
    uint32_t inlen)
{
    uint8_t* inbuf = (uint8_t*)malloc(inlen + 4);
    //uint8_t outbuf[64];
    unsigned i;

    memcpy(inbuf, in, inlen);

    // blocks and last_blok_len 
    uint32_t blocks = outlen / 64;
    uint32_t last_block_len = outlen % 64;
    uint8_t* pend = inbuf + inlen;
    for (i = 0; i < blocks; i++) {
        toByte32_(pend, i);
        AVX_sha512(out, inbuf, inlen + 4, 64);
        out += 64;
    }
    
    if (last_block_len) {
        toByte32_(pend, i);
        AVX_sha512(out, inbuf, inlen + 4, last_block_len);
        //memcpy(out, outbuf, outlen - i * 64);
    }
    free(inbuf);
}

void AVX_sha512_compress4(__m256i* state256, __m256i* w/*__m256i* block256*/)
{
   // uint32_t t;
    //__m256i w[80];
#if 0
    memcpy(w, block256, 16 * sizeof (__m256i));

    for (t = 16; t < 80; t += 16)
    {
        
        //w[t] = w[t - 16] + s0(w[t - 15]) + w[t - 7] + s1(w[t - 2]);
        w[t] = _mm256_add_epi64(
            _mm256_add_epi64 (w[t - 16], s0_256(w[t - 15])),
            _mm256_add_epi64 (w[t - 7], s1_256 (w[t - 2]))
        );
        //w[t + 1] = w[t - 15] + s0(w[t - 14]) + w[t - 6] + s1(w[t - 1]);
        w[t + 1] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 15], s0_256(w[t - 14])),
            _mm256_add_epi64(w[t - 6], s1_256(w[t - 1]))
        );

        //w[t + 2] = w[t - 14] + s0(w[t - 13]) + w[t - 5] + s1(w[t]);
        w[t + 2] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 14], s0_256(w[t - 13])),
            _mm256_add_epi64(w[t - 5], s1_256(w[t ]))
        );

        //w[t + 3] = w[t - 13] + s0(w[t - 12]) + w[t - 4] + s1(w[t + 1]);
        w[t + 3] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 13], s0_256(w[t - 12])),
            _mm256_add_epi64(w[t - 4], s1_256(w[t + 1]))
        );

        //w[t + 4] = w[t - 12] + s0(w[t - 11]) + w[t - 3] + s1(w[t + 2]);
        w[t + 4] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 12], s0_256(w[t - 11])),
            _mm256_add_epi64(w[t - 3], s1_256(w[t + 2]))
        );
        //w[t + 5] = w[t - 11] + s0(w[t - 10]) + w[t - 2] + s1(w[t + 3]);
        w[t + 5] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 11], s0_256(w[t - 10])),
            _mm256_add_epi64(w[t - 2], s1_256(w[t + 3]))
        );

        //w[t + 6] = w[t - 10] + s0(w[t - 9]) + w[t - 1] + s1(w[t + 4]);
        w[t + 6] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 10], s0_256(w[t - 9])),
            _mm256_add_epi64(w[t - 1], s1_256(w[t + 4]))
        );
        //w[t + 7] = w[t - 9] + s0(w[t - 8]) + w[t - 0] + s1(w[t + 5]);
        w[t + 7] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 9], s0_256(w[t - 8])),
            _mm256_add_epi64(w[t ], s1_256(w[t + 5]))
        );

        //w[t + 8] = w[t - 8] + s0(w[t - 7]) + w[t + 1] + s1(w[t + 6]);
        w[t + 8] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 8], s0_256(w[t - 7])),
            _mm256_add_epi64(w[t + 1], s1_256(w[t + 6]))
        );
        //w[t + 9] = w[t - 7] + s0(w[t - 6]) + w[t + 2] + s1(w[t + 7]);
        w[t + 9] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 7], s0_256(w[t - 6])),
            _mm256_add_epi64(w[t + 2], s1_256(w[t + 7]))
        );

        //w[t + 10] = w[t - 6] + s0(w[t - 5]) + w[t + 3] + s1(w[t + 8]);
        w[t + 10] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 6], s0_256(w[t - 5])),
            _mm256_add_epi64(w[t + 3], s1_256(w[t + 8]))
        );

        //w[t + 11] = w[t - 5] + s0(w[t - 4]) + w[t + 4] + s1(w[t + 9]);
        w[t + 11] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 5], s0_256(w[t - 4])),
            _mm256_add_epi64(w[t + 4], s1_256(w[t + 9]))
        );

        //w[t + 12] = w[t - 4] + s0(w[t - 3]) + w[t + 5] + s1(w[t + 10]);
        w[t + 12] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 4], s0_256(w[t - 3])),
            _mm256_add_epi64(w[t + 5], s1_256(w[t + 10]))
        );
        //w[t + 13] = w[t - 3] + s0(w[t - 2]) + w[t + 6] + s1(w[t + 11]);
        w[t + 13] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 3], s0_256(w[t - 2])),
            _mm256_add_epi64(w[t + 6], s1_256(w[t + 11]))
        );
        
        //w[t + 14] = w[t - 2] + s0(w[t - 1]) + w[t + 7] + s1(w[t + 12]);
        w[t + 14] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 2], s0_256(w[t - 1])),
            _mm256_add_epi64(w[t + 7], s1_256(w[t + 12]))
        );
        
        //w[t + 15] = w[t - 1] + s0(w[t]) + w[t + 8] + s1(w[t + 13]);
        w[t + 15] = _mm256_add_epi64(
            _mm256_add_epi64(w[t - 1], s0_256(w[t ])),
            _mm256_add_epi64(w[t + 8], s1_256(w[t + 13]))
        );

    }

    

    //const __m256i* k256 = (const __m256i*)k;
    for (t = 0; t < 80; t += 16)
    {
        w[t] = _mm256_add_epi64(_mm256_set1_epi64x(k[t]), w[t]);
        w[t + 1] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 1]), w[t + 1]);
        w[t + 2] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 2]), w[t + 2]);
        w[t + 3] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 3]), w[t + 3]);
        w[t + 4] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 4]), w[t + 4]);
        w[t + 5] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 5]), w[t + 5]);
        w[t + 6] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 6]), w[t + 6]);
        w[t + 7] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 7]), w[t + 7]);
        w[t + 8] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 8]), w[t + 8]);
        w[t + 9] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 9]), w[t + 9]);
        w[t + 10] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 10]), w[t + 10]);
        w[t + 11] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 11]), w[t + 11]);
        w[t + 12] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 12]), w[t + 12]);
        w[t + 13] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 13]), w[t + 13]);
        w[t + 14] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 14]), w[t + 14]);
        w[t + 15] = _mm256_add_epi64(_mm256_set1_epi64x(k[t + 15]), w[t + 15]);
    }
#else
AVX_sha512_calc_w4(w/*, block256*/);
#endif
    // Initialize working variables
    __m256i a, b, c, d, e, f, g, h;
    a = state256[0];    
    b = state256[1];    
    c = state256[2];    
    d = state256[3];    
    e = state256[4];    
    f = state256[5];    
    g = state256[6];    
    h = state256[7];    

    __m256i  temp1, temp2;
    DO_256(w[0]);
    DO_256(w[1]);
    DO_256(w[2]);
    DO_256(w[3]);
    DO_256(w[4]);
    DO_256(w[5]);
    DO_256(w[6]);
    DO_256(w[7]);
    DO_256(w[8]);
    DO_256(w[9]);
    DO_256(w[10]);
    DO_256(w[11]);
    DO_256(w[12]);
    DO_256(w[13]);
    DO_256(w[14]);
    DO_256(w[15]);

    DO_256(w[16]);
    DO_256(w[17]);
    DO_256(w[18]);
    DO_256(w[19]);
    DO_256(w[20]);
    DO_256(w[21]);
    DO_256(w[22]);
    DO_256(w[23]);
    DO_256(w[24]);
    DO_256(w[25]);
    DO_256(w[26]);
    DO_256(w[27]);
    DO_256(w[28]);
    DO_256(w[29]);
    DO_256(w[30]);
    DO_256(w[31]);

    DO_256(w[32]);
    DO_256(w[33]);
    DO_256(w[34]);
    DO_256(w[35]);
    DO_256(w[36]);
    DO_256(w[37]);
    DO_256(w[38]);
    DO_256(w[39]);
    DO_256(w[40]);
    DO_256(w[41]);
    DO_256(w[42]);
    DO_256(w[43]);
    DO_256(w[44]);
    DO_256(w[45]);
    DO_256(w[46]);
    DO_256(w[47]);
    //
    DO_256(w[48]);
    DO_256(w[49]);
    DO_256(w[50]);
    DO_256(w[51]);
    DO_256(w[52]);
    DO_256(w[53]);
    DO_256(w[54]);
    DO_256(w[55]);
    DO_256(w[56]);
    DO_256(w[57]);
    DO_256(w[58]);
    DO_256(w[59]);
    DO_256(w[60]);
    DO_256(w[61]);
    DO_256(w[62]);
    DO_256(w[63]);

    DO_256(w[64]);
    DO_256(w[65]);
    DO_256(w[66]);
    DO_256(w[67]);
    DO_256(w[68]);
    DO_256(w[69]);
    DO_256(w[70]);
    DO_256(w[71]);
    DO_256(w[72]);
    DO_256(w[73]);
    DO_256(w[74]);
    DO_256(w[75]);
    DO_256(w[76]);
    DO_256(w[77]);
    DO_256(w[78]);
    DO_256(w[79]);



    state256[0] = _mm256_add_epi64 (state256[0],a);
    state256[1] = _mm256_add_epi64(state256[1], b);
    state256[2] = _mm256_add_epi64(state256[2], c);
    state256[3] = _mm256_add_epi64(state256[3], d);
    state256[4] = _mm256_add_epi64(state256[4], e);
    state256[5] = _mm256_add_epi64(state256[5], f);
    state256[6] = _mm256_add_epi64(state256[6], g);
    state256[7] = _mm256_add_epi64(state256[7], h);
}

static void toConvert64(__m256i dest_[16], uint64_t src[16 * 4], uint32_t size)
{

    __m128i _1_128 = _mm_set1_epi32(1);
    //__m128i maska = _mm_load_si128((const __m128i*)u8_maska), temp;
    __m128i idx = _mm_setr_epi32(0, 16, 32, 48);
    for (uint32_t i = 0; i < size; ++i)
    {
        dest_[i] = _mm256_i32gather_epi64(src, idx, 8)/*, maska)*/;
        idx = _mm_add_epi32(idx, _1_128);

    }

}

// Function H (PK + 0 + ADR + 2 * N)
void AVX_sha512_WITH_PREDCALC4(uint8_t hash[4][FIPS205_N], const uint64_t state[8], const uint8_t in[4][2 * FIPS205_N + ADR_SIZE])
{
    ALIGN64 uint8_t temp[4][128] ;
    //uint64_t* temp64 = (uint64_t*)temp;
    __m256i* temp256[4] = { (__m256i*)temp[0], (__m256i*)temp[1], (__m256i*)temp[2], (__m256i*)temp[3] };
    const uint32_t inlen = 2 * FIPS205_N + ADR_SIZE;
    const uint64_t bytes = 128 + inlen;
    //uint32_t j;
    memcpy(temp[0], in[0], inlen);
    memcpy(temp[1], in[1], inlen);
    memcpy(temp[2], in[2], inlen);
    memcpy(temp[3], in[3], inlen);

    uint8_t padded[128 - 2 * FIPS205_N - ADR_SIZE] = {0};
    padded[0] = 0x80;
    uint64_t last_index = 119 - (2 * FIPS205_N + ADR_SIZE);
    //for (i = inlen + 1; i < 119; ++i) padded[i] = 0;
    padded[last_index] = (uint8_t)(bytes >> 61);
    padded[last_index + 1] = (uint8_t)(bytes >> 53);
    padded[last_index + 2] = (uint8_t)(bytes >> 45);
    padded[last_index + 3] = (uint8_t)(bytes >> 37);
    padded[last_index + 4] = (uint8_t)(bytes >> 29);
    padded[last_index + 5] = (uint8_t)(bytes >> 21);
    padded[last_index + 6] = (uint8_t)(bytes >> 13);
    padded[last_index + 7] = (uint8_t)(bytes >> 5);
    padded[last_index + 8] = (uint8_t)(bytes << 3);
    memcpy(temp[0] + inlen, padded, 128 - inlen);
    memcpy(temp[1] + inlen, padded, 128 - inlen);
    memcpy(temp[2] + inlen, padded, 128 - inlen);
    memcpy(temp[3] + inlen, padded, 128 - inlen);

    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    temp256 [0][0]    = _mm256_shuffle_epi8(temp256[0][0], maska_for_shuffle_64);
    temp256 [0][1] = _mm256_shuffle_epi8(temp256[0][1], maska_for_shuffle_64);
    temp256[0][2] = _mm256_shuffle_epi8(temp256[0][2], maska_for_shuffle_64);
    temp256[0][3] = _mm256_shuffle_epi8(temp256[0][3], maska_for_shuffle_64);

    temp256[1][0] = _mm256_shuffle_epi8(temp256[1][0], maska_for_shuffle_64);
    temp256[1][1] = _mm256_shuffle_epi8(temp256[1][1], maska_for_shuffle_64);
    temp256[1][2] = _mm256_shuffle_epi8(temp256[1][2], maska_for_shuffle_64);
    temp256[1][3] = _mm256_shuffle_epi8(temp256[1][3], maska_for_shuffle_64);

    temp256[2][0] = _mm256_shuffle_epi8(temp256[2][0], maska_for_shuffle_64);
    temp256[2][1] = _mm256_shuffle_epi8(temp256[2][1], maska_for_shuffle_64);
    temp256[2][2] = _mm256_shuffle_epi8(temp256[2][2], maska_for_shuffle_64);
    temp256[2][3] = _mm256_shuffle_epi8(temp256[2][3], maska_for_shuffle_64);

    temp256[3][0] = _mm256_shuffle_epi8(temp256[3][0], maska_for_shuffle_64);
    temp256[3][1] = _mm256_shuffle_epi8(temp256[3][1], maska_for_shuffle_64);
    temp256[3][2] = _mm256_shuffle_epi8(temp256[3][2], maska_for_shuffle_64);
    temp256[3][3] = _mm256_shuffle_epi8(temp256[3][3], maska_for_shuffle_64);

    __m256i in256[80], state256[8];

    __m128i step = _mm_set1_epi32(1);
    __m128i idx = _mm_setr_epi32(0, 16, 32, 48);
    
    in256[0] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[1] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[2] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[3] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);

    in256[4] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[5] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[6] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[7] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);

    in256[8] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[9] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[10] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[11] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);

    in256[12] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[13] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[14] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);
    in256[15] = _mm256_i32gather_epi64((__int64 const*)temp, idx, 8); idx = _mm_add_epi32(idx, step);


    state256[0] = _mm256_set1_epi64x(state[0]);
    state256[1] = _mm256_set1_epi64x(state[1]);
    state256[2] = _mm256_set1_epi64x(state[2]);
    state256[3] = _mm256_set1_epi64x(state[3]);
    state256[4] = _mm256_set1_epi64x(state[4]);
    state256[5] = _mm256_set1_epi64x(state[5]);
    state256[6] = _mm256_set1_epi64x(state[6]);
    state256[7] = _mm256_set1_epi64x(state[7]);


    AVX_sha512_compress4(state256, in256);

    idx = _mm_setr_epi32(0, 4, 8, 12);

    in256[0] = _mm256_i32gather_epi64((uint64_t*)state256, idx, 8);
    idx = _mm_add_epi32(idx, step);
    in256[1] = _mm256_i32gather_epi64((uint64_t*)state256, idx, 8);
    idx = _mm_add_epi32(idx, step);
    in256[2] = _mm256_i32gather_epi64((uint64_t*)state256, idx, 8);
    idx = _mm_add_epi32(idx, step);
    in256[3] = _mm256_i32gather_epi64((uint64_t*)state256, idx, 8);
        
    in256[0] = _mm256_shuffle_epi8(in256[0], maska_for_shuffle_64);
    in256[1] = _mm256_shuffle_epi8(in256[1], maska_for_shuffle_64);
    in256[2] = _mm256_shuffle_epi8(in256[2], maska_for_shuffle_64);
    in256[3] = _mm256_shuffle_epi8(in256[3], maska_for_shuffle_64);

    memcpy(hash[0], in256, FIPS205_N);
    memcpy(hash[1], in256 + 1, FIPS205_N);
    memcpy(hash[2], in256 + 2, FIPS205_N);
    memcpy(hash[3], in256 + 3, FIPS205_N);

}

// predcalc_pk_sha
void AVX_sha512_predcalc_pk(uint64_t* state64, const uint8_t* in)
{

    memcpy(state64, HInit, sizeof(HInit));
    /*__declspec (align (64))
        uint8_t temp[128];
    memcpy(temp, in, FIPS205_N);
    memset(temp + FIPS205_N, 0, 128 - FIPS205_N);*/
    __m256i temp256[80];
    uint8_t* temp = (uint8_t*)temp256;
    
    memcpy(temp, in, FIPS205_N);
    memset(temp + FIPS205_N, 0, 128 - FIPS205_N);

    //const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska_512);
    //__m256i* temp256 = (__m256i*)temp;
    temp256[0] = _mm256_shuffle_epi8(temp256[0], maska_for_shuffle_64);
    temp256[1] = _mm256_shuffle_epi8(temp256[1], maska_for_shuffle_64);
    temp256[2] = _mm256_shuffle_epi8(temp256[2], maska_for_shuffle_64);
    temp256[3] = _mm256_shuffle_epi8(temp256[3], maska_for_shuffle_64);
    AVX_sha512_compress(state64, temp256);
}

void AVX_sha512_one_block(uint8_t* out, uint64_t* predcalc, uint8_t* in, size_t inlen, size_t out_len)
{
    ALIGN32 uint64_t state[8];

    __m256i in256[20];
    uint8_t* pin = (uint8_t*)in256;

    size_t bytes = (128 + inlen) ;

    memcpy(pin, in, inlen);

    pin[inlen] = 0x80;
        
    memset(pin + inlen + 1, 0, 124 - inlen);

    pin[124] = (uint8_t)(bytes >> 21);
    pin[125] = (uint8_t)(bytes >> 13);
    pin[126] = (uint8_t)(bytes >> 5);
    pin[127] = (uint8_t)(bytes << 3);


    in256[0] = _mm256_shuffle_epi8(in256[0], maska_for_shuffle_64);
    in256[1] = _mm256_shuffle_epi8(in256[1], maska_for_shuffle_64);
    in256[2] = _mm256_shuffle_epi8(in256[2], maska_for_shuffle_64);
    in256[3] = _mm256_shuffle_epi8(in256[3], maska_for_shuffle_64);
    
    memcpy(state, predcalc, sizeof(state));

    AVX_sha512_compress(state, in256);

    __m256i* state_256 = (__m256i*) state;
    state_256[0] = _mm256_shuffle_epi8(state_256[0], maska_for_shuffle_64);
    memcpy(out, state, out_len);
}