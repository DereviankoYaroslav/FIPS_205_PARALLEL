#include <stdio.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include <immintrin.h>
#include "FIPS_205_Params.h"
#include "FIPS_205_ht_old.h"
#include "FIPS205_ht.h"
#include "Common.h"
#include "AVX256.h"
#include "SHA512.h"
#include "AVX512.h"
//#include "thash.h"
//#include "OLD/api.h"
#include "OLD/thashx8.h"
#include "OLD/wots.h"
#include "OLD/fors.h"
#include "FIPS_205_Hashs.h"
#include "FIPS205_WOTS.h"
#include "FIPS_205_wots_old.h"
#include "FIPS_205_xmss.h"
#include "FIPS_205_xmss_old.h"
#include "FIPS_205_Fors_old.h"
#include "FIPS_205_Fors.h"
#include "FIPS_205_internal.h"
#include "FIPS_205_internal_old.h"
#include "print.h"

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

void ht_signature(uint8_t* sig, unsigned char* root, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* wots_addr, uint8_t* tree_addr, uint64_t tree, uint32_t idx_leaf);
int ht_verify(
    uint8_t* sig,
    uint8_t* root,
    uint8_t* pub_seed,
    uint8_t* pub_root,
    /*uint8_t* tree_addr,
    uint8_t* wots_addr,*/
    uint64_t tree,
    uint32_t idx_leaf
);
int crypto_sign_seed_keypair(unsigned char* pk, unsigned char* sk,
    const unsigned char* seed);
int crypto_sign_signature(uint8_t* sig, size_t* siglen,
    const uint8_t* m, size_t mlen, const uint8_t* sk);


#ifndef _DEBUG
uint64_t tacts, min_tacts;
#endif





int test_calc_w()
{

    ALIGN64 uint32_t w1[64];
    uint32_t w2[64];
    __m128i* w128 = (__m128i*)w2;
    srand(0);
    uint32_t i;
    for (i = 0; i < 16; ++i)
    {
        w1[i] = (rand() << (32 - 15)) + rand();
        w2[i] = w1[i];
    }



    uint32_t t64 = 4, t;



    __m128i t1 = _mm_load_si128((const __m128i*)(w2 + 12));

    for (t = 16; t < 64; t += 4)
    {

        /*
        w[i] := w[i-16] + s0 (w[i-15]) + w[i-7] + s1(i-2)
        */

        __m128i t2 = _mm_add_epi32(
            _mm_add_epi32(w128[t64 - 4], _mm_lddqu_si128((const __m128i*) (w2 + t - 7))),
            _mm_add_epi32(
                s0_128(_mm_lddqu_si128((const __m128i*)(w2 + t - 15))),
                s1_128(_mm_srli_si128(t1, 8))
            ));

        w128[t64] = t1 = _mm_add_epi32(t2, s1_128(_mm_slli_si128(t2, 8)));
        ++t64;
    }

    for (t = 16; t < 64; t += 4)
    {
        uint32_t r1 = w1[t - 16] + w1[t - 7];
        uint32_t r2 = s0(w1[t - 15]);
        uint32_t r3 = s1(w1[t - 2]);
        w1[t] = r1 + r2 + r3;
        //w1[t] = w1[t - 16] + s0(w1[t - 15]) + w1[t - 7] + s1(w1[t - 2]);

        //w1[t + 1] = w1[t - 15] + s0(w1[t - 14]) + w1[t - 6] + s1(w1[t - 1]);
        r1 = w1[t - 15] + w1[t - 6];
        r2 = s0(w1[t - 14]);
        r3 = s1(w1[t - 1]);
        w1[t + 1] = r1 + r2 + r3;

        //w1[t + 2] = w1[t - 14] + s0(w1[t - 13]) + w1[t - 5] + s1(w1[t]);
        r1 = w1[t - 14] + w1[t - 5];
        r2 = s0(w1[t - 13]);
        r3 = s1(w1[t]);
        w1[t + 2] = r1 + r2 + r3;

        //w1[t + 3] = w1[t - 13] + s0(w1[t - 12]) + w1[t - 4] + s1(w1[t + 1]);
        r1 = w1[t - 13] + w1[t - 4];
        r2 = s0(w1[t - 12]);
        r3 = s1(w1[t + 1]);
        w1[t + 3] = r1 + r2 + r3;
    }
    // ++t64;
    int res = 0;
    for (i = 0; i < 64; ++i)
    {
        if (w1[i] != w2[i])
        {
            printf("i = %d\n", i);
            res = 1;
        }

    }
    return res;

}



int test_AVX_sha256()
{
    int res = 0;
    uint8_t etalon_hash[2][32] = {
        { //""
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        },
        {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        }

    };
    uint8_t msg0[] = "";
    uint8_t msg1[] = "abc";
    uint8_t hash[32], hash1[32];
    AVX_sha256(hash, msg0, 0, 32);
    res = memcmp(hash, etalon_hash[0], 32);
    AVX_sha256_device(hash, msg0, 0, 32);
    res |= memcmp(hash, etalon_hash[0], 32);

    AVX_sha256(hash, msg1, 3, 32);
    res |= memcmp(hash, etalon_hash[1], 32);

    AVX_sha256_device(hash, msg1, 3, 32);
    res |= memcmp(hash, etalon_hash[1], 32);

    uint8_t msg[63];
    for (int i = 0; i < 63; ++i)
        msg[i] = i;
    AVX_sha256(hash, msg, 63, 32);
    AVX_sha256_device(hash1, msg, 63, 32);
    res |= memcmp(hash, hash1, 32);
    
    #define DATA_SIZE (1024 * 1024)
    static uint8_t datas[DATA_SIZE];
    uint8_t res1[32], res2[32];
    for (int i = 0; i < DATA_SIZE; ++i)
        datas[i] = rand() % 256;

#ifndef _DEBUG

    

    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif
        AVX_sha256_device(res1, datas, DATA_SIZE, 32);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("AVX_sha256_device time = %lld\n", min_tacts);
    // sha256(uint8_t *out, const uint8_t *in, size_t inlen)
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif
        sha256 (res2, datas, DATA_SIZE/*, 32*/);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("sha256 time = %lld\n", min_tacts);

    res = memcmp(res1, res2, 32);
#endif
    if (res == 0)
    {
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (int i = 0; i < 16; ++i)
        {
            tacts = __rdtsc();
#endif
            // AVX_sha256(buf + BLOCKSIZE, temp, BLOCKSIZE + len, 32);
            AVX_sha256 (res2, datas, DATA_SIZE, 32);
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("AVX_sha256 time = %lld\n", min_tacts);
        res = memcmp(res1, res2, 32);
#endif

    }
    return res;

}

int test_MGF1_AVX_sha256()
{
    uint8_t out1[1000], out2[1000], in[100];
    for (uint32_t i = 0; i < 100; ++i)
    {
        in[i] = i;
    }

    AVX_MGF1_sha256(out1, 1000, in, 100);
    AVX_MGF1_sha256_device(out2, 1000,
        in, 100);
    int res = memcmp(out1, out2, 1000);
    return res;
}

#if FIPS205_N == 16
int test_AVX_HMAC()
{


    uint8_t sk[16], src[100], dest1[16], dest2[16];
    for (uint32_t i = 0; i < 16; ++i)
        sk[i] = rand() % 256;
    for (uint32_t i = 0; i < sizeof(src); ++i)
        src[i] = rand() % 256;

    AVX_HMAC(dest1, sk, src, sizeof(src));
    AVX_HMAC_device(dest2, sk, FIPS205_N, src, sizeof(src));

    int res = memcmp(dest1, dest2, 16);
    return res;

}
#endif



//int test_AVX_sha256_WITH_PREDCALC8()
//{
//    uint8_t hash1[8][32];
//    uint8_t hash2[8][32];
//    uint32_t state1[8], state2[8]; 
//    uint8_t PK_seed[FIPS205_N];
//    
//     __declspec (align (32))
//        uint8_t in[8][64];
//     //__m256i blocks [64] ;
//     __m256i *in256 = (__m256i*)in;
//    // void AVX_SHA256_WITH_PREDCALC(uint8_t* hash, uint32_t *state, const uint8_t* in, uint32_t in_len, uint32_t out_len)
//    srand(0);
//    uint32_t i, j;
//    int res = 0;
//    for (i = 0; i < FIPS205_N; ++i)
//    {
//        PK_seed[i] = rand() % 256;
//    }
//
//    //__m256i AVX_predcalc_pk_256;
//    __m256i state1_[8]/*, state[8]*/;
//
//    AVX_sha256_predcalc_pk(state1, PK_seed);
//    AVX_sha256_predcalc_pk_(state1_, PK_seed);
//    AVX_sha256_device_predcalc_pk(state2, PK_seed, FIPS205_N);
//
//    
//    for (i = 0; i < 8; ++i)
//    {
//        if (state1[i] != state2[i])
//            res = 1;
//    }
//
//    for (i = 0; i < 8; ++i)
//        for (j = 0; j < FIPS205_N + ADR_SIZE; ++j)
//            in[i][j] = rand() % 256;
//    
//    int bits = (2 * FIPS205_N + ADR_SIZE) * 8;
//    for (i = 0; i < 8; ++i)
//    {
//        in[i][FIPS205_N + ADR_SIZE] = 0x80;
//        for (j = FIPS205_N + ADR_SIZE + 1; j < 64; ++j)
//            in[i][j] = 0;
//        in [i][61] = (uint8_t)(bits >> 16);
//        in [i][62] = (uint8_t)(bits >> 8);
//        in [i][63] = (uint8_t)bits;
//    }
//    
//    for (i = 0; i < 8; ++i)
//    {
//        in256[2 * i] = _mm256_shuffle_epi8(in256[2 * i], maska_for_shuffle_32);
//        in256[2 * i + 1] = _mm256_shuffle_epi8(in256[2 * i + 1], maska_for_shuffle_32);
//    }
//    /*create_blocks_for_in64(blocks, (__m256i*)in);
//    memcpy(state, state1_, sizeof(state));
//    AVX_sha256_compress8 ((__m256i*)state, in);*/
//    for (i = 0; i < 8; ++i)
//    {
//        memcpy(state1, state2, sizeof(state1));
//        //AVX_sha256_WITH_PREDCALC(state1, in[i]);
//        AVX_sha256_compress(state1, &in256[i]);
//        memcpy(hash1[i], state1, FIPS205_N);
//    }
//    
//    for (i = 0; i < 8; ++i)
//    {
//        memcpy(state1, state2, sizeof(state1));
//        AVX_sha256_device_compress(state1, in[i]);
//        memcpy(hash2[i], state1, FIPS205_N);
//    }
//    printf("");
//
////
////#ifndef _DEBUG
////    min_tacts = 0xFFFFFFFFFFFFFFFF;
////    for (i = 0; i < 256; ++i)
////    {
////
////        tacts = __rdtsc();
////#endif
////        AVX_sha256_WITH_PREDCALC8(hash2, state1, in);
////#ifndef _DEBUG
////        tacts = __rdtsc() - tacts;
////        if (tacts < min_tacts)
////            min_tacts = tacts;
////    }
////    printf("AVX_SHA256_WITH_PREDCALC8 time = %I64d\n", min_tacts);
////#endif
////
////
////    res = 0;
////    for (i = 0; i < 8; ++i)
////    {
////        for (j = 0; j < FIPS205_N; ++j)
////        {
////            if (hash2[i][j] != hash2[i][j])
////                res = 1;
////        }
////    }
////
////
////    /*
////    thashx8(unsigned char *out0,
////             unsigned char *out1,
////             unsigned char *out2,
////             unsigned char *out3,
////             unsigned char *out4,
////             unsigned char *out5,
////             unsigned char *out6,
////             unsigned char *out7,
////             const unsigned char *in0,
////             const unsigned char *in1,
////             const unsigned char *in2,
////             const unsigned char *in3,
////             const unsigned char *in4,
////             const unsigned char *in5,
////             const unsigned char *in6,
////             const unsigned char *in7, unsigned int inblocks,
////             const unsigned char *pub_seed, uint32_t addrx8[8*8])
////
////    */
////
////    uint8_t pk[FIPS205_N];
////    uint32_t addrx8[8 * 8];
////    for (int i = 0; i < 8; ++i)
////        for (int j = 0; j < 8; ++j)
////            addrx8[i * 8 + j] = rand32();
////    for (int i = 0; i < FIPS205_N; ++i)
////        pk[i] = rand() % 256;
////
////#ifndef _DEBUG
////    min_tacts = 0xFFFFFFFFFFFFFFFF;
////    for (i = 0; i < 256; ++i)
////    {
////
////        tacts = __rdtsc();
////#endif
////        thashx8(
////            hash2[0],
////            hash2[1],
////            hash2[2],
////            hash2[3],
////            hash2[4],
////            hash2[5],
////            hash2[6],
////            hash2[7],
////
////            in[0],
////            in[1],
////            in[2],
////            in[3],
////            in[4],
////            in[5],
////            in[6],
////            in[7],
////            2,
////            pk,
////            addrx8);
////
////#ifndef _DEBUG
////        tacts = __rdtsc() - tacts;
////        if (tacts < min_tacts)
////            min_tacts = tacts;
////    }
////    printf("thashx8 time = %I64d\n", min_tacts);
////#endif
//    return res;
//}
///////////////////////////////////////////////////////////////////
/////////////////////////512///////////////////////////////////////
//int test_fun_256()
//{
//    __declspec (align(64)) uint64_t a[4], res1[4], res2[4];
//    __declspec (align(64)) uint64_t w[64];
//
//    __m256i* a256 = (__m256i*)a;
//    __m256i* res1_256 = (__m256i*)res1;
//    __m256i* res2_256 = (__m256i*)res2;
//
//    srand(0);
//    int res = 0;
//    for (int i = 0; i < 256; ++i)
//    {
//
//        for (int j = 0; j < 16; ++j)
//            w[j] = rand64();
//        for (int j = 0; j < 4; ++j)
//            a[j] = rand64();
//
//        for (int j = 0; j < 4; ++j)
//        {
//            res1[j] = ROR64(a[j], 14);
//
//        }
//
//        //*res2_256 = ROR64_256 (*a256, n14, n14_);
//        /*temp1 = _mm256_srl_epi64(*a256, n14);
//        temp2 = _mm256_srl_epi64(*a256, n14_);
//        *res2_256 = _mm256_or_si256(_mm256_srl_epi64(*a256, n14), _mm256_srl_epi64(*a256, n14_));*/
//        *res2_256 = ROR64_256(*a256, n39, n39_);
//
//        res |= memcmp(res1, res2, 32);
//        if (res)
//        {
//            printf("ROR64 and ROTR_256 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//        for (int j = 0; j < 4; ++j)
//        {
//            res1[j] = SHR64(a[j], 6);
//        }
//
//        *res2_256 = SHR64_256(*a256, 6);
//
//        res = memcmp(res1, res2, 32);
//        if (res)
//        {
//            printf("SHR64 and SHR64_256 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//        for (int j = 0; j < 4; ++j)
//            res1[j] = s1(a[j]);
//        *res2_256 = s1_256(*a256);
//
//        res = memcmp(res1, res2, 16);
//        if (res)
//        {
//            printf("s1 and s1_128 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//        for (int j = 0; j < 4; ++j)
//            res1[j] = s0(a[j]);
//        *res2_256 = s0_256(*a256);
//        res = memcmp(res1, res2, 16);
//        if (res)
//        {
//            printf("s0 and s0_128 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//
//        for (int j = 0; j < 4; ++j)
//            res1[j] = S1(a[j]);
//        *res2_256 = S1_256(*a256);
//        res = memcmp(res1, res2, 16);
//        if (res)
//        {
//            printf("S1 and S1_128 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//        for (int j = 0; j < 4; ++j)
//            res1[j] = S0(a[j]);
//        *res2_256 = S0_256(*a256);
//        res = memcmp(res1, res2, 16);
//        if (res)
//        {
//            printf("S0 and S0_128 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//        //ch_128(e, f, g)
//        uint64_t e = 1, f = 2, g = 3;
//        __m256i e256 = _mm256_set1_epi64x(e);
//        __m256i f256 = _mm256_set1_epi64x(f);
//        __m256i g256 = _mm256_set1_epi64x(g);
//        for (int i = 0; i < 4; ++i)
//            res1[i] = ch(e, f, g);
//        *res2_256 = ch_256(e256, f256, g256);
//        res = memcmp(res1, res2, 32);
//        if (res)
//        {
//            printf("ch and ch_256 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//        // maj_256(a, b, c)
//        for (int i = 0; i < 4; ++i)
//            res1[i] = maj(e, f, g);
//        *res2_256 = maj_256(e256, f256, g256);
//
//        res = memcmp(res1, res2, 16);
//        if (res)
//        {
//            printf("maj and maj_256 ? %s\n", res == 0 ? "OK" : "ERROR");
//            break;
//        }
//
//
//
//
//
//    }
//    return res;
//
//}
//

int test_AVX_HMAC512()
{
    uint8_t dest1[FIPS205_N], dest2[FIPS205_N];
    uint8_t sk[FIPS205_N];
    uint32_t sk_len = FIPS205_N, dest_len = FIPS205_N, src_len, i;
    uint8_t* src;
    srand(0);
    src_len = rand() + 1;
    src = malloc(src_len);
    for (i = 0; i < src_len; ++i)
        src[i] = rand();

    for (i = 0; i < sk_len; ++i)
        sk[i] = rand() % 256;
    HMAC512(dest1, (const uint8_t*)sk, /*sk_len, */(const uint8_t*)src, src_len/*, FIPS205_N*/);
    AVX_HMAC512(dest2, sk, sk_len, src, src_len, FIPS205_N);
    int res = memcmp(dest1, dest2, FIPS205_N);
    return res;


}

int test_AVX_sha512()
{
    uint8_t in[] = "abc";
    uint8_t h1[64], h2[64];
    sha512(h1, in, 3);
    AVX_sha512(h2, in, 3, 64);
    int res = memcmp(h1, h2, 64);
    return res;

}

#if FIPS205_N != 16
int test_AVX_sha512_compress4()
{
    int res, i, j;
    //__m256i state_256[8];
    __m256i block_256_1[80], block_256_2[80];
    __m256i in256[4];

    __m256i datas[4][4] = { 0 };
    uint8_t* p[4] = { (uint8_t*)datas[0], (uint8_t*)datas[1], (uint8_t*)datas[2], (uint8_t*)datas[3] };

    uint8_t adr[22] = { 0 };
    uint8_t node1[4][FIPS205_N], node2[4][FIPS205_N];


    for (j = 0; j < 4; ++j)
    {
        for (int i = 0; i < FIPS205_N; ++i)
        {
            node1[j][i] = rand() % 256;
            node2[j][i] = rand() % 256;
        }
    }
    setTreeHeight(adr, 1);
    setType1(adr, FORS_TREE);
    setHashAddress(adr, 2);

    memcpy(datas[0], adr, ADR_SIZE);
    memcpy(datas[1], adr, ADR_SIZE);
    memcpy(datas[2], adr, ADR_SIZE);
    memcpy(datas[3], adr, ADR_SIZE);
    uint32_t bytes = ADR_SIZE + 128 + 2 * FIPS205_N;
    for (j = 0; j < 4; ++j)
    {
        memcpy(p[j] + ADR_SIZE, node1[j], FIPS205_N);
        memcpy(p[j] + ADR_SIZE + FIPS205_N, node2[j], FIPS205_N);
        p[j][ADR_SIZE + 2 * FIPS205_N] = 0x80;
        for (i = ADR_SIZE + 2 * FIPS205_N + 1; i < 125; ++i)
            p[j][i] = 0;
        p[j][125] = bytes >> 13;
        p[j][126] = (uint8_t)(bytes >> 5);
        p[j][127] = (uint8_t)(bytes << 3);
    }

    for (j = 0; j < 4; ++j)
    {
        for (i = 0; i < 4; ++i)
            datas[j][i] = _mm256_shuffle_epi8(datas[j][i], maska_for_shuffle_64);
    }
    uint64_t* p64 = (uint64_t*)datas;
    uint64_t* pdatas = (uint64_t*)datas;

    for (i = 0; i < 16; ++i)
    {
#ifdef _MSC_VER
        block_256_1[i].m256i_u64[0] = pdatas[0];
        block_256_1[i].m256i_u64[1] = pdatas[16];
        block_256_1[i].m256i_u64[2] = pdatas[32];
        block_256_1[i].m256i_u64[3] = pdatas[48];
        //block_256_1[i] = _mm256_setr_epi64x(pdatas, pdatas + 16, pdatas + 32, pdatas + 48);

        pdatas++;
#else
        block_256_1[i] = _mm256_set_epi64x(
            pdatas[48],
            pdatas[32],
            pdatas[16],
            pdatas[0]);
        //block_256_1[i] = _mm256_setr_epi64x(pdatas, pdatas + 16, pdatas + 32, pdatas + 48);

        pdatas++;
#endif

    }

    //block_256_1[i] = _mm256_i32gather_epi64((const long long*)p64, _mm_setr_epi32(0, 16, 32, 48), 8);
//++p64;

///////////////////////////////////////////////
    FIPS205_AVX_fors_init_in_block0(in256, adr);
    __m256i blocks[80];
    create_blocks_for_in128(blocks, in256);
    printf("");
    __m256i temp_node1[4] = { 0 }, temp_node1_[4];
    __m256i temp_node2[4] = { 0 }, temp_node2_[4];

    //uint8_t* temp8[4] = { temp[0], temp[1], temp[2], temp[3] };
    for (j = 0; j < 4; ++j)
    {
        memcpy(&temp_node1[j], node1[j], FIPS205_N);
        memcpy(&temp_node2[j], node2[j], FIPS205_N);
        temp_node1[j] = _mm256_shuffle_epi8(temp_node1[j], maska_for_shuffle_64);
        temp_node2[j] = _mm256_shuffle_epi8(temp_node2[j], maska_for_shuffle_64);
    }

#ifdef _MSC_VER
    temp_node1_[0] = _mm256_setr_epi64x(temp_node1[0].m256i_i64[0], temp_node1[1].m256i_i64[0], temp_node1[2].m256i_i64[0], temp_node1[3].m256i_i64[0]);
    temp_node1_[1] = _mm256_setr_epi64x(temp_node1[0].m256i_i64[1], temp_node1[1].m256i_i64[1], temp_node1[2].m256i_i64[1], temp_node1[3].m256i_i64[1]);
    temp_node1_[2] = _mm256_setr_epi64x(temp_node1[0].m256i_i64[2], temp_node1[1].m256i_i64[2], temp_node1[2].m256i_i64[2], temp_node1[3].m256i_i64[2]);
    temp_node1_[3] = _mm256_setr_epi64x(temp_node1[0].m256i_i64[3], temp_node1[1].m256i_i64[3], temp_node1[2].m256i_i64[3], temp_node1[3].m256i_i64[3]);

    temp_node2_[0] = _mm256_setr_epi64x(temp_node2[0].m256i_i64[0], temp_node2[1].m256i_i64[0], temp_node2[2].m256i_i64[0], temp_node2[3].m256i_i64[0]);
    temp_node2_[1] = _mm256_setr_epi64x(temp_node2[0].m256i_i64[1], temp_node2[1].m256i_i64[1], temp_node2[2].m256i_i64[1], temp_node2[3].m256i_i64[1]);
    temp_node2_[2] = _mm256_setr_epi64x(temp_node2[0].m256i_i64[2], temp_node2[1].m256i_i64[2], temp_node2[2].m256i_i64[2], temp_node2[3].m256i_i64[2]);
    temp_node2_[3] = _mm256_setr_epi64x(temp_node2[0].m256i_i64[3], temp_node2[1].m256i_i64[3], temp_node2[2].m256i_i64[3], temp_node2[3].m256i_i64[3]);
#else
    int64_t* p0 = (int64_t*)&temp_node1[0];
    int64_t* p1 = (int64_t*)&temp_node1[1];
    int64_t* p2 = (int64_t*)&temp_node1[2];
    int64_t* p3 = (int64_t*)&temp_node1[3];

    temp_node1_[0] = _mm256_setr_epi64x(p0[0], p1[0], p2[0], p3[0]);
    temp_node1_[1] = _mm256_setr_epi64x(p0[1], p1[1], p2[1], p3[1]);
    temp_node1_[2] = _mm256_setr_epi64x(p0[2], p1[2], p2[2], p3[2]);
    temp_node1_[3] = _mm256_setr_epi64x(p0[3], p1[3], p2[3], p3[3]);

    // Same for temp_node2_
    int64_t* q0 = (int64_t*)&temp_node2[0];
    int64_t* q1 = (int64_t*)&temp_node2[1];
    int64_t* q2 = (int64_t*)&temp_node2[2];
    int64_t* q3 = (int64_t*)&temp_node2[3];

    temp_node2_[0] = _mm256_setr_epi64x(q0[0], q1[0], q2[0], q3[0]);
    temp_node2_[1] = _mm256_setr_epi64x(q0[1], q1[1], q2[1], q3[1]);
    temp_node2_[2] = _mm256_setr_epi64x(q0[2], q1[2], q2[2], q3[2]);
    temp_node2_[3] = _mm256_setr_epi64x(q0[3], q1[3], q2[3], q3[3]);
#endif

    FIPS205_AVX_fors_init_in_block0(datas[0], adr);

    create_blocks_for_in128(block_256_2, datas[0]);

    AVX_fors_replace_blocks_keys4__(block_256_2, temp_node1_, temp_node2_);

    res = 0;
    for (i = 0; i < 16; ++i)
    {
#ifdef _MSC_VER
#else
        int64_t* p1 = (int64_t*)&block_256_1[i];
        int64_t* p2 = (int64_t*)&block_256_2[i];
#endif
        for (j = 0; j < 4; ++j)
        {
#ifdef _MSC_VER
            if (block_256_1[i].m256i_i64[j] != block_256_2[i].m256i_i64[j])
                res = 1;
#else
            if (p1[j] != p2[j])
                res = 1;
#endif
        }

    }
    printf("");

    // convert data32 to data64;

    ALIGN32 uint8_t data32[8][32] = { 0 };
    res = 0;

    __m256i data32_inv[8], blocks_data32[8], * data32_256 = (__m256i*)data32;
    for (i = 0; i < 8; ++i)
    {
        for (j = 0; j < FIPS205_N; ++j)
        {
            data32[i][j] = rand() % 256;
        }
    }

    for (i = 0; i < 8; ++i)
    {
        data32_inv[i] = _mm256_shuffle_epi8(data32_256[i], maska_for_shuffle_32);
    }

    for (i = 0; i < 8; ++i)
    {
#ifdef _MSC_VER
#else
        uint32_t* dest = (uint32_t*)&blocks_data32[i];
#endif
        for (j = 0; j < 8; ++j)
        {
#ifdef _MSC_VER
            blocks_data32[i].m256i_i32[j] = data32_inv[j].m256i_u32[i];
#else
            uint32_t* src = (uint32_t*)&data32_inv[j];
            dest[j] = src[i];
#endif
        }
    }

    uint8_t data64[2][4][FIPS205_N] = { 0 };
    __m256i data64_inv[2][4], blocks_data64[2][4], blocks_data64_[2][4];

    for (i = 0; i < 4; ++i)
    {
        data64_inv[0][i] = _mm256_shuffle_epi8(data32_256[i], maska_for_shuffle_64);
        data64_inv[1][i] = _mm256_shuffle_epi8(data32_256[i + 4], maska_for_shuffle_64);
    }

    for (i = 0; i < 4; ++i)
    {
#ifdef _MSC_VER
#else
        uint64_t* dest0 = (uint64_t*)&blocks_data64[0][i];
#endif
        for (j = 0; j < 4; ++j)
        {
#ifdef _MSC_VER
            blocks_data64[0][i].m256i_u64[j] = data64_inv[0][j].m256i_u64[i];
#else
            uint64_t* src0 = (uint64_t*)&data64_inv[0][j];
            dest0[j] = src0[i];
#endif
        }
#ifdef _MSC_VER
#else
        uint64_t* dest1 = (uint64_t*)&blocks_data64[1][i];
#endif
        for (j = 0; j < 4; ++j)
        {
#ifdef _MSC_VER
            blocks_data64[1][i].m256i_u64[j] = data64_inv[1][j].m256i_u64[i];
#else
            uint64_t* src1 = (uint64_t*)&data64_inv[1][j];
            dest1[j] = src1[i];
#endif
        }
    }

    convert_32_64(blocks_data64_, blocks_data32);
    for (i = 0; i < 2; ++i)
    {
#ifdef _MSC_VER
#else
        uint64_t* p1 = (uint64_t*)blocks_data64[i];
        uint64_t* p2 = (uint64_t*)blocks_data64_[i];
#endif
        for (j = 0; j < 4; ++j)
        {
#ifdef _MSC_VER
            if (blocks_data64[i]->m256i_u64[j] != blocks_data64_[i]->m256i_u64[j])
                res = 1;
#else
            if (p1[j] != p2[j])
                res = 1;
#endif
        }
    }


    return res;
}

int test_AVX_MGF1_sha512()
{
    int res = 0;


    if (FIPS205_N > 16)
    {
        uint8_t PK_seed[FIPS205_N], R[FIPS205_N], Msg[64], in[2 * FIPS205_N + 64];
        for (int i = 0; i < FIPS205_N; ++i)
        {
            PK_seed[i] = rand() % 8;
            R[i] = rand() % 8;
        }

        for (int i = 0; i < 64; ++i)
        {
            Msg[i] = rand() % 8;
        }
        memcpy(in, R, FIPS205_N);
        memcpy(in + FIPS205_N, PK_seed, FIPS205_N);
        memcpy(in + 2 * FIPS205_N, Msg, 64);

        uint8_t out1[FIPS205_M], out2[FIPS205_M];

        MGF1_sha512(
            out1,
            FIPS205_M,
            in,
            sizeof(in));

        AVX_MGF1_sha512(
            out2,
            FIPS205_M,
            in,
            sizeof(in));
        for (int i = 0; i < FIPS205_M; ++i)
        {
            if (out1[i] != out2[i])
                res = 1;
        }
    }

    return res;
}

int test_AVX_sha512_WITH_PREDCALC4()
{
    int res = 0;
    uint8_t PK_seed[FIPS205_N], M[4][2 * FIPS205_N], adr[4][ADR_SIZE];
    uint8_t h1[4][FIPS205_N], h2[4][FIPS205_N];
    for (int i = 0; i < FIPS205_N; ++i)
        PK_seed[i] = rand() % 8;
    for (int j = 0; j < 4; ++j)
        for (int i = 0; i < 2 * FIPS205_N; ++i)
            M[j][i] = rand() % 8;
    for (int j = 0; j < 4; ++j)
        for (int i = 0; i < ADR_SIZE; ++i)
            adr[j][i] = rand() % 8;
    uint64_t state[8];
    AVX_sha512_predcalc_pk (state, PK_seed/*, FIPS205_N*/);
    uint8_t in[4][ADR_SIZE + 2 * FIPS205_N];
    for (int j = 0; j < 4; ++j)
    {
        memcpy(in[j], adr[j], ADR_SIZE);
        memcpy(in[j] + ADR_SIZE, M[j], 2 * FIPS205_N);
    }
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 256; ++i)
    {
        tacts = __rdtsc();
#endif
        for (int j = 0; j < 4; ++j)
            AVX_sha512_WITH_PREDCALC(h1[j], state, in[j], ADR_SIZE + 2 * FIPS205_N, FIPS205_N);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("AVX_sha512_WITH_PREDCALC time = %I64d\n", min_tacts);
#endif
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 256; ++i)
    {
        tacts = __rdtsc();
#endif
        AVX_sha512_WITH_PREDCALC4(h2, state, in);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("AVX_sha512_WITH_PREDCALC4 time = %I64d\n", min_tacts);
#endif
    res = memcmp(h1, h2, sizeof(h1));
    return res;
}
#endif

/////////////////////////////////////////////Hashs//////////////////////
int test_AVX_F()
{
    int res = 0;
    uint8_t PK_seed[FIPS205_N], Msg8[8][FIPS205_N];
    uint8_t hash_value1[8][FIPS205_N], hash_value2[8][FIPS205_N];
    uint8_t Adr8[8][22];
    srand(0);
    for (int i = 0; i < FIPS205_N; ++i)
    {
        PK_seed[i] = rand() % 256;
    }

    for (int j = 0; j < 8; ++j)
    {
        for (int i = 0; i < FIPS205_N; ++i)
            Msg8[j][i] = rand() % 256;
        for (int i = 0; i < 22; ++i)
            Adr8[j][i] = rand() % 256;
    }
    uint32_t PK_seed_[32];


    AVX_sha256_predcalc_pk(PK_seed_, PK_seed/*, FIPS205_N*/);

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif
        for (int j = 0; j < 8; ++j)
        {
            AVX_F(hash_value1[j], PK_seed_, Adr8[j], Msg8[j]);
        }
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (min_tacts > tacts)
            min_tacts = tacts;
    }
    printf("AVX_F time = %I64d\n", min_tacts);

#endif


#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif
        thashx8(
            hash_value2[0],
            hash_value2[1],
            hash_value2[2],
            hash_value2[3],
            hash_value2[4],
            hash_value2[5],
            hash_value2[6],
            hash_value2[7],

            Msg8[0],
            Msg8[1],
            Msg8[2],
            Msg8[3],
            Msg8[4],
            Msg8[5],
            Msg8[6],
            Msg8[7],
            2,
            PK_seed,
            (uint32_t*)Adr8);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (min_tacts > tacts)
            min_tacts = tacts;
    }
    printf("thashx8 time = %I64d\n", min_tacts);

#endif

    return res;
}

int test_AVX_HASH()
{
    // void AVX_HASH(uint8_t* hash_value, const void* PK_seed_, uint8_t* Adr, const uint8_t Msg[][FIPS205_N])
    int res = 0;
    uint8_t PK_seed_[FIPS205_N], Adr[ADR_SIZE], Msg[2][FIPS205_N];
    //uint8_t in[3 * FIPS205_N + ADR_SIZE];
    uint8_t out1[FIPS205_N], out2[FIPS205_N];
    for (int i = 0; i < FIPS205_N; ++i)
    {
        PK_seed_[i] = rand() % 8;
        Msg[0][i] = rand() % 8;
        Msg[1][i] = rand() % 8;
    }
    for (int i = 0; i < ADR_SIZE; ++i)
        Adr[i] = rand() % 8;

    HASH(out1, PK_seed_, Adr, Msg);
    
        
#if FIPS205_N == 16
        uint32_t state[8];
#else
        uint64_t state[8];
#endif
    AVX_PREDCALC_VALUE(state, PK_seed_, FIPS205_N);
    AVX_HASH(out2, state, Adr, Msg);
    for (int i = 0; i < FIPS205_N; ++i)
        if (out1[i] != out2[i])
            res = 1;
    return res;
}

int test_AVX_HMsg()
{
    /*
    void HMsg(
    uint8_t* dest,
    const uint8_t* R,
    const uint8_t* PK,
    const uint8_t* msg,
    uint32_t m_len,
    uint8_t* buf)
    */
    uint8_t R[FIPS205_N], PK[2 * FIPS205_N];
    uint8_t Msg[1000];
    uint8_t buf[FIPS205_N + 2 * FIPS205_N + sizeof(Msg)];
    uint8_t out1[FIPS205_M], out2[FIPS205_M];
    for (int i = 0; i < FIPS205_N; ++i)
    {
        R[i] = rand() % 256;
        PK[i] = rand() % 256;
        PK[i + FIPS205_N] = rand() % 256;

    }
    for (int i = 0; i < sizeof(Msg); ++i)
    {
        Msg[i] = rand() % 256;

    }
    /*memcpy(buf, R, FIPS205_N);
    memcpy(buf + FIPS205_N, PK, 2 * FIPS205_N);
    memcpy(buf + FIPS205_N, PK, 2 * FIPS205_N);*/

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif

        HMsg(out1, R, PK, Msg, sizeof(Msg), buf);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("HMsg time = %I64d\n", min_tacts);
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif

    AVX_HMsg(out2, R, PK, Msg, sizeof(Msg), buf);
#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
}
    printf("AVX_HMsg time = %I64d\n", min_tacts);
#endif
    int res = 0;
    for (int i = 0; i < FIPS205_M; ++i)
    {
        if (out1[i] != out2[i])
            res = 1;
    }
        
    return res;



}
int test_AVX_PRFmsg ()
{
    // void PRFmsg(uint8_t* dest, const uint8_t* SK_prf, const uint8_t* optrand, const uint8_t* m, uint32_t mlen)
    uint8_t SK_prf[FIPS205_N], optrand[FIPS205_N];
    uint8_t m[1000];
    uint32_t mlen = sizeof(m);
#if FIPS205_N == 16
    uint8_t out1[FIPS205_N];
#endif
    uint8_t out2[FIPS205_N];
    for (int i = 0; i < FIPS205_N; ++i)
    {
        SK_prf[i] = rand() % 256;
        optrand [i] = rand() % 256;
    }

    for (uint32_t i = 0; i < mlen; ++i)
    {
        m[i] = rand() % 256;
        
    }
#if FIPS205_N == 16
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif

        PRFmsg(out1, SK_prf, optrand, m, mlen);

#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("PRFmsg time = %I64d\n", min_tacts);
#endif
#endif
    int res = 0;
    uint8_t* buf = malloc(FIPS205_N + sizeof(m));
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif
    //res = AVXPRFmsg(out2, SK_prf, optrand, m, mlen);
        
    AVX_PRFmsg(out2, SK_prf, optrand, m, mlen, buf);
    
#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
    }
    printf("AVX_PRFmsg time = %I64d\n", min_tacts);
#endif
#if FIPS205_N == 16
    //if (res == 0)
    {
        for (int i = 0; i < FIPS205_N; ++i)
            if (out1[i] != out2[i])
                res = 1;
    }
#endif
    return res;

}


//void Tl(uint8_t* hash_value, const uint8_t* PK_seed, uint8_t* Adr, const uint8_t Msg[][FIPS205_N], uint32_t len, uint8_t* buf)
int test_Tl()
{
    uint8_t PK_seed[FIPS205_N];
    uint8_t Adr[ADR_SIZE];
    uint8_t Msg1[FIPS205_LEN][FIPS205_N];
    uint8_t Msg2[FIPS205_K][FIPS205_N];
    uint8_t hash_value1[FIPS205_N], hash_value2[FIPS205_N];

    __m256i keys1[FIPS205_LEN] = {0};
    __m256i keys2[FIPS205_K] = {0};
    // void AVX_Tl(uint8_t* out, void* predcalc_pk, uint8_t adr[], __m256i* keys, uint32_t keys_count)
    for (int i = 0; i < FIPS205_N; ++i)
    {
        PK_seed[i] = rand() % 256;
       
        
    }

    for (int i = 0; i < ADR_SIZE; ++i)
    {
        
            Adr[i] = rand() % 256;

    }

    for (int j = 0; j < FIPS205_LEN; ++j)
    {
        for (int i = 0; i < FIPS205_N; ++i)
        {
            Msg1[j][i] = rand() % 256;
        }

        for (int i = 0; i < FIPS205_N; ++i)
        {
#ifdef _MSC_VER
            keys1[j].m256i_i8[i] = Msg1[j][i];
#else
            ((uint8_t*)&keys1[j])[i] = Msg1[j][i];
#endif
        }

    }
    for (int j = 0; j < FIPS205_K; ++j)
    {
        for (int i = 0; i < FIPS205_N; ++i)
        {
            Msg2[j][i] = rand() % 256;
        }
        for (int i = 0; i < FIPS205_N; ++i)
        {
#ifdef _MSC_VER
            keys2[j].m256i_i8[i] = Msg2[j][i];
#else
            ((uint8_t*)&keys2[j])[i] = Msg2[j][i];
#endif
        }
    }

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
        tacts = __rdtsc();
#endif    
    Tl(hash_value1, PK_seed, Adr, Msg1, FIPS205_LEN);

#ifndef _DEBUG

    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
}
    printf("Tl (%d) time = %I64d\n ", FIPS205_LEN, min_tacts);
#endif

#if FIPS205_N == 16
    uint32_t state[8];
#else
    uint64_t state[8];
#endif
    
    AVX_PREDCALC_VALUE(state, PK_seed, FIPS205_N);
    
    //AVX_Tl(hash_value2, state, Adr, Msg1, FIPS205_LEN);

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
        tacts = __rdtsc();
#endif    
    AVX_Tl(hash_value2, state, Adr, keys1, FIPS205_LEN);
    
#ifndef _DEBUG

    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
}
    printf("AVX_Tl (%d) time = %I64d\n ", FIPS205_LEN, min_tacts);
#endif
    int res = 0;
    
    for (int i = 0; i < FIPS205_N; ++i)
    {
        if (hash_value1[i] != hash_value2[i])
            res = 1;
    }
    
    if (res == 0)
    {
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (int k = 0; k < 16; ++k)
        {
            tacts = __rdtsc();
#endif    
        Tl(hash_value1, PK_seed, Adr, Msg2, FIPS205_K);
#ifndef _DEBUG

        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
        printf("Tl (%d) time = %I64d\n ", FIPS205_K, min_tacts);
#endif
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (int k = 0; k < 256; ++k)
        {
            tacts = __rdtsc();
#endif    
        AVX_Tl(hash_value2, state, Adr, keys2, FIPS205_K);
#ifndef _DEBUG

        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
        printf("AVX_Tl (%d) time = %I64d\n ", FIPS205_K, min_tacts);
#endif
        for (int i = 0; i < FIPS205_N; ++i)
        {
            if (hash_value1[i] != hash_value2[i])
                res = 1;
        }
    }
    return res;




}


//void AVX_PREDCALC_W_sha512_(uint8_t* out, const uint64_t* pk, const uint8_t* in, uint32_t in_len, uint32_t out_len)
int test_AVX_PREDCALC_W_sha()
{
    int res = 0;
    uint8_t temp_hash[64];
    uint8_t pk[FIPS205_N];
    uint8_t Adr[ADR_SIZE];
    uint8_t Msg[FIPS205_LEN][FIPS205_N];
    uint8_t out1[FIPS205_N];
#if FIPS205_N != 16
    uint8_t out2[FIPS205_N];
#else
    uint8_t out2[FIPS205_N];
#endif

    for (int i = 0; i < FIPS205_N; ++i)
        pk[i] = rand() % 256;
    for (int i = 0; i < ADR_SIZE; ++i)
        Adr[i] = rand() % 256;
    for (int j = 0; j < FIPS205_LEN; ++j)
        for (int i = 0; i < FIPS205_N; ++i)
            Msg[j][i] = rand() % 256;
#ifndef SHAKE
#if (FIPS205_N == 16)
#define HASH_BLOCK  64
    uint32_t calc_pk[8];
    //predcalc_pk_sha256(calc_pk, pk);
    AVX_sha256_predcalc_pk(calc_pk, pk);
#else
#define HASH_BLOCK  128
    uint64_t calc_pk[8];
    //predcalc_pk_sha512(calc_pk, pk);
    AVX_sha512_predcalc_pk(calc_pk, pk);

#endif
    uint8_t temp[HASH_BLOCK + ADR_SIZE + FIPS205_LEN * FIPS205_N];
    memcpy(temp, pk, FIPS205_N);
    memset(temp + FIPS205_N, 0, HASH_BLOCK - FIPS205_N);
    memcpy(temp + HASH_BLOCK, Adr, ADR_SIZE);
    uint8_t* cur = temp + (HASH_BLOCK + ADR_SIZE);
    for (int i = 0; i < FIPS205_LEN; ++i)
    {
        memcpy(cur, Msg[i], FIPS205_N);
        cur += FIPS205_N;
    }
    uint32_t cur_len = sizeof(temp);
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 16; ++i)
    {
        tacts = __rdtsc();
#endif
        sha512(temp_hash, temp, sizeof(temp));
        memcpy(out1, temp_hash, FIPS205_N);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("time sha512 = %I64d\n", min_tacts);

    //int res = 0;
#endif
#if FIPS205_N > 16
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 256; ++i)
    {
        tacts = __rdtsc();
#endif
    
    AVX_PREDCALC_sha512(out2, calc_pk, temp + HASH_BLOCK, cur_len - HASH_BLOCK, FIPS205_N);
#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
}
    printf("AVX_PREDCALC_sha512 = %I64d\n", min_tacts);

#endif

    
    for (int i = 0; i < FIPS205_N; ++i)
    {
        if (out1[i] != out2[i])
            res = 1;
    }
    
    if (res == 1)
        printf("sha512 and AVX_PREDCALC_sha512 : res = %s\n", res == 0 ? "OK" : "ERROR");


#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int i = 0; i < 256; ++i)
    {
        tacts = __rdtsc();
#endif

    AVX_PREDCALC_W_sha512_(out2, calc_pk, temp + HASH_BLOCK, cur_len - HASH_BLOCK, FIPS205_N);

#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
}
    printf("AVX_PREDCALC_W_sha512_ = %I64d\n", min_tacts);
#endif

    res = 0;
    for (int i = 0; i < FIPS205_N; ++i)
    {
        if (out1[i] != out2[i])
            res = 1;
    }

    if (res == 1)
        printf("sha512 and AVX_PREDCALC_W_sha512_ : res = %s\n", res == 0 ? "OK" : "ERROR");
#endif
#endif
    return res;
        


}
/////////////////////////////////
////WOTS///////////////////

int test_wots_gensk_and_pk()
{
    int res = 0;
    uint8_t adr32[32] = { 0 };
    //FIPS205_wots_genpk(uint8_t * pk, const uint8_t * SK_seed, const void* PK_seed, uint8_t * Adr)
    uint8_t SK_seed[FIPS205_N], PK_seed[FIPS205_N];
    uint8_t Adr[ADR_SIZE] = { 0 };
    srand(0);
    for (int i = 0; i < FIPS205_N; ++i)
    {
        SK_seed[i] = rand() % 256;
        PK_seed[i] = rand() % 256;
    }
    for (int i = 0; i < 13; ++i)
        Adr[i] = rand() % 256;
    setType(Adr, WOTS_HASH);
    //uint8_t adr[ADR_SIZE];

    uint32_t predcalc_pk[8];
    __m256i predcalc_block[8];
    
    adr32[3] = Adr[0];
    memcpy(adr32 + 8, Adr + 1, 8);
    adr32[19] = Adr[9];
    memcpy(adr32 + 20, Adr + 10, 12);


    AVX_sha256_predcalc_pk(predcalc_pk, PK_seed);
    AVX_sha256_predcalc_pk_(predcalc_block, PK_seed);
#if FIPS205_N != 16
    uint64_t predcalc_pk64[8];
    __m256i predcalc_block512[8];
    AVX_sha512_predcalc_pk(predcalc_pk64, PK_seed);
    AVX_sha512_predcalc_pk_(predcalc_block512, PK_seed);
#endif

    return res;
}

int test_base_2b()
{
    int res = 0;
    uint8_t X[FIPS205_N];
    for (int i = 0; i < FIPS205_N; ++i)
    {
        X[i] = rand() % 256;
    }
    uint32_t values1[FIPS205_N * 2], values2[FIPS205_N * 2];
    base_2b_old(values1, X, 4, FIPS205_N * 2);
    base_4_new(values2, X, FIPS205_N * 2);
    res = memcmp(values1, values2, sizeof(values1));
    return res;
}

int test_replace_key()
{
    
    __m256i new_key;
    uint8_t* new_key8 = (uint8_t*)&new_key;
    int res = 0;
    uint8_t adr[ADR_SIZE], key [FIPS205_N];
    for (int i = 0; i < ADR_SIZE; ++i)
        adr[i] = 0;
    for (int i = 0; i < FIPS205_N; ++i)
    {
        key[i] = i + 0x20;
        new_key8 [i] = i + 0x40;
    }
    __m256i dest_[2];
    uint8_t* dest8 = (uint8_t*)dest_;
    
    memcpy(dest8, adr, ADR_SIZE);
    memcpy(dest8 + ADR_SIZE, key, FIPS205_N);
    dest8[ADR_SIZE + FIPS205_N] = 0x80;

    uint32_t bytes = 64 + ADR_SIZE + FIPS205_N;
    uint32_t zero_count = 64 - (ADR_SIZE + FIPS205_N + 1) - 3;
    memset(dest8 + ADR_SIZE + FIPS205_N + 1, 0, zero_count);
    dest8[64 - 3] = bytes >> 13;
    dest8[64 - 2] = bytes >> 5;
    dest8[64 - 1] = bytes << 3;

    AVXSetValue(dest_[0], TYPE_MASKA, 5);
    AVXSetValue(dest_[0], HASH_MASKA, 3);
    replace_key(dest_, new_key);
#ifdef _MSC_VER
    res = dest_[0].m256i_i8[9] != 5;
    if (res == 0)
        res = dest_[0].m256i_i8[0x15] != 3;
    if (res == 0)
        res = memcmp(dest_[0].m256i_i8 + 22, new_key8, 10);
    if (res == 0)
        res = memcmp(dest_[1].m256i_i8, new_key8 + 10, FIPS205_N - 10 );
    if (res == 0)
        res = dest_[1].m256i_i8[FIPS205_N - 9] == 0x80;
    if (res == 0)
    {
        for (uint32_t i = 0; i < zero_count; ++i)
        {
            if (dest_[1].m256i_i8[FIPS205_N - 8 + i] != 0)
                res = 1;
        }
    }
    if (res == 0)
        res = ((uint8_t)(dest_[1].m256i_i8[31])) != ((uint8_t)(bytes << 3)) ;
    if (res == 0)
        res = ((uint8_t)(dest_[1].m256i_i8[30])) != ((uint8_t)(bytes >> 5));
    if (res == 0)
        res = ((uint8_t)(dest_[1].m256i_i8[29])) != ((uint8_t)(bytes >> 13)) ;
    return res;
#else
    uint8_t* d0 = dest8;
    uint8_t* d1 = dest8 + 32;

    res = d0[9] != 5;
    if (res == 0)
        res = d0[0x15] != 3;
    if (res == 0)
        res = memcmp(d0 + 22, new_key8, 10);
    if (res == 0)
        res = memcmp(d1, new_key8 + 10, FIPS205_N - 10);
    if (res == 0)
        res = d1[FIPS205_N - 9] == 0x80;
    if (res == 0)
    {
        for (uint32_t i = 0; i < zero_count; ++i)
        {
            if (d1[FIPS205_N - 8 + i] != 0)
            {
                res = 1;
                break;
            }
        }
    }
    if (res == 0)
        res = (uint8_t)d1[31] != (uint8_t)(bytes << 3);
    if (res == 0)
        res = (uint8_t)d1[30] != (uint8_t)(bytes >> 5);
    if (res == 0)
        res = (uint8_t)d1[29] != (uint8_t)(bytes >> 13);

    return res;
#endif
}

//int test_wots_chain()
//{
//    int res = 0;
//    __m256i key256 = { 0 };
//    uint8_t adr[ADR_SIZE], key8[FIPS205_N], *key8_new  = (uint8_t*)&key256, PK_seed [FIPS205_N];
//    __m256i in[2];
//    for (int i = 0; i < ADR_SIZE; ++i)
//        adr[i] = i;
//    for (int i = 0; i < FIPS205_N; ++i)
//    {
//        key8[i] = 0x20 + i;
//        key8_new[i] = 0x40 + i;
//       
//        PK_seed[i] = 0x60 + i;
//    }
//    //memcpy(&key256, key8_new, FIPS205_N);
//    
//    uint8_t* dest8 = (uint8_t*)in;
//    memcpy(dest8, adr, ADR_SIZE);
//    memcpy(dest8 + ADR_SIZE, key8, FIPS205_N);
//    dest8[ADR_SIZE + FIPS205_N] = 0x80;
//        
//    uint32_t bytes = 64 + ADR_SIZE + FIPS205_N;
//    uint32_t zero_count = 64 - (ADR_SIZE + FIPS205_N + 1) - 3;
//    memset(dest8 + ADR_SIZE + FIPS205_N + 1, 0, zero_count);
//    dest8[64 - 3] = bytes >> 13;
//    dest8[64 - 2] = bytes >> 5;
//    dest8[64 - 1] = bytes << 3;
//
//    uint8_t out1[FIPS205_N];
//    uint8_t  out2 [FIPS205_N];
//    __m256i predcalc_pk = { 0 };
//    uint32_t* predcalc_pk32 = predcalc_pk.m256i_u32;
//    
//    
//    FIPS205_wots_chain_old(out1, PK_seed, key8_new, adr, 0, 15);
//    
//    AVX_PREDCALC_VALUE(predcalc_pk32, PK_seed, FIPS205_N);
//    FIPS205_wots_chain_new(out2, predcalc_pk, in, key256, 0, 15);
//
//    res = 0;
//    res = memcmp(out1, out2, FIPS205_N);
//    /*for (int i = 0; i < FIPS205_N; ++i)
//    {
//        
//        if (out1[i] != out2.m256i_i8[i])
//            res = 1;
//    }*/
//    return res;
//
//}

/*
void FIPS205_wots_gen_sign_old(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, const uint8_t* PK_seed, uint8_t* Adr);
void FIPS205_wots_gen_sign_new(uint8_t sign[][FIPS205_N], const uint8_t* M, const uint8_t* SK_seed, const __m256i state256, uint8_t* adr);
*/

int test_FIPS205_wots()
{
    int res = 0;
    uint8_t SK_seed[FIPS205_N];
    uint8_t PK_seed[FIPS205_N];
    uint8_t M[FIPS205_N];
    uint32_t adr32[8] = { 0 };

    uint8_t Adr[22] = { 0 };
    srand(0);
    for (int i = 0; i < FIPS205_N; ++i)
    {
        SK_seed[i] = rand() % 256;
        PK_seed[i] = rand() % 256;
    }


    for (int i = 0; i < 13; ++i)
        Adr[i] = rand() % 256;
    setType(Adr, WOTS_HASH);
    uint8_t adr[ADR_SIZE];
    memcpy(adr, Adr, ADR_SIZE);



    //for (int i = 0; i < 13; ++i)
    //    adr[i] = rand() % 256;

    setType(adr, WOTS_HASH);
    //uint8_t adr[ADR_SIZE];
    //for (int i = 0; i < FIPS205_N; ++i)
    //{
    //    SK_seed[i] = rand() % 256;
    //    PK_seed[i] = rand() % 256;
    ////    M[i] = rand() % 256;
    //}


    //for (int i = 0; i < 9; ++i)
    //{
    //    adr[i] = rand() % 256;
    //    
    //}

    for (int i = 0; i < FIPS205_N; ++i)
        M[i] = rand() % 256;
    __m256i state256_[8], state256;



    // AVX_sha256_predcalc_pk_(predcalc_block, PK_seed);
    AVX_sha256_predcalc_pk_(state256_, PK_seed);
    AVX_sha256_predcalc_pk((uint32_t*)&state256, PK_seed);

#if FIPS205_N > 16
    __m256i state512_[8], state512[2];
    //AVX_PREDCALC_VALUE(state512, PK_seed_, FIPS205_N);
    AVX_sha512_predcalc_pk_(state512_, PK_seed);
    AVX_sha512_predcalc_pk((uint64_t*)state512, PK_seed);
#endif
    uint8_t cur_adr[22];


    uint8_t sk1[(FIPS205_LEN + 7) / 8 * 8][FIPS205_N];
    uint8_t pk1[(FIPS205_LEN + 7)/8 * 8][FIPS205_N];
    uint8_t pk2[(FIPS205_LEN + 7) / 8 * 8][FIPS205_N];
    __m256i pk2_256[(FIPS205_LEN + 7) / 8 * 8];
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif    
        FIPS205_wots_gen_sk_old(sk1, SK_seed, PK_seed, cur_adr);

        memcpy(cur_adr, adr, ADR_SIZE);
        FIPS205_wots_gen_pk_old(pk1, sk1, PK_seed, cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_wots_gen_pk_old time = %lld\n", min_tacts);
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif

        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif    
        FIPS205_wots_gen_pk_new__(pk2_256, SK_seed, state256_,
//#if FIPS205_N > 16
//            state512_,
//#endif
            cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_wots_gen_pk_new__ time = %lld\n", min_tacts);
#endif
    for (int i = 0; i < FIPS205_LEN; ++i)
    {
#ifdef _MSC_VER
        uint8_t* p = (uint8_t*)pk2_256[i].m256i_u8;
#else
        uint8_t* p = (uint8_t*)&pk2_256[i];
#endif
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pk1[i][j] != p[j])
                res = 1;
        }
    }

    printf("FIPS205_wots_gen_pk - %s\n", res == 0 ? "OK" : "ERROR");

    //return res;
    ///////////////*******************//////////////////////////////////
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif

        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif    
        FIPS205_AVX_wots_gen_pks((uint8_t*)pk2, SK_seed, 
#ifdef SHAKE
            PK_seed,
#else
            state256_,
#endif


//#if FIPS205_N == 16
//            &state256,
//#else
//            state512,
//#endif
            cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_wots_gen_pks time = %lld\n", min_tacts);
#endif
    for (int i = 0; i < FIPS205_LEN; ++i)
    {
#ifdef _MSC_VER
        uint8_t* p = (uint8_t*)pk2_256[i].m256i_u8;
#else
        uint8_t* p = (uint8_t*)&pk2_256[i];
#endif
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pk1[i][j] != pk2[i][j])
                res = 1;
        }
    }

    printf("FIPS205_wots_gen_pk___ - %s\n", res == 0 ? "OK" : "ERROR");

    //return res;
    /*
    void wots_pkGen__(
	uint8_t pk[][FIPS205_N],
	//uint8_*pk, 
	const uint8_t* SK_seed,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr)

    */
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif

        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif    
        wots_pkGen__(pk2, SK_seed, 
#ifdef SHAKE
            const uint8_t * PK_seed,
#else
            &state256,
#if FIPS205_N == 16
            &state256,
#else
            state512,
#endif
#endif 
            cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("wots_pkGen__ (Open MP) time = %lld\n", min_tacts);
#endif
    for (int i = 0; i < FIPS205_LEN; ++i)
    {
        //uint8_t* p = (uint8_t*)pk2_256[i].m256i_u8;
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pk1[i][j] != pk2[i][j])
                res = 1;
        }
    }

    printf("FIPS205_wots_gen_pk - %s\n", res == 0 ? "OK" : "ERROR");

    //return res;
    


    
    {
        uint8_t pk1_[FIPS205_N], pk2_[FIPS205_N];
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
    
        for (int k = 0; k < 16; ++k)
        {
    #endif

            memcpy(cur_adr, adr, ADR_SIZE);
    #ifndef _DEBUG
            tacts = __rdtsc();
    #endif    
            wots_pkGenFull__(
                pk1_,
                SK_seed,
    #ifdef SHAKE
                PK_seed,
    #else
        
                &state256,
    #if FIPS205_N == 16
                & state256,
    #else
                & state512,
    #endif
            
    #endif
                cur_adr);

    #ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("wots_pkGenFull__ (Open MP) time = %lld\n", min_tacts);
#endif
      //  return res;

#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;

        for (int k = 0; k < 16; ++k)
        {
    #endif

            memcpy(cur_adr, adr, ADR_SIZE);
    #ifndef _DEBUG
            tacts = __rdtsc();
    #endif    
            FIPS205_AVX_wots_gen_pk(
                pk2_,
                SK_seed,
    #ifdef SHAKE
                PK_seed,
    #else
                state256_,
    #if FIPS205_N == 16
                &state256,
    #else
                &state512,
    #endif

    #endif
                cur_adr);

        
    #ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("FIPS205_wots_gen_pk_AVX  time = %lld\n", min_tacts);
    #endif

        /*for (int i = 0; i < FIPS205_LEN; ++i)
        {*/
            //uint8_t* p = (uint8_t*)pk2_256[i].m256i_u8;
            for (int j = 0; j < FIPS205_N; ++j)
            {
                if (pk1_[j] != pk2_[j])
                    res = 1;
            }
        //}

        printf("FIPS205_wots_gen_pk_(Open mp and AVX - %s\n", res == 0 ? "OK" : "ERROR");
        

        //uint8_t adr32[32] = { 0 };
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (int i = 0; i < 16; ++i)
        {
            tacts = __rdtsc();
#endif

            wots_gen_pk((uint8_t*)pk1, SK_seed,
                PK_seed, (uint32_t*)adr32);
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("wots_gen_pk_avtors = %I64d\n", min_tacts);
#endif

        
        
        /*
        wots_gen_pk(pk, sk_seed, pub_seed, wots_addr);

        copy_keypair_addr(wots_pk_addr, wots_addr);
        thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

        */

//        uint8_t wots_addr[32] = { 0 }, wots_pk_addr[32];
//    
//        //uint8_t wots_addr[32] = { 0 }, wots_pk_addr[32] = { 0 };
//#ifndef _DEBUG
//        min_tacts = 0xFFFFFFFFFFFFFFFF;
//        
//    
//        for (int k = 0; k < 256; ++k)
//        {
//#endif

            
//#ifndef _DEBUG
//            tacts = __rdtsc();
//#endif    
//            wots_gen_pk(pk1, SK_seed, PK_seed, wots_addr);
//
//            copy_keypair_addr(wots_pk_addr, wots_addr);
//            thash(pk2_, pk1, SPX_WOTS_LEN, PK_seed, wots_pk_addr);
//
//#ifndef _DEBUG
//            tacts = __rdtsc() - tacts;
//            if (tacts < min_tacts)
//                min_tacts = tacts;
//        }
//    printf("wots_gen_pk (autor)  time = %lld\n", min_tacts);
//#endif
    }

    uint8_t sign1[FIPS205_LEN][FIPS205_N] = {0};
    uint8_t sign2[FIPS205_LEN][FIPS205_N] = {0};
    //uint8_t pk1_[FIPS205_N], pk2_[FIPS205_N];
    

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif    
        
        FIPS205_wots_gen_sign_old(sign1, M, SK_seed, PK_seed, cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_wots_gen_sign_old time = %lld\n", min_tacts);
#endif

    
    res = 0;
    {
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (int k = 0; k < 16; ++k)
        {
#endif
            memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
            tacts = __rdtsc();
#endif

            FIPS205_wots_gen_sign_new_(sign2, M, SK_seed, &state256, state256_, cur_adr);
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("FIPS205_wots_gen_sign_new_ time = %lld\n", min_tacts);
#endif
        
        res = 0;
        for (int i = 0; i < FIPS205_M; ++i)
        {
            for (int j = 0; j < FIPS205_N; ++j)
            {
                if (sign1[i][j] != sign2[i][j])
                    res = 1;
            }
        }
        
    }

    if (res == 0)
    {
        //memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (int k = 0; k < 16; ++k)
        {
#endif
            memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
            tacts = __rdtsc();
#endif
            
            FIPS205_AVX_wots_sign(sign2, M, SK_seed, /*&state256, */state256_, cur_adr);
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("FIPS205_AVX_wots_sign time = %lld\n", min_tacts);
#endif
        
        res = 0;
        for (int i = 0; i < FIPS205_M; ++i)
        {
            for (int j = 0; j < FIPS205_N; ++j)
            {
                if (sign1[i][j] != sign2[i][j])
                    res = 1;
            }
        }

        
    }
    
    if (res == 0)
    {
        //memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (int k = 0; k < 16; ++k)
        {
#endif
            memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
            tacts = __rdtsc();
#endif

            wots_sign__OLD((uint8_t*)sign2, M, SK_seed, &state256, &state256, cur_adr);
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("wots_sign_ (Open MP) time = %lld\n", min_tacts);
#endif

        res = 0;
        for (int i = 0; i < FIPS205_M; ++i)
        {
            for (int j = 0; j < FIPS205_N; ++j)
            {
                if (sign1[i][j] != sign2[i][j])
                    res = 1;
            }
        }


    }

    //uint32_t adr32[32] = { 0 };

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
    wots_sign((uint8_t*)sign2, M, SK_seed, PK_seed, (uint32_t*)adr32);
#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
    }
    printf("wots_sign avtors time = %lld\n", min_tacts);
#endif
    printf("FIPS205_wots_gen_sign - %s\n", res == 0 ? "OK" : "ERROR");

    uint8_t pk3[(FIPS205_LEN + 7)/8 * 8][FIPS205_N], pk4[(FIPS205_LEN + 7) / 8 * 8][FIPS205_N];

    memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
    FIPS205_wots_gen_pkFromSig_old(
        pk3,
        sign1,
        M,
        PK_seed,
        cur_adr);
#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
    }
    printf("FIPS205_wots_gen_pkFromSig_old time = %lld\n", min_tacts);
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        FIPS205_AVX_wots_gen_pkFromSig(
            pk4,
            sign1,
            M,
            state256_,
            cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_wots_gen_pkFromSig time = %lld\n", min_tacts);
#endif
    res = 0;
    for (int i = 0; i < FIPS205_LEN; ++i)
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pk3[i][j] != pk4[i][j])
                res = 1;
        }
    printf("FIPS205_AVX_wots_gen_pkFromSig - %s\n", res == 0 ? "OK" : "ERROR");

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        FIPS205_wots_gen_pkFromSig_new___(
            pk4,
            sign1,
            M,
            state256_,
            cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_wots_gen_pkFromSig_new___ time = %lld\n", min_tacts);
#endif
    res = 0;
    for (int i = 0; i < FIPS205_LEN; ++i)
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pk3[i][j] != pk4[i][j])
                res = 1;
        }
    printf("FIPS205_wots_gen_pkFromSig_new___ - %s\n", res == 0 ? "OK" : "ERROR");

    /*
    void FIPS205_wots_gen_pkFromSig_new____(
	uint8_t pk[][FIPS205_N],
	const uint8_t sign[][FIPS205_N],
	const uint8_t* M,
	const __m256i* blockstate256,
	uint8_t* adr)
    */

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        //FIPS205_wots_gen_pkFromSig_new____
        FIPS205_AVX_wots_gen_pkFromSig
        (
            pk4,
            sign1,
            M,
            state256_,
            cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    //printf("FIPS205_wots_gen_pkFromSig_new____ time = %lld\n", min_tacts);
    printf("FIPS205_wots_gen_pkFromSig_new____ time = %lld\n", min_tacts);
#endif
    res = 0;
    for (int i = 0; i < FIPS205_LEN; ++i)
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pk3[i][j] != pk4[i][j])
                res = 1;
        }
    printf("FIPS205_wots_gen_pkFromSig_new____ - %s\n", res == 0 ? "OK" : "ERROR");



#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        wots_pkFromSig__(
            pk4,
            (uint8_t*)sign1,
            M,
            &state256,
#if FIPS205_N ==16
            &state256,
#else
            &state512,
#endif
            cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("wots_pkFromSig__ (с Open MP) time = %lld\n", min_tacts);
#endif

    res = 0;
    for (int i = 0; i < FIPS205_LEN; ++i)
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pk3[i][j] != pk4[i][j])
                res = 1;
        }
    printf("wots_pkFromSig__ - %s\n", res == 0 ? "OK" : "ERROR");

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        //////////////////////////////////////////////
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        wots_pk_from_sig((uint8_t*)pk4,
            (const uint8_t*)sign1, M,
            PK_seed, (uint32_t*)adr32);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("wots_pk_from_sig (avtor) time = %lld\n", min_tacts);
#endif
    
    printf("Full key\n");

    
    uint8_t pkFull1[FIPS205_N], pkFull2[FIPS205_N];
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
        //////////////////////////////////////////////
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        /*
        void wots_pkFromSig_Full(

	uint8_t* pksig,

	const uint8_t* sig,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif

	uint8_t* adr)

        */
        wots_pkFromSig_Full(
            pkFull1,
            (const uint8_t*)sign1,
            M,
        #ifdef SHAKE
            PK_seed,
        #else
            &state256,
#if FIPS205_N ==16
            &state256,
#else
            &state512,
#endif
#endif
            adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("wots_pkFromSigFull (с Open MP) time = %lld\n", min_tacts);
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (int k = 0; k < 16; ++k)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
        //////////////////////////////////////////////
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
    
        FIPS205_AVX_wots_pkFromSig
        (
            pkFull2,
            sign1,
            M,
#ifdef SHAKE
            const uint8_t * pk,
#else
            state256_,
#if FIPS205_N ==16
            & state256,
#else
            & state512,
#endif
#endif
            adr
        );
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_wots_pkFromSig time = %lld\n", min_tacts);
#endif   
    res = 0;
    //for (int i = 0; i < FIPS205_LEN; ++i)
        for (int j = 0; j < FIPS205_N; ++j)
        {
            if (pkFull1[j] != pkFull2[j])
                res = 1;
        }
    printf("wots_pkFromSigFull and FIPS205_AVX_wots_pkFromSig - %s\n", res == 0 ? "OK" : "ERROR");


    






    
    
    return res;

}


int test_FIPS205_xmss()
{
    srand(0);
    uint8_t SK_seed[FIPS205_N], SK_prf [FIPS205_N], PK_seed_[FIPS205_N];
    uint8_t msg[FIPS205_N];
    int res = 0  ;
    
#ifdef SHAKE
    uint8_t adr[32] = { 0 };
    uint8_t cur_adr[32];
#else
    uint8_t adr[22] = { 0 };
    uint8_t cur_adr[22];
#endif
    int i;
    for (i = 0; i < FIPS205_N; ++i)
    {
        SK_seed[i] = rand() % 256;
        SK_prf[i] = rand() % 256;
        PK_seed_[i] = rand() % 256;
        msg[i] = rand() % 256;
    }

#ifdef SHAKE
    uint8_t* PK_seed = PK_seed_;
#else
    uint32_t PK_seed[8];
    
    __m256i predcalc_block256[8];
    AVX_sha256_predcalc_pk_(predcalc_block256, PK_seed_);
    AVX_sha256_predcalc_pk(PK_seed, PK_seed_);
    #if FIPS205_N == 16
        uint32_t PK_seed_n[8];
        AVX_sha256_predcalc_pk(PK_seed_n, PK_seed_);
    #else
        uint64_t PK_seed_n[8];
        AVX_sha512_predcalc_pk(PK_seed_n, (const uint8_t*)PK_seed_);
        
    #endif
    
#endif
    
    uint8_t PK_root1[FIPS205_N], PK_root2[FIPS205_N];

   // uint8_t cur_adr[ADR_SIZE];
        
#ifndef _DEBUG
    uint64_t tacts, min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
    
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
    
        xmss_node__OLD(
            PK_root1,
            SK_seed,
            0,
            FIPS205_H_ ,
#ifdef SHAKE
            PK_seed,
#else
            PK_seed,
            PK_seed_n,
#endif
            cur_adr);

#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_xmss_node__OLD (Open MP)time- %I64d\n", min_tacts);
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
        //memcpy(l_adr32, adr32, 32);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        //xmss_node(PK_root1, SK_seed, 0, FIPS205_H_ - 1, PK_seed_, l_adr32);
        
        FIPS205_AVX_xmss_node(
            PK_root2,
            SK_seed,
            0,
            FIPS205_H_ ,
#ifdef SHAKE
            PK_seed,
#else
            predcalc_block256,
            PK_seed_n,
#endif
            cur_adr);

#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_xmss_node (AVX) time- %I64d\n", min_tacts);
#endif
    for (i = 0; i < FIPS205_N; ++i)
    {
        if (PK_root1[i] != PK_root2[i])
            res = 1;
    }
    printf("FIPS205_AVX_xmss_node_OLD and FIPS205_AVX_xmss_node: %s\n", res == 0 ? "OK" : "ERROR");

           

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
        //memcpy(l_adr32, adr32, 32);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        //xmss_node(PK_root1, SK_seed, 0, FIPS205_H_ - 1, PK_seed_, l_adr32);

        FIPS205_AVX_xmss_node__(
            PK_root2,
            SK_seed,
            
#ifdef SHAKE
            PK_seed,
#else
            predcalc_block256,
            PK_seed_n,
#endif
            cur_adr);

#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_xmss_node__ (AVX) time- %I64d\n", min_tacts);
#endif
    for (i = 0; i < FIPS205_N; ++i)
    {
        if (PK_root1[i] != PK_root2[i])
            res = 1;
    }
    printf("FIPS205_AVX_xmss_node and FIPS205_AVX_xmss_node__: %s\n", res == 0 ? "OK" : "ERROR");

    {
        
        uint8_t pk[2 * FIPS205_N], sk[4 * FIPS205_N];
        unsigned char seed[3 * FIPS205_N];
        memcpy(seed, (const void*)SK_seed, FIPS205_N);
        memcpy(seed + FIPS205_N, (const void*)SK_prf, FIPS205_N);
        memcpy(seed + 2 * FIPS205_N, (const void*)PK_seed_, FIPS205_N);
        //SPX_TREE_HEIGHT(SPX_FULL_HEIGHT / SPX_D)
        printf("SPX_FULL_HEIGHT = %d\n", SPX_FULL_HEIGHT);
        printf("SPX_D = %d\n", SPX_D);
        printf("SPX_TREE_HEIGHT = %d\n", SPX_TREE_HEIGHT);

#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (i = 0; i < 16; ++i)
        {
#endif
#ifndef _DEBUG
            tacts = __rdtsc();
#endif
            crypto_sign_seed_keypair(pk, sk, seed);

#ifndef _DEBUG
            tacts = __rdtsc() - tacts;

            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("crypto_sign_seed_keypair (Autor) time- %I64d\n", min_tacts);
#endif
        
    }

    static uint8_t SIGtmp1[FIPS205_N * (FIPS205_H_ + FIPS205_LEN)], SIGtmp2[FIPS205_N * (FIPS205_H_ + FIPS205_LEN)];
    memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
    
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, sizeof(adr));
        //memcpy(l_adr32, adr32, 32);
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        //xmss_node(PK_root1, SK_seed, 0, 7, PK_seed, (PADR)l_adr);
#ifdef SHAKE
        xmss_sign__OLD(SIGtmp1, msg, SK_seed, 6, PK_seed, cur_adr);
#else
        xmss_sign__OLD(SIGtmp1, msg, SK_seed, 6, PK_seed, PK_seed_n, cur_adr);
#endif
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("xmss_sign__OLD time- %I64d\n", min_tacts);
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, sizeof(adr));
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        FIPS205_AVX_xmss_sign(SIGtmp2, msg, SK_seed, 6,
#ifdef SHAKE
            PK_seed,
#else
            predcalc_block256,
            PK_seed_n,
#endif
            cur_adr);


#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_xmss_sign time = %I64d\n", min_tacts);
#endif
    res = 0;
    for (i = 0; i < sizeof(SIGtmp2); ++i)
    {
        if (SIGtmp1[i] != SIGtmp2[i])
            res = 1;

    }
    printf("xmss_sign__OLD and FIPS205_AVX_xmss_sign %s\n", res == 0 ? "OK" : "ERROR");

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, sizeof(adr));
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        FIPS205_AVX_xmss_sign_(SIGtmp2, msg, SK_seed, 6,
#ifdef SHAKE
            PK_seed,
#else
            predcalc_block256,
            PK_seed_n,
#endif
            cur_adr);


#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_xmss_sign_ time = %I64d\n", min_tacts);
#endif
    res = 0;
    for (i = 0; i < sizeof(SIGtmp2); ++i)
    {
        if (SIGtmp1[i] != SIGtmp2[i])
            res = 1;

    }
    printf("FIPS205_AVX_xmss_sign and FIPS205_AVX_xmss_sign_ %s\n", res == 0 ? "OK" : "ERROR");




    //xmss_pkFromSig_
    uint8_t pk1[FIPS205_N], pk2[FIPS205_N];
#ifndef _DEBUG

    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, ADR_SIZE);
        // l_adr32
        //memcpy(l_adr32, adr32, 32);

#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        /*
        void xmss_pkFromSig__OLD(
	uint8_t* root,
	size_t idx,
	const uint8_t* SIGtmp,
	const uint8_t* Msg,
#ifdef SHAKE
	const uint8_t* PK_seed,
#else
	const void* PK_seed,
	const void* PK_seed_n,
#endif
	uint8_t* adr);
#endif
        */

        xmss_pkFromSig__OLD (pk1, 0, SIGtmp1, msg, PK_seed, PK_seed_n, cur_adr);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("xmss_pkFromSig  (Open MP) time- %I64d\n", min_tacts);
#endif

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
        memcpy(cur_adr, adr, sizeof(adr));
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        /*
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
        */
        FIPS205_AVX_xmss_pkFromSig (pk2, 0, SIGtmp1, msg,
#ifdef SHAKE
            PK_seed,
#else
            predcalc_block256,
            PK_seed_n,
#endif
            cur_adr);


#ifndef _DEBUG
        tacts = __rdtsc() - tacts;

        if (tacts < min_tacts)
            min_tacts = tacts;
    }
    printf("FIPS205_AVX_xmss_pkFromSig time = %I64d\n", min_tacts);
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


//int test_FIPS205_HT()
//{
//    uint64_t idx_tree;
//    uint32_t idx_leaf;
//    uint8_t SK_seed[FIPS205_N], PK_seed_[FIPS205_N], PK_root[FIPS205_N];
//    //uint8_t fors[FIPS205_K * (FIPS205_A + 1) * FIPS205_N];
//#if 1
//    uint8_t digest[FIPS205_M], * md = digest;
//
//#else
//    uint8_t md[(K * A + 7) / 8];
//
//#endif
//
//    // uint8_t* fors_sign(uint8_t* FORS, const uint8_t* md, const uint8_t* SK_seed, const uint8_t* PK_seed, PADR adr);
//    /*
//    uint8_t* ht_sign(uint8_t* pSig, const uint8_t* PK_fors, const uint8_t* SK_seed, const uint8_t* PK_seed,
//    uint64_t idxtree, uint32_t idxleaf);
//    */
//    srand(0);
//    for (int i = 0; i < FIPS205_N; ++i)
//    {
//        SK_seed[i] = rand() % 256;
//        PK_seed_[i] = rand() % 256;
//    }
//    for (int i = 0; i < FIPS205_M; ++i)
//        digest[i] = rand() % 256;
//
//#ifdef SHAKE
//    uint8_t adr[32] = { 0 };
//    uint8_t* PK_seed = PK_seed_;
//#else
//    uint8_t adr[22] = { 0 };
//    uint32_t PK_seed[8];
//#if FIPS205_N == 16
//    uint32_t PK_seed_n[8];
//#else
//    uint64_t PK_seed_n[8];
//#endif
//#endif
//
//    __m256i state256_[8];
//    __m256i state256;
//    AVX_sha256_predcalc_pk_(state256_, PK_seed_);
//
//    AVX_sha256_predcalc_pk((uint32_t*)&state256, PK_seed_);
//
//    //uint32_t* PK_seed = (uint32_t*)&state256;
//
//
//#if FIPS205_N == 16
//    memcpy(PK_seed, (uint32_t*)&state256, sizeof(PK_seed));
//    memcpy(PK_seed_n, PK_seed, sizeof(PK_seed));
//#else
//
//    AVX_sha512_predcalc_pk(PK_seed_n, PK_seed_);
//#endif
//
//
//    // 2: ADRS.setLayerAddress(𝑑 −1)
//
//
//    // 3: PK.root ← xmss_node(SK.seed, 0, ℎ′,PK.seed,ADRS)
////#ifdef SHAKE
////	SetAddress4(adr, LayerAddressOFFSET, D - 1);
////	xmss_node_(PK_root, SK_seed, 0, H_, PK_seed, adr);
////#else
////    ShortSetAddress1_OLD(adr, LayerAddressOFFSET, FIPS205_D - 1);
////	xmss_node__OLD(PK_root, SK_seed, 0, FIPS205_H_, PK_seed, PK_seed_n, adr);
////#endif
//#if 1
//    idx_tree = DigestParse(&idx_leaf, digest);
//#else
//    idx_tree = DigestParse(md, &idx_leaf, digest);
//#endif
//#ifdef SHAKE
//
//    //setTreeAddress(adr, idx_tree);
//    // 12 : ADRS.setTypeAndClear(FORS_TREE)
//    SetAddress8(adr, TreeAddressOFFSET, idx_tree);
//    //setTypeAndClear(adr, FORS_TREE);
//    SetAddressType4_0(adr, FORS_TREE);
//    // 13 : ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//    //setKeyPairAddress(adr, idx_leaf);
//    SetAddress4(adr, KeyPairAddressOFFSET, idx_leaf);
//#else
//    //ShortSetAddress8(adr, ShortTreeAddressOFFSET, idx_tree);
//    //ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET, idx_tree);
//    setTreeAddress(adr, idx_tree);
//    //setTypeAndClear(adr, FORS_TREE);
//    //ShortSetAddressType1(adr, FORS_TREE);
//    setType(adr, FORS_TREE);
//    // 13 : ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//    //setKeyPairAddress(adr, idx_leaf);
//    //ShortSetAddress4(adr, ShortKeyPairAddressOFFSET, idx_leaf);
//    setKeyPairAddress(adr, idx_leaf);
//#endif
//    uint8_t PK_fors[FIPS205_N];
//    static uint8_t fors_sign[FIPS205_K * (FIPS205_A + 1) * FIPS205_N];
//    int i;
//    /*for (i = 0; i < FIPS205_N; ++i)
//        PK_fors[i] = rand() % 256;*/
//    
//
//#if FIPS205_N == 16
//    fors_sign__OLD(fors_sign, md, SK_seed, &state256, &state256, adr);
//#else
//    fors_sign__OLD(fors_sign, md, SK_seed, &state256, PK_seed_n, adr);
//#endif
//#if FIPS205_N == 16
//    fors_pkFromSig__OLD(PK_fors, (const uint8_t*)fors_sign, md, &state256, &state256, adr);
//#else
//    fors_pkFromSig__OLD(PK_fors, (const uint8_t*)fors_sign, md, &state256, PK_seed_n, adr);
//#endif
//    
//    //#if FIPS205_N == 16
//    //	fors_sign_(fors, md, SK_seed, predcalc_pk_256, predcalc_pk_256, adr);
//    //	fors_pkFromSig_(PK_fors, fors, md, predcalc_pk_256, predcalc_pk_256, adr);
//    //#endif
//    //#if FIPS205_N == 24
//    //	fors_sign_(fors, md, SK_seed, predcalc_pk_256, predcalc_pk_384, adr);
//    //	fors_pkFromSig_(PK_fors, fors, md, predcalc_pk_256, predcalc_pk_384, adr);
//    //#endif
//    //#if FIPS205_N == 32
//    //	fors_sign_(fors, md, SK_seed, predcalc_pk_256, predcalc_pk_512, adr);
//    //	fors_pkFromSig_(PK_fors, fors, md, predcalc_pk_256, predcalc_pk_512, adr);
//    //#endif
//    
//
//#ifndef _DEBUG
//    uint64_t tacts, mintacts;
//#endif
//
//    uint8_t SIGHT1[(FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N],
//        SIGHT2[(FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N];
//
//
//#ifndef _DEBUG
//
//    mintacts = 0xFFFFFFFFFFFFFFFF;
//    for (i = 0; i < 16; ++i)
//    {
//        tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//        FIPS205_ht_sign_(SIGHT2, PK_fors, SK_seed, PK_seed, idx_tree, idx_leaf);
//#else
//        ht_sign__OLD(SIGHT1, PK_fors, SK_seed, PK_seed, PK_seed_n, idx_tree, idx_leaf);
//        //#if FIPS205_N == 16
//        //		ht_sign_(SIGHT2, PK_fors, SK_seed, 
//        //			predcalc_pk_256, predcalc_pk_256, idx_tree, idx_leaf);
//        //
//        //#endif
//        //#if FIPS205_N == 24
//        //		ht_sign_(SIGHT2, PK_fors, SK_seed,
//        //			predcalc_pk_256, predcalc_pk_384, idx_tree, idx_leaf);
//        //
//        //#endif
//        //#if FIPS205_N == 32
//        //		ht_sign_(SIGHT2, PK_fors, SK_seed,
//        //			predcalc_pk_256, predcalc_pk_512, idx_tree, idx_leaf);
//        //
//        //#endif
//#endif
//#ifndef _DEBUG
//        tacts = __rdtsc() - tacts;
//        if (tacts < mintacts)
//            mintacts = tacts;
//    }
//    printf("FIPS_ht_sign__END time = %I64d\n", mintacts);
//
//
//#endif
//
//#ifndef _DEBUG
//
//    mintacts = 0xFFFFFFFFFFFFFFFF;
//    for (i = 0; i < 16; ++i)
//    {
//        tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//        FIPS205_AVX_ht_sign(SIGHT2, PK_fors, SK_seed, PK_seed, idx_tree, idx_leaf);
//#else
//        FIPS205_AVX_ht_sign(SIGHT2, PK_fors, SK_seed, state256_, PK_seed_n, idx_tree, idx_leaf);
//    
//#endif
//#ifndef _DEBUG
//        tacts = __rdtsc() - tacts;
//        if (tacts < mintacts)
//            mintacts = tacts;
//    }
//    printf("FIPS_AVX_ht_sign time = %I64d\n", mintacts);
//
//
//#endif
//
//	int res = 0;
//	for (i = 0; i < sizeof(SIGHT2); ++i)
//	{
//		if (SIGHT1[i] != SIGHT2[i])
//			res = 1;
//	}
//
//	printf("ht_sign__OLD and FIPS_AVX_ht_sign %s\n", res == 0 ? "OK" : "ERROR");
//
//#ifndef _DEBUG
//
//	
//	mintacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//
//		res |= ht_verify__OLD(PK_fors, SIGHT2, PK_seed, PK_seed_n, idx_tree, idx_leaf, PK_root);
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < mintacts)
//			mintacts = tacts;
//	}
//	printf("ht_verify__OLD (Open MP) time = %I64d\n", mintacts);
//
//#endif
//
//#ifndef _DEBUG
//
//	res = 0;
//	mintacts = 0xFFFFFFFFFFFFFFFF;
//	for (i = 0; i < 16; ++i)
//	{
//		tacts = __rdtsc();
//#endif
//#ifdef SHAKE
//		res |= ht_verify__OLD(PK_fors, SIGHT2, PK_seed, idx_tree, idx_leaf, PK_root);
//#else
//		res |= FIPS205_AVX_ht_verify(PK_fors, SIGHT2, state256_, PK_seed_n, idx_tree, idx_leaf, PK_root);
//
//#endif
//#ifndef _DEBUG
//		tacts = __rdtsc() - tacts;
//		if (tacts < mintacts)
//			mintacts = tacts;
//	}
//	printf("FIPS205_AVX_ht_verify time = %I64d\n", mintacts);
//#endif
//
//
//
//
//	printf("ht_verify__OLD and FIPS205_AVX_ht_verify %s\n", res == 0 ? "OK" : "ERROR");
//	return res;
//}


int test_FIPS205_fors_and_HT()
{
	uint8_t digest[FIPS205_M];
	uint8_t md[(FIPS205_K * FIPS205_A + 7) / 8];
    uint8_t fors_sk1[FIPS205_K][FIPS205_N], fors_sk2[FIPS205_K][FIPS205_N];
    uint8_t fors_sign1[FIPS205_K * (FIPS205_A + 1) * FIPS205_N], fors_sign2[FIPS205_K * (FIPS205_A + 1) * FIPS205_N];
    
	uint8_t SK_seed[FIPS205_N], SK_prf [FIPS205_N], PK_seed_[FIPS205_N];

    uint8_t adr[ADR_SIZE] = { 0 }, cur_adr [ADR_SIZE];
	
	srand(0);
	int i, j, res = 0;
	for (i = 0; i < FIPS205_N; ++i)
	{
		SK_seed[i] = rand() % 256;
        SK_prf [i] = rand() % 256;
		PK_seed_[i] = rand() % 256;
	}
#ifdef SHAKE
	uint8_t* PK_seed = PK_seed_;
#else
    __m256i state256;
    __m256i state256_[8];
    
    AVX_sha256_predcalc_pk((uint32_t*)&state256, PK_seed_);
    AVX_sha256_predcalc_pk_(state256_, PK_seed_);
    
#if FIPS205_N != 16
    __m256i state512_[8];
    __m256i state512[2];
    AVX_sha512_predcalc_pk((uint64_t*)state512, PK_seed_);
    AVX_sha512_predcalc_pk_(state512_, PK_seed_);
#endif
    void* PK_seed = &state256;
    void* BLOCK_PK_seed = state256_;
#if FIPS205_N == 16
    void *HASH_PK_seed = &state256;
    void* BLOCK_HASH_PK_seed = state256_;
#else
    void* HASH_PK_seed = &state512;
    void* BLOCK_HASH_PK_seed = state512_;
#endif
#endif












//    uint32_t PK_seed[8];
//#if FIPS205_N == 16
//    __m256i PK_seed_n [8];
//    memcpy(PK_seed, (uint32_t*)&state256, sizeof(PK_seed));
//    memcpy(PK_seed_n, state256_, sizeof(state256_));
//#else
//    memcpy(PK_seed, (uint32_t*)&state256, sizeof(PK_seed));
//    //uint64_t PK_seed_n[8];
//    __m256i PK_seed_n[8];
//    //AVX_sha512_predcalc_pk(PK_seed_n, PK_seed_);
//    AVX_sha512_predcalc_pk_(PK_seed_n, PK_seed_);
//#endif
//#endif
 
    __m256i in64[64];
    


	for (i = 0; i < FIPS205_M; ++i)
	{
		digest[i] = rand() % 256;
	}
	memcpy(md, digest, sizeof(md));
	
	uint8_t tmp_idxtree[(FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8];
	uint8_t tmp_idxleaf[(FIPS205_H + 8 * FIPS205_D - 1) / (8 * FIPS205_D)];
	
	memcpy(tmp_idxtree, digest + sizeof(md), sizeof(tmp_idxtree));
	memcpy(tmp_idxleaf, digest + sizeof(md) + sizeof(tmp_idxtree), sizeof(tmp_idxleaf));
	
	
	uint64_t idxtree = toInt64(tmp_idxtree, (FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8) & (((uint64_t)1 << (FIPS205_H - FIPS205_H / FIPS205_D)) - 1);
	
	uint32_t idxleaf = toInt32(tmp_idxleaf, sizeof(tmp_idxleaf)) % ((uint64_t)1 << (FIPS205_H / FIPS205_D));
	
#ifdef SHAKE
	SetAddress8_OLD(adr, TreeAddressOFFSET_OLD, idxtree);
	SetAddressType4_0_OLD (adr, FORS_TREE_OLD);
	SetAddress4_OLD(adr, KeyPairAddressOFFSET_OLD, idxleaf);
#else 
	ShortSetAddress8_OLD(adr, ShortTreeAddressOFFSET_OLD, idxtree);
	ShortSetAddressType1_OLD(adr, FORS_TREE_OLD);
	ShortSetAddress4_OLD(adr, ShortKeyPairAddressOFFSET_OLD, idxleaf);

#endif

    FIPS205_AVX_fors_init(in64, SK_seed, adr);

#ifndef _DEBUG
	uint64_t tacts;
	uint64_t min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif

		memcpy(cur_adr, adr, sizeof (adr));

#ifndef _DEBUG
		tacts = __rdtsc();
#endif
        for (int j = 0; j < FIPS205_K; ++j)
        {
            fors_skGen__OLD(fors_sk1[j], SK_seed, &state256, cur_adr, j);
        }

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < min_tacts)
            min_tacts = tacts;
	}
	printf("fors_skGen (Open MP) time = %I64d\n", min_tacts);
#endif
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif

#ifdef SHAKE
		memcpy(cur_adr, adr, 32);
#else
		memcpy(cur_adr, adr, ADR_SIZE);
#endif
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
#ifdef SHAKE
		fors_skGen_(fors_sign2, SK_seed, PK_seed, cur_adr, md[0]);
#else
		FIPS205_AVX_fors_sk(fors_sk2, SK_seed, state256_, cur_adr);
#endif // SHAKE

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < min_tacts)
            min_tacts = tacts;
	}
	printf("FIPS205_AVX_fors_sk time = %I64d\n", min_tacts);
#endif
    res = 0;
    for (i = 0; i < FIPS205_K; ++i)
    {
        for (j = 0; j < FIPS205_N; ++j)
        {
            if (fors_sk1[i][j] != fors_sk2[i][j])
                res = 1;
        }
    }
    printf("fors_skGen and FIPS205_AVX_fors_sk : %s\n", res == 0? "OK" : "ERROR");
#if 0
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFF;
	for (i = 0; i < 4; ++i)
	{
#endif
		memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
		fors_node__OLD(fors_sign1, SK_seed, 0, 1, PK_seed, PK_seed_n, cur_adr);
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < min_tacts)
            min_tacts = tacts;
	}
	printf("fors_node (Open MP) time = %I64d\n", min_tacts);
#endif
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFF;

	for (i = 0; i < 4; ++i)
	{
#endif
#ifdef SHAKE 
		memcpy(cur_adr, adr, 32);
#else
		memcpy(cur_adr, adr, 22);
#endif
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
#ifdef SHAKE
		fors_node_(fors_sign2, SK_seed, 0, 1, PK_seed, cur_adr);
#else
        FIPS205_AVX_fors_node(fors_sign2, &state256, PK_seed_n, in64, /*cur_adr, */0, 1);
#endif

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < min_tacts)
            min_tacts = tacts;
	}
	printf("FIPS205_AVX_fors_node time = %I64d\n", min_tacts);
#endif
	
	/*
    void FIPS205_AVX_fors_sks(uint8_t sk[][FIPS205_N],
	__m256i* in_block,
	const void* PK_seed,
	uint32_t* ind);
    */
    
    res = 0;
    for (i = 0; i < FIPS205_N; ++i)
    {
        if (fors_sign1[i] != fors_sign2[i])
            res = 1;
    }
    printf("fors_node and FIPS205_AVX_fors_node : %s\n", res == 0 ? "YES" : "NO");
#endif

	uint8_t* p1, * p2;
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 4; ++i)
	{
#endif
		memcpy(cur_adr, adr, ADR_SIZE);
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
#if FIPS205_N == 16
		p1 = fors_sign__OLD(fors_sign1, md, SK_seed, &state256, &state256, cur_adr);
#else
        p1 = fors_sign__OLD(fors_sign1, md, SK_seed, &state256, state512, cur_adr);
#endif

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < min_tacts)
            min_tacts = tacts;
		//printf("fors_sign %x %x\n", fors_sign1[0], fors_sign1[1]);
	}
	printf("fors_sign__OLD: tacts = %I64d\n", min_tacts);
#endif
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 4; ++i)
	{
#endif
		#ifdef SHAKE
			memcpy(cur_adr, adr, 32);
		#else	
			memcpy(cur_adr, adr, 22);
		#endif
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
#ifdef SHAKE
		p2 = fors_sign_(fors_sign2, md, SK_seed, PK_seed_, cur_adr);
#else
#if FIPS205_N == 16
		p2 = fors_sign__OLD(fors_sign2, md, SK_seed, 
            &state256,
			&state256,
			cur_adr);
#else
        p2 = fors_sign__OLD(fors_sign2, md, SK_seed,
            &state256,
            state512,
            cur_adr);
#endif
#endif

#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < min_tacts)
            min_tacts = tacts;
		//printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
	}
	printf("fors_sign_: tacts = %I64d\n", min_tacts);
#endif
	
	res = 0;
	if (p1 - fors_sign1 != p2 - fors_sign2)
		res = 1;

	for (i = 0; res == 0 && (i < FIPS205_K * (FIPS205_A + 1) * FIPS205_N); ++i)
	{
		if (fors_sign1[i] != fors_sign2[i])
			res = 1;
	}
	
	printf("fors_sign and fors_sign_: %s\n", res == 0 ? "OK" : "ERROR");


    /*
    uint8_t* FIPS205_AVX_fors_sign(uint8_t* SigFors, uint8_t* md,
	__m256i* in_block,
	const void* PK_seed, const void* PK_seed_n)

    */



    /*
    uint8_t* FIPS205_AVX_fors_sign_(uint8_t* SigFors, uint8_t* md,
	__m256i* in_block,
	const void* PK_seed_, const void* PK_seed, const void* PK_seed_n)
    */
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 5; ++i)
    {
#endif
#ifdef SHAKE
        memcpy(cur_adr, adr, 32);
#else	
        memcpy(cur_adr, adr, 22);
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        /*
        uint8_t* FIPS205_AVX_fors_sign(uint8_t* SigFors, uint8_t* md,
	__m256i* in_block,
	const void* PK_seed_, const void* PK_seed, const void* PK_seed_n);
        */
#ifdef SHAKE
        p2 = FIPS205_AVX_fors_sign(fors_sign2, md, SK_seed, PK_seed, cur_adr);
#else
#if FIPS205_N == 16 
       p2 = FIPS205_AVX_fors_sign__(
            fors_sign2, 
            md, 
            in64,
            &state256,      // for 256 with predcalc
            state256_,      // for 256 with || predcalc
            &state256);     // for 256 and predcalc
#else
       p2 = FIPS205_AVX_fors_sign__(
           fors_sign2,
           md,
           in64,
           &state256,   // for 256 with predcalc
           state256_,   // for 256 with || predcalc
           state512     // for 512 with predcalc
       );
#endif


        
#endif
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
    }
    printf("FIPS205_AVX_fors_sign__: tacts = %I64d\n", min_tacts);
#endif
    res = 0;
    if (p1 - fors_sign1 != p2 - fors_sign2)
        res = 1;

    for (i = 0; res == 0 && (i < FIPS205_K * (FIPS205_A + 1) * FIPS205_N); ++i)
    {
        if (fors_sign1[i] != fors_sign2[i])
            res = 1;
    }

    printf("fors_sign__OLD and FIPS205_AVX_fors_sign__: %s\n", res == 0 ? "OK" : "ERROR");

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 5; ++i)
    {
#endif
#ifdef SHAKE
        memcpy(cur_adr, adr, 32);
#else	
        memcpy(cur_adr, adr, 22);
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        
#ifdef SHAKE
        p2 = FIPS205_AVX_fors_sign(fors_sign2, md, SK_seed, PK_seed, cur_adr);
#else
#if FIPS205_N == 16
        p2 = FIPS205_AVX_fors_sign(fors_sign2, md, //in64,
            SK_seed,
            //&state256, 
            state256_,  // block 256
            state256_,  // block 256 or 512
            cur_adr);
#else
        p2 = FIPS205_AVX_fors_sign(fors_sign2, md, //in64,
            SK_seed,
            //&state256,
            state256_,
            state512_,
            cur_adr);

#endif
#endif
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
    }
    printf("FIPS205_AVX_fors_sign: tacts = %I64d\n", min_tacts);
#endif

    res = 0;
    if (p1 - fors_sign1 != p2 - fors_sign2)
        res = 1;

    for (i = 0; res == 0 && (i < FIPS205_K * (FIPS205_A + 1) * FIPS205_N); ++i)
    {
        if (fors_sign1[i] != fors_sign2[i])
            res = 1;
    }

    printf("FIPS205_AVX_fors_sign__ and FIPS205_AVX_fors_sign: %s\n", res == 0 ? "OK" : "ERROR");


    /*
    void FIPS205_AVX_fors_sign_new(uint8_t *sign, uint8_t *md, const uint8_t* SK_seed, const void* PK_256, const void* PK_256_512, uint8_t* adr)
    */

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 5; ++i)
    {
#endif
#ifdef SHAKE
        memcpy(cur_adr, adr, 32);
#else	
        memcpy(cur_adr, adr, 22);
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif

#ifdef SHAKE
        p2 = FIPS205_AVX_fors_sign_new (fors_sign2, md, SK_seed, PK_seed, cur_adr);
#else
#if FIPS205_N == 16
        p2 = FIPS205_AVX_fors_sign_new (
            fors_sign2, 
            md, //in64,
            SK_seed,
            //&state256, 
            state256_,  // block 256
            &state256,  // block 256 or 512
            cur_adr);
#else
        p2 = FIPS205_AVX_fors_sign_new(fors_sign2, 
            md, //in64,
            SK_seed,
            //&state256,
            state256_,
            state512,
            cur_adr);

#endif
#endif
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
    }
    printf("FIPS205_AVX_fors_sign_new: tacts = %I64d\n", min_tacts);
#endif

    res = 0;
    if (p1 - fors_sign1 != p2 - fors_sign2)
    {
        
        res = 1;
        printf("FIPS205_AVX_fors_sign_new p1 - fors_sign1 != p2 - fors_sign2\n");
    }

    for (i = 0; res == 0 && (i < FIPS205_K * (FIPS205_A + 1) * FIPS205_N); ++i)
    {
        if (fors_sign1[i] != fors_sign2[i])
        {
            printf("FIPS205_AVX_fors_sign_new i = %d\tfors_sign1[i] = %d fors_sign2[i] = %d\n", i, fors_sign1[i], fors_sign2[i]);
            res = 1;
            break;
        }
    }

    printf("FIPS205_AVX_fors_sign_new and FIPS205_AVX_fors_sign: %s\n", res == 0 ? "OK" : "ERROR");

    /*
    uint8_t* FIPS205_AVX_fors_sign_new_(uint8_t* sign, uint8_t* md, const uint8_t* SK_seed, const void* PK_256, const void* PK_256_512, uint8_t* adr)

    */
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 5; ++i)
    {
#endif
#ifdef SHAKE
        memcpy(cur_adr, adr, 32);
#else	
        memcpy(cur_adr, adr, 22);
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif

#ifdef SHAKE
        p2 = FIPS205_AVX_fors_sign_new(fors_sign2, md, SK_seed, PK_seed, cur_adr);
#else
#if FIPS205_N == 16
        p2 = FIPS205_AVX_fors_sign_new__(
            fors_sign2,
            md, //in64,
            SK_seed,
            //&state256, 
            state256_,  // block 256
            &state256,  // block 256 or 512
            cur_adr);
#else
        p2 = FIPS205_AVX_fors_sign_new__(
            fors_sign2,
            md, //in64,
            SK_seed,
            //&state256,
            state256_,
            state512,
            cur_adr);

#endif
#endif
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
    }
    printf("FIPS205_AVX_fors_sign_new__: tacts = %I64d\n", min_tacts);
#endif

    res = 0;
    if (p1 - fors_sign1 != p2 - fors_sign2)
    {

        res = 1;
        printf("FIPS205_AVX_fors_sign_new p1 - fors_sign1 != p2 - fors_sign2\n");
    }

    for (i = 0; res == 0 && (i < FIPS205_K * (FIPS205_A + 1) * FIPS205_N); ++i)
    {
        if (fors_sign1[i] != fors_sign2[i])
        {
            printf("FIPS205_AVX_fors_sign_new_ i = %d\tfors_sign1[i] = %d fors_sign2[i] = %d\n", i, fors_sign1[i], fors_sign2[i]);
            res = 1;
            break;
        }
    }

    printf("FIPS205_AVX_fors_sign_new and FIPS205_AVX_fors_sign: %s\n", res == 0 ? "OK" : "ERROR");

    // autor
    /*
    void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const unsigned char *sk_seed, const unsigned char *pub_seed,
               const uint32_t fors_addr[8])
    */
    

    /*__declspec (align (32))
        uint32_t ind[(FIPS205_K + 7) / 8 * 8] = { 0 };
    fors_base(ind, md, FIPS205_K);
    
    FIPS205_AVX_fors_sks(
        fors_sk1,
        in64,
        state256_,
        ind);*/

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 4; ++i)
	{
#endif
#ifdef SHAKE
		memcpy(cur_adr, adr, 32);
#else	
		memcpy(cur_adr, adr, 22);
#endif
#ifndef _DEBUG
		tacts = __rdtsc();
#endif
#ifdef SHAKE
		p2 = fors_sign___OLD(fors_sign2, md, SK_seed, PK_seed, cur_adr);
#else
#if FIPS205_N == 16
        p2 = fors_sign___OLD(fors_sign2, md, SK_seed,
			&state256,
            &state256,
			cur_adr);
#else
        p2 = fors_sign___OLD(fors_sign2, md, SK_seed,
            &state256,
            state512,
            cur_adr);
#endif
#endif
#ifndef _DEBUG
		tacts = __rdtsc() - tacts;
		if (tacts < min_tacts)
            min_tacts = tacts;
		//printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
	}
	printf("fors_sign__: tacts = %I64d\n", min_tacts);
#endif

	res = 0;
	if (p1 - fors_sign1 != p2 - fors_sign2)
		res = 1;

	for (i = 0; res == 0 && (i < FIPS205_K * (FIPS205_A + 1) * FIPS205_N); ++i)
	{
		if (fors_sign1[i] != fors_sign2[i])
			res = 1;
	}

	printf("fors_sign and fors_sign__: %s\n", res == 0 ? "OK" : "ERROR");



    {
        static uint8_t fors_sign3[sizeof(fors_sign2) + 1000];
        uint32_t adr[8] = { 0 }, cur_adr[8];
        uint8_t pk[FIPS205_N];
        SetAddress8_OLD(adr, TreeAddressOFFSET_OLD, idxtree);
        //SetAddressType4_0_OLD(adr, FORS_TREE_OLD);
        SetAddress4_OLD(adr, KeyPairAddressOFFSET_OLD, idxleaf);
#ifndef _DEBUG
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (i = 0; i < 5; ++i)
        {
#endif
            memcpy(cur_adr, adr, sizeof(adr));
#ifndef _DEBUG
            tacts = __rdtsc();
#endif
            fors_sign(fors_sign3, pk, md, SK_seed, PK_seed, cur_adr);

#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
            //printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
        }
        printf("fors_sign (author): tacts = %I64d\n", min_tacts);

#endif
        uint8_t pk_autor[FIPS205_N];
#ifndef _DEBUG
        
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (i = 0; i < 5; ++i)
        {
#endif
            memcpy(cur_adr, adr, sizeof(adr));
#ifndef _DEBUG
            tacts = __rdtsc();
#endif
        
            fors_pk_from_sig(pk_autor,
                fors_sign3, md,
                PK_seed,
                cur_adr);

#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
            //printf("fors_sign_ %x %x\n", fors_sign2[0], fors_sign2[1]);
        }
        printf("fors_pk_from_sig (author): tacts = %I64d\n", min_tacts);

#endif



    }


	uint8_t PK_fors1[FIPS205_N], PK_fors2[FIPS205_N];

	
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
	{
#endif
        setType1(adr, FORS_TREE);
        memcpy(cur_adr, adr, ADR_SIZE);

#ifndef _DEBUG
			tacts = __rdtsc();
#endif
            /*
            &state256,   // for 256 with predcalc
           state256_,   // for 256 with || predcalc
            */
#if FIPS205_N == 16
			fors_pkFromSig__OLD(PK_fors1, (const uint8_t*)fors_sign1, md, &state256, &state256, cur_adr);
#else
            fors_pkFromSig__OLD(PK_fors1, (const uint8_t*)fors_sign1, md, &state256, state512, cur_adr);
#endif
#ifndef _DEBUG
			tacts = __rdtsc() - tacts;
			if (tacts < min_tacts)
                min_tacts = tacts;
			//printf("fors_pkFromSig: %x %x\n", PK_fors1[0], PK_fors1[1]);
	}
	printf("fors_pkFromSig tacts = %I64d\n", min_tacts);
#endif





#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
	for (i = 0; i < 16; ++i)
		{
#endif
#ifdef SHAKE
			memcpy(cur_adr, adr, 32);
#else
			memcpy(cur_adr, adr, 22);
#endif




#ifndef _DEBUG
			tacts = __rdtsc();
#endif
#ifdef SHAKE
			fors_pkFromSig__OLD(PK_fors2, (const uint8_t*)fors_sign1, md, PK_seed, cur_adr);
#else       
            
            #if FIPS205_N == 16
			fors_pkFromSig__OLD(PK_fors2, (const uint8_t*)fors_sign1, md, &state256, &state256, cur_adr);
#else
            fors_pkFromSig__OLD(PK_fors2, (const uint8_t*)fors_sign1, md, &state256, state512, cur_adr);
#endif
            

#endif
#ifndef _DEBUG
			tacts = __rdtsc() - tacts;
			if (tacts < min_tacts)
                min_tacts = tacts;
			//printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
		}
		printf("fors_pkFromSig_ tacts = %I64d\n", min_tacts);
#endif
		res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
		printf("fors_pkFromSig and fors_pkFromSig_: %s\n", res == 0 ? "OK" : "ERROR");

#ifndef _DEBUG		
        min_tacts = 0xFFFFFFFFFFFFFFFF;

		for (i = 0; i < 16; ++i)
		{
#endif
#ifdef SHAKE
			memcpy(cur_adr, adr, 32);
#else
			memcpy(cur_adr, adr, 22);
#endif
#ifndef _DEBUG		
			tacts = __rdtsc();
#endif
#ifdef SHAKE
			fors_pkFromSig__(PK_fors2, (const uint8_t*)fors_sign1, md, PK_seed, cur_adr);
#else
#if FIPS205_N == 16
            fors_pkFromSig___OLD(PK_fors2, (const uint8_t*)fors_sign1, md, &state256, &state256, cur_adr);
#else
            fors_pkFromSig___OLD(PK_fors2, (const uint8_t*)fors_sign1, md, &state256, state512, cur_adr);
#endif
            
            
#endif
#ifndef _DEBUG		
			tacts = __rdtsc() - tacts;
			if (tacts < min_tacts)
                min_tacts = tacts;
			//printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
		}
		printf("fors_pkFromSig__ (Open MP) tacts = %I64d\n", min_tacts);
#endif

		res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
		printf("fors_pkFromSig and fors_pkFromSig__: %s\n", res == 0 ? "OK" : "ERROR");

#ifndef _DEBUG		
        min_tacts = 0xFFFFFFFFFFFFFFFF;

        for (i = 0; i < 16; ++i)
        {
#endif
#ifdef SHAKE
            memcpy(cur_adr, adr, 32);
#else
            memcpy(cur_adr, adr, 22);
#endif




#ifndef _DEBUG
            tacts = __rdtsc();
#endif
            /*
            PK_fors2, (const uint8_t*)fors_sign1, md, &state256, &state256, cur_adr
            */
#if FIPS205_N == 16
            FIPS205_AVX_fors_pkFromSig(
                PK_fors2,
                (const uint8_t*)fors_sign1,
                md,
                &state256, state256_, state256_,
                adr);
#else
            FIPS205_AVX_fors_pkFromSig(
                PK_fors2,
                (const uint8_t*)fors_sign1,
                md,
                state512, state256_, state512_,
                adr);
#endif

#ifndef _DEBUG		
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
            //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
        }
        printf("FIPS205_AVX_fors_pkFromSig tacts = %I64d\n", min_tacts);
#endif

        res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
        printf("fors_pkFromSig__ and FIPS205_AVX_fors_pkFromSig: %s\n", res == 0 ? "OK" : "ERROR");

        /*
        void FIPS205_AVX_fors_pkFromSig_new__(
	uint8_t* pkFromSig,
	const uint8_t* SigFors,
	const uint8_t* md,
	const void* PK_seed_,		// one 256 0r 512
	const void* PK_seed,		// block 256
	const void* PK_seed_n,		// block 512
	uint8_t* adr)
        */
#ifndef _DEBUG		
        min_tacts = 0xFFFFFFFFFFFFFFFF;

        for (i = 0; i < 16; ++i)
        {
#endif
#ifdef SHAKE
            memcpy(cur_adr, adr, 32);
#else
            memcpy(cur_adr, adr, 22);
#endif




#ifndef _DEBUG
            tacts = __rdtsc();
#endif
            /*
            PK_fors2, (const uint8_t*)fors_sign1, md, &state256, &state256, cur_adr
            */
#if FIPS205_N == 16
            FIPS205_AVX_fors_pkFromSig_new__(
                PK_fors2,
                (const uint8_t*)fors_sign1,
                md,
                &state256, 
                &state256, 
                //state256_,
                adr);
#else
            FIPS205_AVX_fors_pkFromSig_new__(
                PK_fors2,
                (const uint8_t*)fors_sign1,
                md,
                &state512, // 256 or 512
                &state256, // 256
                //state512_,
                adr);
#endif

#ifndef _DEBUG		
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
            //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
        }
        printf("FIPS205_AVX_fors_pkFromSig_new__ tacts = %I64d\n", min_tacts);
#endif

        res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
        printf("fors_pkFromSig__ and FIPS205_AVX_fors_pkFromSig_new__: %s\n", res == 0 ? "OK" : "ERROR");
/*
uint8_t* FIPS205_AVX_fors_sign_and_PK(
    uint8_t* sign,
    uint8_t* pk,
    const uint8_t* md,
    const uint8_t* SK_seed,
    const void* PK_256,
    const void* PK_256_512,
    uint8_t* adr);

*/
//#ifndef _DEBUG		
//        min_tacts = 0xFFFFFFFFFFFFFFFF;
//
//        for (i = 0; i < 16; ++i)
//        {
//#endif
//#ifdef SHAKE
//            memcpy(cur_adr, adr, 32);
//#else
//            memcpy(cur_adr, adr, 22);
//#endif
//
//
//
//
//#ifndef _DEBUG
//            tacts = __rdtsc();
//#endif
//            /*
//            PK_fors2, (const uint8_t*)fors_sign1, md, &state256, &state256, cur_adr
//            */
//#if FIPS205_N == 16
//            FIPS205_AVX_fors_sign_and_PK(
//                fors_sign2,
//                PK_fors2,
//                md,
//                SK_seed,
//                state256_,
//                &state256,
//                cur_adr);
//
//#else
//            FIPS205_AVX_fors_sign_and_PK(
//                fors_sign2,
//                PK_fors2,
//                md,
//                SK_seed,
//                state256_,
//                state512,
//                cur_adr);
//#endif
//
//#ifndef _DEBUG		
//            tacts = __rdtsc() - tacts;
//            if (tacts < min_tacts)
//                min_tacts = tacts;
//            
//        }
//        printf("FIPS205_AVX_fors_sign_and_PK tacts = %I64d\n", min_tacts);
//#endif
//
//        res = memcmp(fors_sign1, fors_sign2, FIPS205_K * (FIPS205_A + 1) * FIPS205_N);
//        if (res == 0)
//            res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
//        printf("fors_pkFromSig__ and FIPS205_AVX_fors_sign_and_PK: %s\n", res == 0 ? "OK" : "ERROR");

        ////////////////////////////////////HT///////////////////////
        static uint8_t SIGHT1[(FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N],
            SIGHT2[(FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N],
            SIGHT3[(FIPS205_H + FIPS205_D * FIPS205_LEN) * FIPS205_N];
        uint8_t ht_adr[ADR_SIZE] = {0};
        setLayerAddress(ht_adr, FIPS205_D - 1);
        
        uint8_t PK_root[FIPS205_N];
        FIPS205_AVX_xmss_node(
            PK_root,
            SK_seed,
            0,
            FIPS205_H_,
#ifdef SHAKE
            PK_seed_,
#else
            state256_, // Block
#if FIPS205_N == 16
            & state256,
#else
            state512,
#endif
#endif
            ht_adr
        );

        /*uint64_t idx_tree;
        uint32_t idx_leaf;*/
        //idx_tree = DigestParse(&idxleaf, digest);
#ifndef _DEBUG

        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (i = 0; i < 16; ++i)
        {
            tacts = __rdtsc();
#endif
#ifdef SHAKE
            FIPS205_ht_sign_(SIGHT2, PK_fors, SK_seed, PK_seed, idx_tree, idx_leaf);
#else
            ht_sign__OLD(SIGHT1, PK_fors1, SK_seed, PK_seed, 
                //PK_seed_n, 
#if FIPS205_N == 16
                &state256,
#else
                state512,
#endif
                idxtree, idxleaf);
            //#if FIPS205_N == 16
            //		ht_sign_(SIGHT2, PK_fors, SK_seed, 
            //			predcalc_pk_256, predcalc_pk_256, idx_tree, idx_leaf);
            //
            //#endif
            //#if FIPS205_N == 24
            //		ht_sign_(SIGHT2, PK_fors, SK_seed,
            //			predcalc_pk_256, predcalc_pk_384, idx_tree, idx_leaf);
            //
            //#endif
            //#if FIPS205_N == 32
            //		ht_sign_(SIGHT2, PK_fors, SK_seed,
            //			predcalc_pk_256, predcalc_pk_512, idx_tree, idx_leaf);
            //
            //#endif
#endif
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("FIPS_ht_sign__END time = %I64d\n", min_tacts);


#endif

#ifndef _DEBUG

        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (i = 0; i < 16; ++i)
        {
            tacts = __rdtsc();
#endif
#ifdef SHAKE
            FIPS205_AVX_ht_sign(SIGHT2, PK_fors, SK_seed, PK_seed, idx_tree, idx_leaf);
#else
            FIPS205_AVX_ht_sign(SIGHT2, PK_fors1, SK_seed, state256_, 
                //PK_seed_n, 
#if FIPS205_N == 16
                & state256,
#else
                state512,
#endif
                idxtree, idxleaf);

#endif
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("FIPS_AVX_ht_sign time = %I64d\n", min_tacts);


#endif

        res = 0;
        for (i = 0; i < sizeof(SIGHT2); ++i)
        {
            if (SIGHT1[i] != SIGHT2[i])
                res = 1;
        }

        printf("ht_sign__OLD and FIPS_AVX_ht_sign %s\n", res == 0 ? "OK" : "ERROR");


        //void ht_signature(uint8_t* sig, unsigned char* root, uint8_t* sk_seed, uint8_t* pub_seed,
        //uint8_t* wots_addr, uint8_t* tree_addr, uint64_t tree, uint32_t idx_leaf);
        {
#ifndef _DEBUG
            min_tacts = 0xFFFFFFFFFFFFFFFF;
            for (i = 0; i < 16; ++i)
            {
                tacts = __rdtsc();
#endif
                uint32_t wots_addr[32] = { 0 }, tree_addr[32] = { 0 };
#ifdef SHAKE
                FIPS205_AVX_ht_sign(SIGHT2, PK_fors, SK_seed, PK_seed, idx_tree, idx_leaf);
#else
                ht_signature(
                    SIGHT3, 
                    PK_fors2, 
                    SK_seed, 
                    PK_seed_, 
                    (uint8_t*)wots_addr, 
                    (uint8_t*)tree_addr, 
                    idxtree, 
                    idxleaf);
#endif

#ifndef _DEBUG
                tacts = __rdtsc() - tacts;
                if (tacts < min_tacts)
                    min_tacts = tacts;
            }
            printf("ht_signature (autor) time = %I64d\n", min_tacts);


#endif
        }
#ifndef _DEBUG


        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (i = 0; i < 16; ++i)
        {
            tacts = __rdtsc();
#endif

            res |= ht_verify__OLD(PK_fors1, SIGHT2, PK_seed, 
                //PK_seed_n, 
#if FIPS205_N == 16
                &state256,
#else
                state512,
#endif
                idxtree, idxleaf, PK_root);
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("ht_verify__OLD (Open MP) time = %I64d\n", min_tacts);

#endif

#ifndef _DEBUG

        res = 0;
        min_tacts = 0xFFFFFFFFFFFFFFFF;
        for (i = 0; i < 16; ++i)
        {
            tacts = __rdtsc();
#endif
#ifdef SHAKE
            res |= ht_verify__OLD(PK_fors, SIGHT2, PK_seed, idx_tree, idx_leaf, PK_root);
#else
            res |= FIPS205_AVX_ht_verify(PK_fors1, SIGHT2, state256_, 
                //PK_seed_n, 
#if FIPS205_N == 16
                &state256,
#else
                state512,
#endif
                idxtree, idxleaf, PK_root);

#endif
#ifndef _DEBUG
            tacts = __rdtsc() - tacts;
            if (tacts < min_tacts)
                min_tacts = tacts;
        }
        printf("FIPS205_AVX_ht_verify time = %I64d\n", min_tacts);
#endif




        printf("ht_verify__OLD and FIPS205_AVX_ht_verify %s\n", res == 0 ? "OK" : "ERROR");

        /*
        int ht_verify(
    uint8_t *sig, 
    uint8_t *root,
    uint8_t * pub_seed,
    uint8_t* pub_root,
    uint8_t * tree_addr,
    uint8_t *wots_addr,
    uint64_t tree,
    uint32_t idx_leaf
    )
        */

        {
            /*uint8_t wots_addr[32] = { 0 }, tree_addr[32] = { 0 };*/
            
            
#ifndef _DEBUG

            res = 0;
            min_tacts = 0xFFFFFFFFFFFFFFFF;
            for (i = 0; i < 1; ++i)
            {
                tacts = __rdtsc();
#endif
#ifdef SHAKE
                res |= ht_verify__OLD(PK_fors, SIGHT2, PK_seed, idx_tree, idx_leaf, PK_root);
#else

                ht_verify(
                    SIGHT3,
                    PK_fors1,
                    PK_seed,
                    PK_root,
                    /*tree_addr,
                    wots_addr,*/
                    idxtree, 
                    idxleaf
                );

#endif
#ifndef _DEBUG
                tacts = __rdtsc() - tacts;
                if (tacts < min_tacts)
                    min_tacts = tacts;
            }
            printf("ht_verify (autor) time = %I64d\n", min_tacts);
#endif


            
        }
        
/*
uint8_t* FIPS205_AVX_fors_sign_and_pk(
    uint8_t* SigFors,
    uint8_t* pk,
    const uint8_t* md,
    //__m256i* in_block,
    const uint8_t* SK_seed,
    const void* PK_seed_,		// one for 256 / 512
    const void* PK_seed,		// block for 256
    const void* PK_seed_n,		// block for 256/512
    uint8_t* adr)
*/
//#ifndef _DEBUG		
//        min_tacts = 0xFFFFFFFFFFFFFFFF;
//
//        for (i = 0; i < 16; ++i)
//        {
//#endif
//#ifdef SHAKE
//            memcpy(cur_adr, adr, 32);
//#else
//            memcpy(cur_adr, adr, 22);
//#endif
//
//
//
//
//#ifndef _DEBUG
//            tacts = __rdtsc();
//#endif
//#if FIPS205_N == 16
//            FIPS205_AVX_fors_sign_and_pk(
//                fors_sign2,
//                PK_fors2,
//                md,
//                //__m256i* in_block,
//                SK_seed,
//                &state256,
//                state256_,
//                state256_,
//                adr);
//#else
//            FIPS205_AVX_fors_sign_and_pk(
//                fors_sign2,
//                PK_fors2,
//                md,
//                SK_seed,
//                &state512,		// one for 256 / 512
//                state256_,		// block for 256
//                state512_,		// block for 256/512
//                adr);
//#endif
//
//#ifndef _DEBUG		
//            tacts = __rdtsc() - tacts;
//            if (tacts < min_tacts)
//                min_tacts = tacts;
//        }
//        printf("FIPS205_AVX_fors_sign_and_pk tacts = %I64d\n", min_tacts);
//#endif
//        
//        //res = memcmp(PK_fors1, PK_fors2, FIPS205_N);
//        for (i = 0; (i < FIPS205_K * (FIPS205_A + 1) * FIPS205_N); ++i)
//        {
//            if (fors_sign1[i] != fors_sign2[i])
//                res = 1;
//        }
//        if (res == 0)
//        {
//            for (i = 0; i < FIPS205_N; ++i)
//            {
//                if (PK_fors1[i] != PK_fors2[i])
//                    res = 1;
//            }
//        }
//        printf("FIPS205_AVX_fors_sign_and_pk: %s\n", res == 0 ? "OK" : "ERROR");
	    return res;

}



int test_2_b()
{
    uint32_t x1[FIPS205_K], x2 [FIPS205_K];
    uint8_t md[(FIPS205_K * FIPS205_A + 7) / 8 * 8];
    srand(0);
    for (int i = 0; i < sizeof(md); ++i)
    {
        md[i] = rand() % 256;

    }

    base_2b_old(x1, md, FIPS205_A, FIPS205_K);


    fors_base(x2, md, FIPS205_K);
//#if FIPS205_N == 16 
//#ifndef FAST
//    base12(x2, md, FIPS205_K);
//#else
//    base6(x2, md, FIPS205_K);
//#endif
//#endif
//
//#if FIPS205_N == 24 
//#ifndef FAST
//    base14(x2, md, FIPS205_K);
//#else
//    base8(x2, md, FIPS205_K);
//#endif
//#endif
//
//#if FIPS205_N == 32 
//#ifndef FAST
//    base14(x2, md, FIPS205_K);
//#else
//    base9(x2, md, FIPS205_K);
//#endif
//#endif
    int res = 0;
    for (int i = 0; i < FIPS205_K; ++i)
    {
        if (x1[i] != x2[i])
            res = 1;
    }
    return res;

}

int test_internal_function()
{
    printf(" * **********************test_internal_function*********************\n");
    int res = 0;
    uint8_t SK[4 * FIPS205_N], * PK = SK + 2 * FIPS205_N;
    uint8_t *SK_seed = SK, *SK_prf = SK + FIPS205_N, *PK_seed = PK, *PK_root = PK + FIPS205_N;
    uint8_t PK_root1[FIPS205_N], PK_root2[FIPS205_N];
    
    srand(0);
    int i;
    for (i = 0; i < FIPS205_N; ++i)
    {
        SK_seed[i] = rand() % 256;
        SK_prf[i] = rand() % 256;
        PK_seed[i] = rand() % 256;
    }
    // slh_keygen_internal__OLD(uint8_t* SK, uint8_t* PK, const uint8_t* SK_seed, const uint8_t* SK_prf, const uint8_t* PK_seed);

#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif

    slh_keygen_internal__OLD (PK_root1, SK_seed, SK_prf, PK_seed);
    
#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
    //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
}
    
    printf("slh_keygen_internal__OLD tacts = %I64d\n", min_tacts);
#endif
    
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif

    FIPS205_keygen_internal(PK_root2, SK_seed, SK_prf, PK_seed);
#ifndef _DEBUG
    tacts = __rdtsc() - tacts;
    if (tacts < min_tacts)
        min_tacts = tacts;
    //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
}
    printf("FIPS205_keygen_internal tacts = %I64d\n", min_tacts);
#endif

    for (i = 0; i < FIPS205_N; ++i)
    {
        if (PK_root1[i] != PK_root2[i])
            res = 1;
    }
    
    
    memcpy(PK_root, PK_root1, FIPS205_N);
    
    uint8_t pk[2 * FIPS205_N], sk[4 * FIPS205_N];

    {
    
        

       //     uint8_t pk[2 * FIPS205_N], sk[4 * FIPS205_N];
            unsigned char seed[3 * FIPS205_N];
            memcpy(seed, (const void*)SK_seed, FIPS205_N);
            memcpy(seed + FIPS205_N, (const void*)SK_prf, FIPS205_N);
            memcpy(seed + 2 * FIPS205_N, (const void*)PK_seed, FIPS205_N);
            //SPX_TREE_HEIGHT(SPX_FULL_HEIGHT / SPX_D)
            
#ifndef _DEBUG
            min_tacts = 0xFFFFFFFFFFFFFFFF;
            for (i = 0; i < 16; ++i)
            {
#endif
#ifndef _DEBUG
                tacts = __rdtsc();
#endif
                crypto_sign_seed_keypair(pk, sk, seed);

#ifndef _DEBUG
                tacts = __rdtsc() - tacts;

                if (tacts < min_tacts)
                    min_tacts = tacts;
            }
            printf("crypto_sign_seed_keypair (Autor) time- %I64d\n", min_tacts);
#endif

        
    }
    
    static uint8_t sign1[FIPS205_SIG_BYTES], sign2[FIPS205_SIG_BYTES];
    uint8_t M[39];
    for (i = 0; i < sizeof(M); ++i)
        M[i] = rand() % 256;

#ifndef _DEBUG
    

    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif

        slh_sign_internal__OLD(sign1, M, sizeof (M),
            SK, PK_seed); 
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
    }
    printf("slh_sign_internal__OLD tacts = %I64d\n", min_tacts);
#endif

    //printf("sign1\n");
    //print(FIPS205_SIG_BYTES * 8, sign1);

#ifndef _DEBUG


    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        /*
        void FIPS205_sign_internal(uint8_t* sign, const uint8_t* M, uint32_t M_len, const uint8_t* SK, uint8_t* addrng)
        */
        FIPS205_sign_internal(sign2, M, sizeof(M),
            SK, PK_seed);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
    }
    printf("FIPS205_sign_internal tacts = %I64d\n", min_tacts);
#endif

    //printf("sign2 after FIPS205_sign_internal\n");
    //print(FIPS205_SIG_BYTES * 8, sign2);

    for (i = 0; i < FIPS205_SIG_BYTES; ++i)
    {
        if (sign1[i] != sign2[i])
            res = 1;
    }


#ifndef _DEBUG


    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        /*
        void FIPS205_sign_internal(uint8_t* sign, const uint8_t* M, uint32_t M_len, const uint8_t* SK, uint8_t* addrng)
        */
        FIPS205_sign_internal_new__(sign2, M, sizeof(M),
            SK, PK_seed);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
    }
    printf("FIPS205_sign_internal_new__ tacts = %I64d\n", min_tacts);
#endif
    res = 0;

    //printf("\n");
    //printf("sign2 after FIPS205_sign_internal_new__\n");
    //print(FIPS205_SIG_BYTES * 8, sign2);

    for (i = 0; i < FIPS205_SIG_BYTES; ++i)
    {
        if (sign1[i] != sign2[i])
            res = 1;
    }

    printf("FIPS205_sign_internal1 res = %s\n", res == 0? "OK" : "ERROR");

    /*
    int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
    */
    size_t siglen;
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        /*
        void FIPS205_sign_internal(uint8_t* sign, const uint8_t* M, uint32_t M_len, const uint8_t* SK, uint8_t* addrng)
        */

        crypto_sign_signature(sign2, &siglen, M, sizeof(M),
            sk);

#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        //printf("fors_pkFromSig_ %x %x\n", PK_fors2[0], PK_fors2[1]);
    }
    printf("crypto_sign_signature (autor) tacts = %I64d\n", min_tacts);
#endif
    res = 0;
    
#ifndef _DEBUG


    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        res |= slh_verify_internal__OLD(M, sizeof(M), sign1, FIPS205_SIG_BYTES, PK_seed);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;
        
    }
    
    printf("slh_verify_internal__OLD tacts = %I64d\n", min_tacts);

#endif
    printf("slh_verify_internal__OLD res = %s\n", res == 0 ? "OK" : "ERROR");
    res = 0;
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        res |= FIPS205_verify_internal(M, sizeof(M), sign1, FIPS205_SIG_BYTES, PK_seed);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;

    }
    printf("FIPS205_verify_internal tacts = %I64d\n", min_tacts);

#endif
    
    printf("FIPS205_verify_internal res = %s\n", res == 0 ? "OK" : "ERROR");

    res = 0;
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        res |= FIPS205_verify_internal_new__(M, sizeof(M), sign1, FIPS205_SIG_BYTES, PK_seed);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;

    }
    printf("FIPS205_verify_internal_new__ tacts = %I64d\n", min_tacts);

#endif

    printf("FIPS205_verify_internal_new__ res = %s\n", res == 0 ? "OK" : "ERROR");

 // int crypto_sign_verify(const uint8_t *sig, size_t siglen,
    //const uint8_t* m, size_t mlen, const uint8_t* pk)

    int res1 = 0;
#ifndef _DEBUG
    min_tacts = 0xFFFFFFFFFFFFFFFF;
    for (i = 0; i < 16; ++i)
    {
#endif
#ifndef _DEBUG
        tacts = __rdtsc();
#endif
        res1 |= crypto_sign_verify(sign2, siglen, M, sizeof(M), pk);
#ifndef _DEBUG
        tacts = __rdtsc() - tacts;
        if (tacts < min_tacts)
            min_tacts = tacts;

    }
    printf("crypto_sign_verify tacts = %I64d\n", min_tacts);

#endif

    //printf("FIPS205_verify_internal res = %s\n", res == 0 ? "OK" : "ERROR");
    return res;



}

