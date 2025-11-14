#include <stdio.h>
#include <string.h>
#include "FIPS_205_Params.h"
#include "SHA512_defined.h"
#include "SHA512.h"
#include "Common.h"


#define WL128(padded, bytes){            \
    padded[119] = (uint8_t)(bytes >> 61);   \
    padded[120] = (uint8_t)(bytes >> 53);   \
    padded[121] = (uint8_t)(bytes >> 45);   \
    padded[122] = (uint8_t)(bytes >> 37);   \
    padded[123] = (uint8_t)(bytes >> 29);   \
    padded[124] = (uint8_t)(bytes >> 21);   \
    padded[125] = (uint8_t)(bytes >> 13);   \
    padded[126] = (uint8_t)(bytes >> 5);    \
    padded[127] = (uint8_t)(bytes << 3);    \
}

#define WL256(padded, bytes){            \
    padded[247] = (uint8_t)(bytes >> 61);   \
    padded[248] = (uint8_t)(bytes >> 53);   \
    padded[249] = (uint8_t)(bytes >> 45);   \
    padded[250] = (uint8_t)(bytes >> 37);   \
    padded[251] = (uint8_t)(bytes >> 29);   \
    padded[252] = (uint8_t)(bytes >> 21);   \
    padded[253] = (uint8_t)(bytes >> 13);   \
    padded[254] = (uint8_t)(bytes >> 5);    \
    padded[255] = (uint8_t)(bytes << 3);    \
}

static uint64_t load_bigendian(const uint8_t* x)
{
    return
        (uint64_t)(x[7]) \
        | (((uint64_t)(x[6])) << 8) \
        | (((uint64_t)(x[5])) << 16) \
        | (((uint64_t)(x[4])) << 24) \
        | (((uint64_t)(x[3])) << 32) \
        | (((uint64_t)(x[2])) << 40) \
        | (((uint64_t)(x[1])) << 48) \
        | (((uint64_t)(x[0])) << 56)
        ;
}

static void store_bigendian(uint8_t* x, uint64_t u)
{
    x[7] = (uint8_t)u; u >>= 8;
    x[6] = (uint8_t)u; u >>= 8;
    x[5] = (uint8_t)u; u >>= 8;
    x[4] = (uint8_t)u; u >>= 8;
    x[3] = (uint8_t)u; u >>= 8;
    x[2] = (uint8_t)u; u >>= 8;
    x[1] = (uint8_t)u; u >>= 8;
    x[0] = (uint8_t)u;
}
//uint64_t FOldFun512(
//    uint64_t a, uint64_t b, uint64_t c, uint64_t d, 
//    uint64_t e, uint64_t f, uint64_t g, uint64_t h,
//    uint64_t w, uint64_t k)
//{
//    uint64_t T1 = h + S1(e) + ch(e, f, g) + k + w; 
//    uint64_t T2 = S0(a) + maj(a, b, c); 
//        h = g; 
//        g = f; 
//        f = e; 
//        e = d + T1; 
//        d = c; 
//        c = b; 
//        b = a; 
//        a = T1 + T2;
//        return a;
//}
//
//uint64_t FOldFun512_(
//    uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d,
//    uint64_t *e, uint64_t *f, uint64_t *g, uint64_t *h,
//    uint64_t w, uint64_t k)
//{
//    uint64_t T1 = *h + S1(*e) + ch(*e, *f, *g) + k + w;
//    uint64_t T2 = S0(*a) + maj(*a, *b, *c);
//    *h = *g;
//    *g = *f;
//    *f = *e;
//    *e = *d + T1;
//    *d = *c;
//    *c = *b;
//    *b = *a;
//    *a = T1 + T2;
//    return *a;
//}
//
//void M512_old_fun(uint64_t* w, int num0, int num1, int num2, int num3)
//{
//    // w0 = s1(w14) + w9 + s0(w1) + w0;
//    w[num0] = s1(w[num1]) + w[num2] + s0 (w[num3]) + w[num0];
//}
//
//void EXPAND512_old_fun(uint64_t* w)
//{
//    M512_old_fun(w, 0, 14, 9, 1) ;
//    M512_old_fun(w, 1, 15, 10, 2) ;
//    M512_old_fun(w, 2, 0, 11, 3) ;
//    M512_old_fun(w, 3, 1, 12, 4) ;
//    M512_old_fun(w, 4, 2, 13, 5) ;
//    M512_old_fun(w, 5, 3, 14, 6) ;
//    M512_old_fun(w, 6, 4, 15, 7) ;
//    M512_old_fun(w, 7, 5, 0, 8) ;
//    M512_old_fun(w, 8, 6, 1, 9) ;
//    M512_old_fun(w, 9, 7, 2, 10) ;
//    M512_old_fun(w, 10, 8, 3, 11) ;
//    M512_old_fun(w, 11, 9, 4, 12) ;
//    M512_old_fun(w, 12, 10, 5, 13) ;
//    M512_old_fun(w, 13, 11, 6, 14) ;
//    M512_old_fun(w, 14, 12, 7, 15) ;
//    M512_old_fun(w, 15, 13, 8, 0);
//}
//void funBlock512(uint64_t* a_, uint64_t* b_, uint64_t* c_, uint64_t* d_, uint64_t* e_, uint64_t* f_, uint64_t* g_, uint64_t* h_,
//    uint64_t w[16])
//{
//#ifdef _DEBUG
//    FILE* file_w = fopen("old_w.txt", "wt");
//    FILE* file_coef = fopen("old_coef.txt", "wt");
//#endif;
//    uint64_t T1, T2;
//    uint64_t a = *a_, b = *b_, c = *c_, d = *d_;
//    uint64_t e = *e_, f = *f_, g = *g_, h = *h_;
//    uint64_t w0 = w[0], w1 = w[1], w2 = w[2], w3 = w[3];
//    uint64_t w4 = w[4], w5 = w[5], w6 = w[6], w7 = w[7];
//    uint64_t w8 = w[8], w9 = w[9], w10 = w[10], w11 = w[11];
//    uint64_t w12 = w[12], w13 = w[13], w14 = w[14], w15 = w[15];
//#ifdef _DEBUG 
//    fprintf(file_w, "step 0\n");
//    for (int i = 0; i < 16; ++i)
//        fprintf(file_w, "%d\t%I64x\n", i, w[i]);
//#endif
//    //F(w0, 0x428a2f98d728ae22ULL);
//    F(w0, 0x428a2f98d728ae22ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "step 0\n");
//    fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "0 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "0 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    
//    F(w1, 0x7137449123ef65cdULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "1 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "1 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w2, 0xb5c0fbcfec4d3b2fULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "2 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "2 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w3, 0xe9b5dba58189dbbcULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "3 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "3 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w4, 0x3956c25bf348b538ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "4 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "4 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w5, 0x59f111f1b605d019ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "5 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "5 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w6, 0x923f82a4af194f9bULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "6 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "6 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w7, 0xab1c5ed5da6d8118ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "7 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "7 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w8, 0xd807aa98a3030242ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "8 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "8 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w9, 0x12835b0145706fbeULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "9 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "9 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w10, 0x243185be4ee4b28cULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "10 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "10 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//
//    F(w11, 0x550c7dc3d5ffb4e2ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "11 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "11 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w12, 0x72be5d74f27b896fULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "12 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "12 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w13, 0x80deb1fe3b1696b1ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "13 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "13 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w14, 0x9bdc06a725c71235ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "14 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "14 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    F(w15, 0xc19bf174cf692694ULL);
//#ifdef _DEBUG 
//    fprintf(file_coef, "\nT1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "15 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "15 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//    
//    EXPAND512_old_fun(w);
//#ifdef _DEBUG 
//    fprintf(file_w, "step 1\n");
//    for (int i = 0; i < 16; ++i)
//        fprintf(file_w, "%d\t%I64x\n", i+16, w[i]);
//#endif
//
//    w0 = w[0];
//    w1 = w[1];
//    w2 = w[2];
//    w3 = w[3];
//    w4 = w[4];
//    w5 = w[5];
//    w6 = w[6];
//    w7 = w[7];
//    w8 = w[8];
//    w9 = w[9];
//    w10 = w[10];
//    w11= w[11];
//    w12 = w[12];
//    w13= w[13];
//    w14= w[14];
//    w15 = w[15];
//    F(w0, 0xe49b69c19ef14ad2ULL)	;
//#ifdef _DEBUG 
//    fprintf(file_coef, "step 1\n");
//    fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//    fprintf(file_coef, "16 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//    fprintf(file_coef, "16 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w1, 0xefbe4786384f25e3ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "17 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "17 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w2, 0x0fc19dc68b8cd5b5ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "18 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "18 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w3, 0x240ca1cc77ac9c65ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "19 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "19 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w4, 0x2de92c6f592b0275ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "20 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "20 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w5, 0x4a7484aa6ea6e483ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "21 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "21 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//
//        //F(w6, 0x5cb0a9dcbd41fbd4ULL)	;
//        a = FOldFun512_(
//            &a, &b, &c, &d,
//            &e, &f, &g, &h,
//            w6, 0x5cb0a9dcbd41fbd4);
//#ifdef _DEBUG 
//        //fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "22 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "22 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//
//        /*a = FOldFun512(
//            a, b, c, d,
//            e, f, g, h,
//            w6, 0x5cb0a9dcbd41fbd4);*/
//
//
//        F(w7, 0x76f988da831153b5ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "23 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "23 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//
//        /*a = FOldFun512(
//            a, b, c, d,
//            e, f, g, h,
//            w7, 0x76f988da831153b5ULL);*/
//        F(w8, 0x983e5152ee66dfabULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "24 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "24 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w9, 0xa831c66d2db43210ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "25 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "25 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w10, 0xb00327c898fb213fULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "26 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "26 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w11, 0xbf597fc7beef0ee4ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "27 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "27 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w12, 0xc6e00bf33da88fc2ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "28 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "28 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w13, 0xd5a79147930aa725ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "29 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "29 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w14, 0x06ca6351e003826fULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "30 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "30 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        F(w15, 0x142929670a0e6e70ULL)	;
//#ifdef _DEBUG 
//        fprintf(file_coef, "T1 = %I64x\tT2 = %I64x\n", T1, T2);
//        fprintf(file_coef, "31 a = %I64x\tb = %I64x\tc = %I64x\td = %I64x\t", a, b, c, d);
//        fprintf(file_coef, "31 e = %I64x\tf = %I64x\tg = %I64x\th = %I64x\n", e, f, g, h);
//#endif 
//        EXPAND512_old_fun(w);
//#ifdef _DEBUG 
//        fprintf(file_w, "step 2\n");
//        for (int i = 0; i < 16; ++i)
//            fprintf(file_w, "%d\t%I64x\n", i+32, w[i]);
//#endif
//        w0 = w[0];
//        w1 = w[1];
//        w2 = w[2];
//        w3 = w[3];
//        w4 = w[4];
//        w5 = w[5];
//        w6 = w[6];
//        w7 = w[7];
//        w8 = w[8];
//        w9 = w[9];
//        w10 = w[10];
//        w11 = w[11];
//        w12 = w[12];
//        w13 = w[13];
//        w14 = w[14];
//        w15 = w[15];
//
//        F(w0, 0x27b70a8546d22ffcULL)	;
//        F(w1, 0x2e1b21385c26c926ULL)	;
//        F(w2, 0x4d2c6dfc5ac42aedULL)	;
//        F(w3, 0x53380d139d95b3dfULL)	;
//        F(w4, 0x650a73548baf63deULL)	;
//        F(w5, 0x766a0abb3c77b2a8ULL)	;
//        F(w6, 0x81c2c92e47edaee6ULL)	;
//        F(w7, 0x92722c851482353bULL)	;
//        F(w8, 0xa2bfe8a14cf10364ULL)	;
//        F(w9, 0xa81a664bbc423001ULL)	;
//        F(w10, 0xc24b8b70d0f89791ULL)	;
//        F(w11, 0xc76c51a30654be30ULL)	;
//        F(w12, 0xd192e819d6ef5218ULL)	;
//        F(w13, 0xd69906245565a910ULL)	;
//        F(w14, 0xf40e35855771202aULL)	;
//        F(w15, 0x106aa07032bbd1b8ULL)	;
//        EXPAND512_old_fun(w);
//#ifdef _DEBUG 
//        fprintf(file_w, "step 3\n");
//        for (int i = 0; i < 16; ++i)
//            fprintf(file_w, "%d\t%I64x\n", i+48, w[i]);
//#endif
//        w0 = w[0];
//        w1 = w[1];
//        w2 = w[2];
//        w3 = w[3];
//        w4 = w[4];
//        w5 = w[5];
//        w6 = w[6];
//        w7 = w[7];
//        w8 = w[8];
//        w9 = w[9];
//        w10 = w[10];
//        w11 = w[11];
//        w12 = w[12];
//        w13 = w[13];
//        w14 = w[14];
//        w15 = w[15];
//        F(w0, 0x19a4c116b8d2d0c8ULL)	;
//        F(w1, 0x1e376c085141ab53ULL)	;
//        F(w2, 0x2748774cdf8eeb99ULL)	;
//        F(w3, 0x34b0bcb5e19b48a8ULL)	;
//        F(w4, 0x391c0cb3c5c95a63ULL)	;
//        F(w5, 0x4ed8aa4ae3418acbULL)	;
//        F(w6, 0x5b9cca4f7763e373ULL)	;
//        F(w7, 0x682e6ff3d6b2b8a3ULL)	;
//        F(w8, 0x748f82ee5defb2fcULL)	;
//        F(w9, 0x78a5636f43172f60ULL)	;
//        F(w10, 0x84c87814a1f0ab72ULL)	;
//        F(w11, 0x8cc702081a6439ecULL)	;
//        F(w12, 0x90befffa23631e28ULL)	;
//        F(w13, 0xa4506cebde82bde9ULL)	;
//        F(w14, 0xbef9a3f7b2c67915ULL)	;
//        F(w15, 0xc67178f2e372532bULL)	;
//        EXPAND512_old_fun(w);
//#ifdef _DEBUG 
//        fprintf(file_w, "step 4\n");
//        for (int i = 0; i < 16; ++i)
//            fprintf(file_w, "%d\t%I64x\n", i+64, w[i]);
//#endif
//        w0 = w[0];
//        w1 = w[1];
//        w2 = w[2];
//        w3 = w[3];
//        w4 = w[4];
//        w5 = w[5];
//        w6 = w[6];
//        w7 = w[7];
//        w8 = w[8];
//        w9 = w[9];
//        w10 = w[10];
//        w11 = w[11];
//        w12 = w[12];
//        w13 = w[13];
//        w14 = w[14];
//        w15 = w[15];
//        F(w0, 0xca273eceea26619cULL)	;
//        F(w1, 0xd186b8c721c0c207ULL)	;
//        F(w2, 0xeada7dd6cde0eb1eULL)	;
//        F(w3, 0xf57d4f7fee6ed178ULL)	;
//        F(w4, 0x06f067aa72176fbaULL)	;
//        F(w5, 0x0a637dc5a2c898a6ULL)	;
//        F(w6, 0x113f9804bef90daeULL)	;
//        F(w7, 0x1b710b35131c471bULL)	;
//        F(w8, 0x28db77f523047d84ULL)	;
//        F(w9, 0x32caab7b40c72493ULL)	;
//        F(w10, 0x3c9ebe0a15c9bebcULL)	;
//        F(w11, 0x431d67c49c100d4cULL)	;
//        F(w12, 0x4cc5d4becb3e42b6ULL)	;
//        F(w13, 0x597f299cfc657e2aULL)	;
//        F(w14, 0x5fcb6fab3ad6faecULL)	;
//        F(w15, 0x6c44198c4a475817ULL)
//            fclose(file_coef);
//        fclose(file_w);
//        *a_ = a; *b_ = b; *c_ = c; *d_ = d;
//        *e_ = e; *f_ = f; *g_ = g; *h_ = h;
//}

static int crypto_hashblocks_sha512(uint8_t* statebytes, const uint8_t* in, uint32_t inlen)
{
    uint64_t state[8];
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h;
    uint64_t T1;
    uint64_t T2;

    a = load_bigendian(statebytes + 0); state[0] = a;
    b = load_bigendian(statebytes + 8); state[1] = b;
    c = load_bigendian(statebytes + 16); state[2] = c;
    d = load_bigendian(statebytes + 24); state[3] = d;
    e = load_bigendian(statebytes + 32); state[4] = e;
    f = load_bigendian(statebytes + 40); state[5] = f;
    g = load_bigendian(statebytes + 48); state[6] = g;
    h = load_bigendian(statebytes + 56); state[7] = h;

    while (inlen >= 128) {
        uint64_t w0 = load_bigendian(in + 0);
        uint64_t w1 = load_bigendian(in + 8);
        uint64_t w2 = load_bigendian(in + 16);
        uint64_t w3 = load_bigendian(in + 24);
        uint64_t w4 = load_bigendian(in + 32);
        uint64_t w5 = load_bigendian(in + 40);
        uint64_t w6 = load_bigendian(in + 48);
        uint64_t w7 = load_bigendian(in + 56);
        uint64_t w8 = load_bigendian(in + 64);
        uint64_t w9 = load_bigendian(in + 72);
        uint64_t w10 = load_bigendian(in + 80);
        uint64_t w11 = load_bigendian(in + 88);
        uint64_t w12 = load_bigendian(in + 96);
        uint64_t w13 = load_bigendian(in + 104);
        uint64_t w14 = load_bigendian(in + 112);
        uint64_t w15 = load_bigendian(in + 120);
#if 0 
       BLOCK
#else
        F(w0, 0x428a2f98d728ae22ULL)	
            F(w1, 0x7137449123ef65cdULL)	
            F(w2, 0xb5c0fbcfec4d3b2fULL)	
            F(w3, 0xe9b5dba58189dbbcULL)	
            F(w4, 0x3956c25bf348b538ULL)	
            F(w5, 0x59f111f1b605d019ULL)	
            F(w6, 0x923f82a4af194f9bULL)	
            F(w7, 0xab1c5ed5da6d8118ULL)	
            F(w8, 0xd807aa98a3030242ULL)	
            F(w9, 0x12835b0145706fbeULL)	
            F(w10, 0x243185be4ee4b28cULL)	
            F(w11, 0x550c7dc3d5ffb4e2ULL)	
            F(w12, 0x72be5d74f27b896fULL)	
            F(w13, 0x80deb1fe3b1696b1ULL)	
            F(w14, 0x9bdc06a725c71235ULL)	
            F(w15, 0xc19bf174cf692694ULL)	
            EXPAND							
            F(w0, 0xe49b69c19ef14ad2ULL)	
            F(w1, 0xefbe4786384f25e3ULL)	
            F(w2, 0x0fc19dc68b8cd5b5ULL)	
            F(w3, 0x240ca1cc77ac9c65ULL)	
            F(w4, 0x2de92c6f592b0275ULL)	
            F(w5, 0x4a7484aa6ea6e483ULL)	
            F(w6, 0x5cb0a9dcbd41fbd4ULL)	
            F(w7, 0x76f988da831153b5ULL)	
            F(w8, 0x983e5152ee66dfabULL)	
            F(w9, 0xa831c66d2db43210ULL)	
            F(w10, 0xb00327c898fb213fULL)	
            F(w11, 0xbf597fc7beef0ee4ULL)	
            F(w12, 0xc6e00bf33da88fc2ULL)	
            F(w13, 0xd5a79147930aa725ULL)	
            F(w14, 0x06ca6351e003826fULL)	
            F(w15, 0x142929670a0e6e70ULL)	
            EXPAND							
            F(w0, 0x27b70a8546d22ffcULL)	
            F(w1, 0x2e1b21385c26c926ULL)	
            F(w2, 0x4d2c6dfc5ac42aedULL)	
            F(w3, 0x53380d139d95b3dfULL)	
            F(w4, 0x650a73548baf63deULL)	
            F(w5, 0x766a0abb3c77b2a8ULL)	
            F(w6, 0x81c2c92e47edaee6ULL)	
            F(w7, 0x92722c851482353bULL)	
            F(w8, 0xa2bfe8a14cf10364ULL)	
            F(w9, 0xa81a664bbc423001ULL)	
            F(w10, 0xc24b8b70d0f89791ULL)	
            F(w11, 0xc76c51a30654be30ULL)	
            F(w12, 0xd192e819d6ef5218ULL)	
            F(w13, 0xd69906245565a910ULL)	
            F(w14, 0xf40e35855771202aULL)	
            F(w15, 0x106aa07032bbd1b8ULL)	
            EXPAND							
            F(w0, 0x19a4c116b8d2d0c8ULL)	
            F(w1, 0x1e376c085141ab53ULL)	
            F(w2, 0x2748774cdf8eeb99ULL)	
            F(w3, 0x34b0bcb5e19b48a8ULL)	
            F(w4, 0x391c0cb3c5c95a63ULL)	
            F(w5, 0x4ed8aa4ae3418acbULL)	
            F(w6, 0x5b9cca4f7763e373ULL)	
            F(w7, 0x682e6ff3d6b2b8a3ULL)	
            F(w8, 0x748f82ee5defb2fcULL)	
            F(w9, 0x78a5636f43172f60ULL)	
            F(w10, 0x84c87814a1f0ab72ULL)	
            F(w11, 0x8cc702081a6439ecULL)	
            F(w12, 0x90befffa23631e28ULL)	
            F(w13, 0xa4506cebde82bde9ULL)	
            F(w14, 0xbef9a3f7b2c67915ULL)	
            F(w15, 0xc67178f2e372532bULL)	
            EXPAND							
            F(w0, 0xca273eceea26619cULL)	
            F(w1, 0xd186b8c721c0c207ULL)	
            F(w2, 0xeada7dd6cde0eb1eULL)	
            F(w3, 0xf57d4f7fee6ed178ULL)	
            F(w4, 0x06f067aa72176fbaULL)	
            F(w5, 0x0a637dc5a2c898a6ULL)	
            F(w6, 0x113f9804bef90daeULL)	
            F(w7, 0x1b710b35131c471bULL)	
            F(w8, 0x28db77f523047d84ULL)	
            F(w9, 0x32caab7b40c72493ULL)	
            F(w10, 0x3c9ebe0a15c9bebcULL)	
            F(w11, 0x431d67c49c100d4cULL)	
            F(w12, 0x4cc5d4becb3e42b6ULL)	
            F(w13, 0x597f299cfc657e2aULL)	
            F(w14, 0x5fcb6fab3ad6faecULL)	
            F(w15, 0x6c44198c4a475817ULL)

#endif
       /* uint64_t w[16] = { w0, w1, w2, w3, w4, w5, w6, w7,
        w8, w9, w10, w11, w12, w13, w14, w15 };
        funBlock512(&a, &b, &c, &d, &e, &f, &g, &h,
            w);*/

        
        a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 128;
        inlen -= 128;
    }
    store_bigendian(statebytes + 0, state[0]);
    store_bigendian(statebytes + 8, state[1]);
    store_bigendian(statebytes + 16, state[2]);
    store_bigendian(statebytes + 24, state[3]);
    store_bigendian(statebytes + 32, state[4]);
    store_bigendian(statebytes + 40, state[5]);
    store_bigendian(statebytes + 48, state[6]);
    store_bigendian(statebytes + 56, state[7]);

    return inlen;
}


size_t crypto_hashblocks_sha512_currents_(uint64_t* state, const uint8_t* in, size_t inlen)
{
    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];
    uint64_t T1;
    uint64_t T2;

    uint64_t w0, w1, w2, w3 = 0, w4, w5, w6, w7,
        w8, w9, w10, w11, w12, w13, w14, w15;

    while (inlen >= 128)
    {
        w0 = load_bigendian(in + 0);
        w1 = load_bigendian(in + 8);
        w2 = load_bigendian(in + 16);
        w3 = load_bigendian(in + 24);
        w4 = load_bigendian(in + 32);
        w5 = load_bigendian(in + 40);
        w6 = load_bigendian(in + 48);
        w7 = load_bigendian(in + 56);
        w8 = load_bigendian(in + 64);
        w9 = load_bigendian(in + 72);
        w10 = load_bigendian(in + 80);
        w11 = load_bigendian(in + 88);
        w12 = load_bigendian(in + 96);
        w13 = load_bigendian(in + 104);
        w14 = load_bigendian(in + 112);
        w15 = load_bigendian(in + 120);

        F(w0, 0x428a2f98d728ae22ULL)
            F(w1, 0x7137449123ef65cdULL)
            F(w2, 0xb5c0fbcfec4d3b2fULL)
            F(w3, 0xe9b5dba58189dbbcULL)
            F(w4, 0x3956c25bf348b538ULL)
            F(w5, 0x59f111f1b605d019ULL)
            F(w6, 0x923f82a4af194f9bULL)
            F(w7, 0xab1c5ed5da6d8118ULL)
            F(w8, 0xd807aa98a3030242ULL)
            F(w9, 0x12835b0145706fbeULL)
            F(w10, 0x243185be4ee4b28cULL)
            F(w11, 0x550c7dc3d5ffb4e2ULL)
            F(w12, 0x72be5d74f27b896fULL)
            F(w13, 0x80deb1fe3b1696b1ULL)
            F(w14, 0x9bdc06a725c71235ULL)
            F(w15, 0xc19bf174cf692694ULL)

            EXPAND

            F(w0, 0xe49b69c19ef14ad2ULL)
            F(w1, 0xefbe4786384f25e3ULL)
            F(w2, 0x0fc19dc68b8cd5b5ULL)
            F(w3, 0x240ca1cc77ac9c65ULL)
            F(w4, 0x2de92c6f592b0275ULL)
            F(w5, 0x4a7484aa6ea6e483ULL)
            F(w6, 0x5cb0a9dcbd41fbd4ULL)
            F(w7, 0x76f988da831153b5ULL)
            F(w8, 0x983e5152ee66dfabULL)
            F(w9, 0xa831c66d2db43210ULL)
            F(w10, 0xb00327c898fb213fULL)
            F(w11, 0xbf597fc7beef0ee4ULL)
            F(w12, 0xc6e00bf33da88fc2ULL)
            F(w13, 0xd5a79147930aa725ULL)
            F(w14, 0x06ca6351e003826fULL)
            F(w15, 0x142929670a0e6e70ULL)

            EXPAND

            F(w0, 0x27b70a8546d22ffcULL)
            F(w1, 0x2e1b21385c26c926ULL)
            F(w2, 0x4d2c6dfc5ac42aedULL)
            F(w3, 0x53380d139d95b3dfULL)
            F(w4, 0x650a73548baf63deULL)
            F(w5, 0x766a0abb3c77b2a8ULL)
            F(w6, 0x81c2c92e47edaee6ULL)
            F(w7, 0x92722c851482353bULL)
            F(w8, 0xa2bfe8a14cf10364ULL)
            F(w9, 0xa81a664bbc423001ULL)
            F(w10, 0xc24b8b70d0f89791ULL)
            F(w11, 0xc76c51a30654be30ULL)
            F(w12, 0xd192e819d6ef5218ULL)
            F(w13, 0xd69906245565a910ULL)
            F(w14, 0xf40e35855771202aULL)
            F(w15, 0x106aa07032bbd1b8ULL)

            EXPAND

            F(w0, 0x19a4c116b8d2d0c8ULL)
            F(w1, 0x1e376c085141ab53ULL)
            F(w2, 0x2748774cdf8eeb99ULL)
            F(w3, 0x34b0bcb5e19b48a8ULL)
            F(w4, 0x391c0cb3c5c95a63ULL)
            F(w5, 0x4ed8aa4ae3418acbULL)
            F(w6, 0x5b9cca4f7763e373ULL)
            F(w7, 0x682e6ff3d6b2b8a3ULL)
            F(w8, 0x748f82ee5defb2fcULL)
            F(w9, 0x78a5636f43172f60ULL)
            F(w10, 0x84c87814a1f0ab72ULL)
            F(w11, 0x8cc702081a6439ecULL)
            F(w12, 0x90befffa23631e28ULL)
            F(w13, 0xa4506cebde82bde9ULL)
            F(w14, 0xbef9a3f7b2c67915ULL)
            F(w15, 0xc67178f2e372532bULL)

            EXPAND

            F(w0, 0xca273eceea26619cULL)
            F(w1, 0xd186b8c721c0c207ULL)
            F(w2, 0xeada7dd6cde0eb1eULL)
            F(w3, 0xf57d4f7fee6ed178ULL)
            F(w4, 0x06f067aa72176fbaULL)
            F(w5, 0x0a637dc5a2c898a6ULL)
            F(w6, 0x113f9804bef90daeULL)
            F(w7, 0x1b710b35131c471bULL)
            F(w8, 0x28db77f523047d84ULL)
            F(w9, 0x32caab7b40c72493ULL)
            F(w10, 0x3c9ebe0a15c9bebcULL)
            F(w11, 0x431d67c49c100d4cULL)
            F(w12, 0x4cc5d4becb3e42b6ULL)
            F(w13, 0x597f299cfc657e2aULL)
            F(w14, 0x5fcb6fab3ad6faecULL)
            F(w15, 0x6c44198c4a475817ULL)

            a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 128;
        inlen -= 128;
    }

    /*state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;*/

    return inlen;
}


void sha512_predcalc_pk(uint64_t* state64, const uint8_t* in_)
{
    
    uint64_t a = 0x6a09e667f3bcc908;
    uint64_t b = 0xbb67ae8584caa73b;
    uint64_t c = 0x3c6ef372fe94f82b;
    uint64_t d = 0xa54ff53a5f1d36f1;
    uint64_t e = 0x510e527fade682d1;
    uint64_t f = 0x9b05688c2b3e6c1f;
    uint64_t g = 0x1f83d9abfb41bd6b;
    uint64_t h = 0x5be0cd19137e2179;
    uint64_t T1;
    uint64_t T2;

    uint64_t w0, w1, w2, w3 = 0, w4 = 0, w5 = 0, w6 = 0, w7 = 0,
        w8 = 0, w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = 0, w15 = 0;
    uint8_t in[128] = { 0 };
    memcpy(in, in_, FIPS205_N);
    //while (inlen >= 128) 
    {
        w0 = load_bigendian(in + 0);
        w1 = load_bigendian(in + 8);
        w2 = load_bigendian(in + 16);
#if FIPS205_N == 32
        w3 = load_bigendian(in + 24);
#endif

        F(w0, 0x428a2f98d728ae22ULL)
            F(w1, 0x7137449123ef65cdULL)
            F(w2, 0xb5c0fbcfec4d3b2fULL)
            F(w3, 0xe9b5dba58189dbbcULL)
            F(w4, 0x3956c25bf348b538ULL)
            F(w5, 0x59f111f1b605d019ULL)
            F(w6, 0x923f82a4af194f9bULL)
            F(w7, 0xab1c5ed5da6d8118ULL)
            F(w8, 0xd807aa98a3030242ULL)
            F(w9, 0x12835b0145706fbeULL)
            F(w10, 0x243185be4ee4b28cULL)
            F(w11, 0x550c7dc3d5ffb4e2ULL)
            F(w12, 0x72be5d74f27b896fULL)
            F(w13, 0x80deb1fe3b1696b1ULL)
            F(w14, 0x9bdc06a725c71235ULL)
            F(w15, 0xc19bf174cf692694ULL)

            EXPAND

            F(w0, 0xe49b69c19ef14ad2ULL)
            F(w1, 0xefbe4786384f25e3ULL)
            F(w2, 0x0fc19dc68b8cd5b5ULL)
            F(w3, 0x240ca1cc77ac9c65ULL)
            F(w4, 0x2de92c6f592b0275ULL)
            F(w5, 0x4a7484aa6ea6e483ULL)
            F(w6, 0x5cb0a9dcbd41fbd4ULL)
            F(w7, 0x76f988da831153b5ULL)
            F(w8, 0x983e5152ee66dfabULL)
            F(w9, 0xa831c66d2db43210ULL)
            F(w10, 0xb00327c898fb213fULL)
            F(w11, 0xbf597fc7beef0ee4ULL)
            F(w12, 0xc6e00bf33da88fc2ULL)
            F(w13, 0xd5a79147930aa725ULL)
            F(w14, 0x06ca6351e003826fULL)
            F(w15, 0x142929670a0e6e70ULL)

            EXPAND

            F(w0, 0x27b70a8546d22ffcULL)
            F(w1, 0x2e1b21385c26c926ULL)
            F(w2, 0x4d2c6dfc5ac42aedULL)
            F(w3, 0x53380d139d95b3dfULL)
            F(w4, 0x650a73548baf63deULL)
            F(w5, 0x766a0abb3c77b2a8ULL)
            F(w6, 0x81c2c92e47edaee6ULL)
            F(w7, 0x92722c851482353bULL)
            F(w8, 0xa2bfe8a14cf10364ULL)
            F(w9, 0xa81a664bbc423001ULL)
            F(w10, 0xc24b8b70d0f89791ULL)
            F(w11, 0xc76c51a30654be30ULL)
            F(w12, 0xd192e819d6ef5218ULL)
            F(w13, 0xd69906245565a910ULL)
            F(w14, 0xf40e35855771202aULL)
            F(w15, 0x106aa07032bbd1b8ULL)

            EXPAND

            F(w0, 0x19a4c116b8d2d0c8ULL)
            F(w1, 0x1e376c085141ab53ULL)
            F(w2, 0x2748774cdf8eeb99ULL)
            F(w3, 0x34b0bcb5e19b48a8ULL)
            F(w4, 0x391c0cb3c5c95a63ULL)
            F(w5, 0x4ed8aa4ae3418acbULL)
            F(w6, 0x5b9cca4f7763e373ULL)
            F(w7, 0x682e6ff3d6b2b8a3ULL)
            F(w8, 0x748f82ee5defb2fcULL)
            F(w9, 0x78a5636f43172f60ULL)
            F(w10, 0x84c87814a1f0ab72ULL)
            F(w11, 0x8cc702081a6439ecULL)
            F(w12, 0x90befffa23631e28ULL)
            F(w13, 0xa4506cebde82bde9ULL)
            F(w14, 0xbef9a3f7b2c67915ULL)
            F(w15, 0xc67178f2e372532bULL)

            EXPAND

            F(w0, 0xca273eceea26619cULL)
            F(w1, 0xd186b8c721c0c207ULL)
            F(w2, 0xeada7dd6cde0eb1eULL)
            F(w3, 0xf57d4f7fee6ed178ULL)
            F(w4, 0x06f067aa72176fbaULL)
            F(w5, 0x0a637dc5a2c898a6ULL)
            F(w6, 0x113f9804bef90daeULL)
            F(w7, 0x1b710b35131c471bULL)
            F(w8, 0x28db77f523047d84ULL)
            F(w9, 0x32caab7b40c72493ULL)
            F(w10, 0x3c9ebe0a15c9bebcULL)
            F(w11, 0x431d67c49c100d4cULL)
            F(w12, 0x4cc5d4becb3e42b6ULL)
            F(w13, 0x597f299cfc657e2aULL)
            F(w14, 0x5fcb6fab3ad6faecULL)
            F(w15, 0x6c44198c4a475817ULL)
        

        
}

    state64[0] = a + 0x6a09e667f3bcc908;
    state64[1] = b + 0xbb67ae8584caa73b;
    state64[2] = c + 0x3c6ef372fe94f82b;
    state64[3] = d + 0xa54ff53a5f1d36f1;
    state64[4] = e + 0x510e527fade682d1;
    state64[5] = f + 0x9b05688c2b3e6c1f;
    state64[6] = g + 0x1f83d9abfb41bd6b;
    state64[7] = h + 0x5be0cd19137e2179;

    
}

//void predcalc_pk_sha512(uint64_t* state64, const uint8_t* in_)
//{
//#if 0
//    uint64_t a = 0x6a09e667f3bcc908;
//    uint64_t b = 0xbb67ae8584caa73b;
//    uint64_t c = 0x3c6ef372fe94f82b;
//    uint64_t d = 0xa54ff53a5f1d36f1;
//    uint64_t e = 0x510e527fade682d1;
//    uint64_t f = 0x9b05688c2b3e6c1f;
//    uint64_t g = 0x1f83d9abfb41bd6b;
//    uint64_t h = 0x5be0cd19137e2179;
//    uint64_t T1;
//    uint64_t T2;
//
//    uint64_t w0, w1, w2, w3 = 0, w4 = 0, w5 = 0, w6 = 0, w7 = 0,
//        w8 = 0, w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = 0, w15 = 0;
//    uint8_t in[128] = { 0 };
//    memcpy(in, in_, FIPS205_N);
//    
//    {
//        w0 = load_bigendian(in + 0);
//        w1 = load_bigendian(in + 8);
//        w2 = load_bigendian(in + 16);
//#if FIPS205_N == 32
//        w3 = load_bigendian(in + 24);
//#endif
//
//        BLOCK
//    }
//
//    state64[0] = a + 0x6a09e667f3bcc908;
//    state64[1] = b + 0xbb67ae8584caa73b;
//    state64[2] = c + 0x3c6ef372fe94f82b;
//    state64[3] = d + 0xa54ff53a5f1d36f1;
//    state64[4] = e + 0x510e527fade682d1;
//    state64[5] = f + 0x9b05688c2b3e6c1f;
//    state64[6] = g + 0x1f83d9abfb41bd6b;
//    state64[7] = h + 0x5be0cd19137e2179;
//
//#else
//    memcpy(state64, HInit, sizeof(HInit));
//    __declspec (align (64))
//        uint8_t temp[64];
//    memcpy(temp, in, FIPS205_N);
//    memset(temp + FIPS205_N, 0, 128 - FIPS205_N);
//    const __m256i maska = _mm256_load_si256((const __m256i*)u8_maska);
//    __m256i* temp256 = (__m256i*)temp;
//    temp256[0] = _mm256_shuffle_epi8(temp256[0], maska);
//    temp256[1] = _mm256_shuffle_epi8(temp256[1], maska);
//    AVX_sha256_compress(state, temp256);
//#endif
//        
//}

static void crypto_hashblocks_sha512_2_(uint8_t* out, uint64_t* state, const uint8_t* in)
{
    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];
    uint64_t T1;
    uint64_t T2;

    uint64_t w0, w1, w2, w3 = 0, w4, w5, w6, w7,
        w8, w9, w10, w11, w12, w13, w14, w15;

    
    {
        w0 = load_bigendian(in + 0);
        w1 = load_bigendian(in + 8);
        w2 = load_bigendian(in + 16);
        w3 = load_bigendian(in + 24);
        w4 = load_bigendian(in + 32);
        w5 = load_bigendian(in + 40);
        w6 = load_bigendian(in + 48);
        w7 = load_bigendian(in + 56);
        w8 = load_bigendian(in + 64);
        w9 = load_bigendian(in + 72);
        w10 = load_bigendian(in + 80);
        w11 = load_bigendian(in + 88);
        w12 = load_bigendian(in + 96);
        w13 = load_bigendian(in + 104);
        w14 = load_bigendian(in + 112);
        w15 = load_bigendian(in + 120);

        BLOCK

    }

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];

    store_bigendian(out + 0, a);
    store_bigendian(out + 8, b);
    store_bigendian(out + 16, c);
    store_bigendian(out + 24, d);
    store_bigendian(out + 32, e);
    store_bigendian(out + 40, f);
    store_bigendian(out + 48, g);
    store_bigendian(out + 56, h);

//#endif
    

}

static uint64_t HInit[8] =
{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
           0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const uint8_t iv512[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
};

void sha512(uint8_t* out, const uint8_t* in, size_t inlen)
{
    //uint8_t h[64];
    uint8_t padded[256];
    unsigned int i;
    size_t bytes = inlen;
    uint8_t temp[64];
    for (i = 0; i < 64; ++i) temp[i] = iv512[i];
    crypto_hashblocks_sha512(temp, in, inlen);
    in += inlen;
    inlen &= 127;
    in -= inlen;

    for (i = 0; i < inlen; ++i) padded[i] = in[i];
    padded[inlen] = 0x80;

    if (inlen < 112) {
        for (i = inlen + 1; i < 119; ++i) padded[i] = 0;
        /*padded[119] = (uint8_t)(bytes >> 61);
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);*/
        WL128(padded, bytes)
        //blocks(h, padded, 128);
        crypto_hashblocks_sha512(temp, padded, 128);
    }
    else {
        for (i = inlen + 1; i < 247; ++i) padded[i] = 0;
        /*
        padded[247] = (uint8_t)(bytes >> 61);
        padded[248] = (uint8_t)(bytes >> 53);
        padded[249] = (uint8_t)(bytes >> 45);
        padded[250] = (uint8_t)(bytes >> 37);
        padded[251] = (uint8_t)(bytes >> 29);
        padded[252] = (uint8_t)(bytes >> 21);
        padded[253] = (uint8_t)(bytes >> 13);
        padded[254] = (uint8_t)(bytes >> 5);
        padded[255] = (uint8_t)(bytes << 3);
        */
        WL256(padded, bytes)
        //blocks(h, padded, 256);
        crypto_hashblocks_sha512(temp, padded, 256);
    }

    for (i = 0; i < 64; ++i) out[i] = temp[i];
}

void sha512_with_predcalc2_(uint8_t* out, uint64_t* state, const uint8_t* in, uint32_t inlen)
{
    //uint8_t h[64];
    uint8_t padded[256];
    unsigned int i;
    size_t bytes = 128 + inlen;

    
    for (i = 0; i < inlen; ++i) padded[i] = in[i];
    padded[inlen] = 0x80;

    
    {
        for (i = inlen + 1; i < 119; ++i) padded[i] = 0;
        /*padded[119] = bytes >> 61;
        padded[120] = bytes >> 53;
        padded[121] = bytes >> 45;
        padded[122] = bytes >> 37;
        padded[123] = bytes >> 29;
        padded[124] = bytes >> 21;
        padded[125] = bytes >> 13;
        padded[126] = bytes >> 5;
        padded[127] = bytes << 3;
        */
        WL128(padded, bytes)

    }
    uint8_t temp[64];
    crypto_hashblocks_sha512_2_(temp, state, padded);
    memcpy(out, temp, FIPS205_N);

    
}

//void AVX_sha512_predcalc_pk(uint64_t* state64, const uint8_t* in);
#if FIPS205_N > 16
//int test_sha512_with_predcalc()
//{
//    size_t i;
//    uint8_t pk[FIPS205_N], sk[FIPS205_N];
//    uint8_t adr[22];
//    uint8_t in[128 + 22 + FIPS205_N] = { 0 };
//    uint8_t out1[64], out2[64];
//    uint64_t state[8];
//
//    srand(0);
//    for (i = 0; i < FIPS205_N; ++i)
//    {
//        pk[i] = rand() % 256;
//        sk[i] = rand() % 256;
//    }
//    for (i = 0; i < 22; ++i)
//        adr[i] = rand() % 256;
//    memcpy(in, pk, FIPS205_N);
//    memcpy(in + 128, adr, 22);
//    memcpy(in + 128 + 22, sk, FIPS205_N);
//    sha512(out1, in, 128 + 22 + FIPS205_N);
//    AVX_sha512_predcalc_pk(state, in);
//    size_t inlen = 22 + FIPS205_N;
//    sha512_with_predcalc2_(out2, state, in + 128, inlen);
//    int res = 0;
//    for (i = 0; i < FIPS205_N; ++i)
//    {
//        if (out1[i] != out2[i])
//            res = 1;
//    }
//    return res;
//}
//
//int test_sha512()
//{
//    uint8_t in[4] = "abc";
//    uint8_t h[64];
//    /*
//    ddaf35a193617abacc417349ae2041311
//    2e6fa4e89a97ea20a9eeee64b55d39a21
//    92992a274fc1a836ba3c23a3feebbd454
//    d4423643ce80e2a9ac94fa54ca49f
//    */
//    sha512(h, in, 3, 64);
//    int res = 0;
//    if (h[0] != 0xdd || h[1] != 0xaf || h[2] != 0x35)
//        res = 1;
//    return res;
//}

#endif
void HMAC512(uint8_t* dest, const uint8_t* sk, const uint8_t* src, uint32_t len)
{

    #define	BLOCKSIZE	128

    uint8_t buf[BLOCKSIZE + BLOCKSIZE / 2]; // oKey
    uint8_t* temp = malloc(BLOCKSIZE + len);    //      ikey
    if (temp)
    {
        uint32_t i;
        
        for (i = 0; i < FIPS205_N; ++i)
        {
            temp[i] = sk[i] ^ 0x36;
        }

        for (i = 0; i < BLOCKSIZE - FIPS205_N; ++i)
        {
            temp[FIPS205_N + i] = 0x36;
        }
        for (i = 0; i < len; i++)
            temp[BLOCKSIZE + i] = src[i];

        for (i = 0; i < FIPS205_N; ++i)
        {
            buf[i] = sk[i] ^ 0x5C;
        }

        for (i = 0; i < BLOCKSIZE - FIPS205_N; ++i)
        {
            buf[FIPS205_N + i] = 0x5C;
        }


        //cur += BLOCKSIZE - N;



        sha512(buf + BLOCKSIZE, temp, BLOCKSIZE + len);
        sha512(buf, buf, BLOCKSIZE + BLOCKSIZE / 2);
        memcpy(dest, buf, FIPS205_N);
        
        /*for (i = 0; i < 64; ++i)
        {
            dest[i] = temp[i];
        }*/
        
        free(temp);
    }


}

//int test_HMAC512()
//{
//    uint8_t Key[20] = {0};
//    memset(Key, 0x0b, 20);
//    uint8_t Data[] = "Hi There";
//    uint8_t etalon[] = {
//        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
//        0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
//        0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
//        0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
//        0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02,
//        0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
//        0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
//        0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54
//    }, calc_res[64];
//    HMAC512(calc_res, Key, sizeof(Key), Data, (uint32_t)strlen(Data), 64);
//    int res = memcmp(calc_res, etalon, 64);
//    return res;
//}

void MGF1_sha512(uint8_t* out, uint32_t outlen,
    const uint8_t* in, uint32_t inlen)
{
    uint8_t* inbuf = (uint8_t*)malloc(inlen + 4);
    uint8_t outbuf[64];
    unsigned i;

    memcpy(inbuf, in, inlen);

        /* While we can fit in at least another full block of SHA256 output.. */
    uint32_t blocks = outlen / 64;
    uint8_t* pend = inbuf + inlen;
    for (i = 0; i < blocks; i++) {
        toByte32_(pend, i);
        sha512 (out, inbuf, inlen + 4);
        out += 64;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > blocks * 64) {
        toByte32_(pend, i);
        sha512 (outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i * 64);
    }
    free(inbuf);
}

size_t sha512_with_predcalc_(uint8_t* out, uint64_t* predcalc_pk, uint8_t* in, size_t inlen)
{
    uint64_t state[8];
    size_t bytes = 128 + inlen;
    memcpy(state, predcalc_pk, 8 * 8);
    size_t curlen = crypto_hashblocks_sha512_currents_(
        state, in, inlen);
    in = in + inlen - curlen;
    inlen = curlen;
    uint8_t padded[256];
    size_t i;

    for (i = 0; i < inlen; ++i) padded[i] = in[i];
    padded[inlen] = 0x80;

    if (inlen < 112)
    {
        for (i = inlen + 1; i < 119; ++i) padded[i] = 0;
        WL128(padded, bytes)
        /*padded[119] = bytes >> 61;
        padded[120] = bytes >> 53;
        padded[121] = bytes >> 45;
        padded[122] = bytes >> 37;
        padded[123] = bytes >> 29;
        padded[124] = bytes >> 21;
        padded[125] = bytes >> 13;
        padded[126] = bytes >> 5;
        padded[127] = bytes << 3;*/
        crypto_hashblocks_sha512_2_(out, state, padded);

    }
    else {
        for (i = inlen + 1; i < 247; ++i) padded[i] = 0;
        WL256(padded, bytes)
            /*padded[247] = bytes >> 61;
            padded[248] = bytes >> 53;
            padded[249] = bytes >> 45;
            padded[250] = bytes >> 37;
            padded[251] = bytes >> 29;
            padded[252] = bytes >> 21;
            padded[253] = bytes >> 13;
            padded[254] = bytes >> 5;
            padded[255] = bytes << 3;*/
            crypto_hashblocks_sha512_currents_(state, padded, 256);

        store_bigendian(out + 0, state[0]);
        store_bigendian(out + 8, state[1]);
        store_bigendian(out + 16, state[2]);
        store_bigendian(out + 24, state[3]);
    }
    
//#if FIPS205_N == 32
//        store_bigendian(out + 24, state[3]);
//#endif
//#if 0
//        store_bigendian(out + 32, state[4]);
//        store_bigendian(out + 40, state[5]);
//        store_bigendian(out + 48, state[6]);
//        store_bigendian(out + 56, state[7]);
//#endif
}

//void sha512_with_predcalc2_(uint8_t* out, uint64_t* state, const uint8_t* in, size_t inlen)
//{
//    uint8_t h[64];
//    uint8_t padded[256];
//    unsigned int i;
//    size_t bytes = 128 + inlen;
//
//    //for (i = 0; i < 64; ++i) h[i] = state[i];
//
//    //blocks(h, in, inlen);
//    /*in += inlen;
//    inlen &= 127;
//    in -= inlen;*/
//    //size_t inlen = 22 + N;
//
//    for (i = 0; i < inlen; ++i) padded[i] = in[i];
//    padded[inlen] = 0x80;
//
//    //if (inlen < 112) 
//    {
//        for (i = inlen + 1; i < 119; ++i) padded[i] = 0;
//        padded[119] = bytes >> 61;
//        padded[120] = bytes >> 53;
//        padded[121] = bytes >> 45;
//        padded[122] = bytes >> 37;
//        padded[123] = bytes >> 29;
//        padded[124] = bytes >> 21;
//        padded[125] = bytes >> 13;
//        padded[126] = bytes >> 5;
//        padded[127] = bytes << 3;
//        //blocks(h, padded, 128);
//
//    }
//    /*else {
//        for (i = inlen + 1; i < 247; ++i) padded[i] = 0;
//        padded[247] = bytes >> 61;
//        padded[248] = bytes >> 53;
//        padded[249] = bytes >> 45;
//        padded[250] = bytes >> 37;
//        padded[251] = bytes >> 29;
//        padded[252] = bytes >> 21;
//        padded[253] = bytes >> 13;
//        padded[254] = bytes >> 5;
//        padded[255] = bytes << 3;
//        blocks(h, padded, 256);
//    }*/
//
//    crypto_hashblocks_sha512_2_(out, state, padded);
//
//    //for (i = 0; i < 64; ++i) out[i] = h[i];
//}




    

