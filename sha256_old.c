/* Adapted from Public Domain code by D. J. Bernstein. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>


#include "FIPS_205_Common_fun_old.h"
#include "sha2.h"
#include "SHA512.h"
//#include ""

void u32_to_bytes_(unsigned char* out, uint32_t in)
{
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

static uint32_t load_bigendian(const uint8_t *x)
{
  return
      (uint32_t) (x[3]) \
  | (((uint32_t) (x[2])) << 8) \
  | (((uint32_t) (x[1])) << 16) \
  | (((uint32_t) (x[0])) << 24)
  ;
}

static void store_bigendian(uint8_t *x,uint32_t u)
{
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(w,k) \
  T1 = h + Sigma1(e) + Ch(e,f,g) + k + w; \
  T2 = Sigma0(a) + Maj(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;

#define NEXT_STEP   \
F(w0, 0x428a2f98)   \
F(w1, 0x71374491)   \
F(w2, 0xb5c0fbcf)   \
F(w3, 0xe9b5dba5)   \
F(w4, 0x3956c25b)   \
F(w5, 0x59f111f1)   \
F(w6, 0x923f82a4)   \
F(w7, 0xab1c5ed5)   \
F(w8, 0xd807aa98)   \
F(w9, 0x12835b01)   \
F(w10, 0x243185be)   \
F(w11, 0x550c7dc3)   \
F(w12, 0x72be5d74)   \
F(w13, 0x80deb1fe)   \
F(w14, 0x9bdc06a7)   \
F(w15, 0xc19bf174)   \
   \
EXPAND   \
   \
F(w0, 0xe49b69c1)   \
F(w1, 0xefbe4786)   \
F(w2, 0x0fc19dc6)   \
F(w3, 0x240ca1cc)   \
F(w4, 0x2de92c6f)   \
F(w5, 0x4a7484aa)   \
F(w6, 0x5cb0a9dc)   \
F(w7, 0x76f988da)   \
F(w8, 0x983e5152)   \
F(w9, 0xa831c66d)   \
F(w10, 0xb00327c8)   \
F(w11, 0xbf597fc7)   \
F(w12, 0xc6e00bf3)   \
F(w13, 0xd5a79147)   \
F(w14, 0x06ca6351)   \
F(w15, 0x14292967)   \
   \
EXPAND   \
   \
F(w0, 0x27b70a85)   \
F(w1, 0x2e1b2138)   \
F(w2, 0x4d2c6dfc)   \
F(w3, 0x53380d13)   \
F(w4, 0x650a7354)   \
F(w5, 0x766a0abb)   \
F(w6, 0x81c2c92e)   \
F(w7, 0x92722c85)   \
F(w8, 0xa2bfe8a1)   \
F(w9, 0xa81a664b)   \
F(w10, 0xc24b8b70)   \
F(w11, 0xc76c51a3)   \
F(w12, 0xd192e819)   \
F(w13, 0xd6990624)   \
F(w14, 0xf40e3585)   \
F(w15, 0x106aa070)   \
   \
EXPAND   \
   \
F(w0, 0x19a4c116)   \
F(w1, 0x1e376c08)   \
F(w2, 0x2748774c)   \
F(w3, 0x34b0bcb5)   \
F(w4, 0x391c0cb3)   \
F(w5, 0x4ed8aa4a)   \
F(w6, 0x5b9cca4f)   \
F(w7, 0x682e6ff3)   \
F(w8, 0x748f82ee)   \
F(w9, 0x78a5636f)   \
F(w10, 0x84c87814)   \
F(w11, 0x8cc70208)   \
F(w12, 0x90befffa)   \
F(w13, 0xa4506ceb)   \
F(w14, 0xbef9a3f7)   \
F(w15, 0xc67178f2)   


static int crypto_hashblocks_sha256(uint8_t *statebytes,const uint8_t *in,size_t inlen)
{
  uint32_t state[8];
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t h;
  uint32_t T1;
  uint32_t T2;

  // 0x682E6FF3
  a = load_bigendian(statebytes +  0); state[0] = a;
  b = load_bigendian(statebytes +  4); state[1] = b;
  c = load_bigendian(statebytes +  8); state[2] = c;
  d = load_bigendian(statebytes + 12); state[3] = d;
  e = load_bigendian(statebytes + 16); state[4] = e;
  f = load_bigendian(statebytes + 20); state[5] = f;
  g = load_bigendian(statebytes + 24); state[6] = g;
  h = load_bigendian(statebytes + 28); state[7] = h;

  while (inlen >= 64) {
    uint32_t w0  = load_bigendian(in +  0);
    uint32_t w1  = load_bigendian(in +  4);
    uint32_t w2  = load_bigendian(in +  8);
    uint32_t w3  = load_bigendian(in + 12);
    uint32_t w4  = load_bigendian(in + 16);
    uint32_t w5  = load_bigendian(in + 20);
    uint32_t w6  = load_bigendian(in + 24);
    uint32_t w7  = load_bigendian(in + 28);
    uint32_t w8  = load_bigendian(in + 32);
    uint32_t w9  = load_bigendian(in + 36);
    uint32_t w10 = load_bigendian(in + 40);
    uint32_t w11 = load_bigendian(in + 44);
    uint32_t w12 = load_bigendian(in + 48);
    uint32_t w13 = load_bigendian(in + 52);
    uint32_t w14 = load_bigendian(in + 56);
    uint32_t w15 = load_bigendian(in + 60);

    NEXT_STEP
        
    /*F(w0 ,0x428a2f98)
    F(w1 ,0x71374491)
    F(w2 ,0xb5c0fbcf)
    F(w3 ,0xe9b5dba5)
    F(w4 ,0x3956c25b)
    F(w5 ,0x59f111f1)
    F(w6 ,0x923f82a4)
    F(w7 ,0xab1c5ed5)
    F(w8 ,0xd807aa98)
    F(w9 ,0x12835b01)
    F(w10,0x243185be)
    F(w11,0x550c7dc3)
    F(w12,0x72be5d74)
    F(w13,0x80deb1fe)
    F(w14,0x9bdc06a7)
    F(w15,0xc19bf174)

    EXPAND
    
    F(w0 ,0xe49b69c1)
    F(w1 ,0xefbe4786)
    F(w2 ,0x0fc19dc6)
    F(w3 ,0x240ca1cc)
    F(w4 ,0x2de92c6f)
    F(w5 ,0x4a7484aa)
    F(w6 ,0x5cb0a9dc)
    F(w7 ,0x76f988da)
    F(w8 ,0x983e5152)
    F(w9 ,0xa831c66d)
    F(w10,0xb00327c8)
    F(w11,0xbf597fc7)
    F(w12,0xc6e00bf3)
    F(w13,0xd5a79147)
    F(w14,0x06ca6351)
    F(w15,0x14292967)

    EXPAND

    F(w0 ,0x27b70a85)
    F(w1 ,0x2e1b2138)
    F(w2 ,0x4d2c6dfc)
    F(w3 ,0x53380d13)
    F(w4 ,0x650a7354)
    F(w5 ,0x766a0abb)
    F(w6 ,0x81c2c92e)
    F(w7 ,0x92722c85)
    F(w8 ,0xa2bfe8a1)
    F(w9 ,0xa81a664b)
    F(w10,0xc24b8b70)
    F(w11,0xc76c51a3)
    F(w12,0xd192e819)
    F(w13,0xd6990624)
    F(w14,0xf40e3585)
    F(w15,0x106aa070)

    EXPAND

    F(w0 ,0x19a4c116)
    F(w1 ,0x1e376c08)
    F(w2 ,0x2748774c)
    F(w3 ,0x34b0bcb5)
    F(w4 ,0x391c0cb3)
    F(w5 ,0x4ed8aa4a)
    F(w6 ,0x5b9cca4f)
    F(w7 ,0x682e6ff3)
    F(w8 ,0x748f82ee)
    F(w9 ,0x78a5636f)
    F(w10,0x84c87814)
    F(w11,0x8cc70208)
    F(w12,0x90befffa)
    F(w13,0xa4506ceb)
    F(w14,0xbef9a3f7)
    F(w15,0xc67178f2)*/

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

    in += 64;
    inlen -= 64;
  }

  store_bigendian(statebytes +  0,state[0]);
  store_bigendian(statebytes +  4,state[1]);
  store_bigendian(statebytes +  8,state[2]);
  store_bigendian(statebytes + 12,state[3]);
  store_bigendian(statebytes + 16,state[4]);
  store_bigendian(statebytes + 20,state[5]);
  store_bigendian(statebytes + 24,state[6]);
  store_bigendian(statebytes + 28,state[7]);

  return (int)inlen;
}

#define blocks crypto_hashblocks_sha256

static const uint8_t iv[32] = {
  0x6a,0x09,0xe6,0x67,
  0xbb,0x67,0xae,0x85,
  0x3c,0x6e,0xf3,0x72,
  0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f,
  0x9b,0x05,0x68,0x8c,
  0x1f,0x83,0xd9,0xab,
  0x5b,0xe0,0xcd,0x19,
} ;


static const uint8_t iv_224[32] = {
#if 1
    0xc1, 0x05, 0x9e, 0xd8,
    0x36, 0x7c, 0xd5, 0x07,
    0x30, 0x70, 0xdd, 0x17,
    0xf7, 0x0e, 0x59, 0x39,
    0Xff, 0xc0, 0x0b, 0x31,
    0X68, 0x58, 0x15, 0x11,
    0X64, 0xf9, 0x8f, 0xa7,
    0Xbe, 0xfa, 0x4f, 0xa4
#else
H0
= c1059ed8
)0(H1 = 367cd507
)0(H2 = 3070dd17
)0(H3 = f70e5939
)0(H4 = ffc00b31
)0(H5 = 68581511
)0(H6 = 64f98fa7
15)0(H7 = befa4fa4
#endif
};

//void sha256(uint8_t *out,const uint8_t *in,size_t inlen)
//{
//  uint8_t h[32];
//  uint8_t padded[128];
//  unsigned int i;
//  size_t bits = inlen << 3;
//
//  for (i = 0;i < 32;++i) h[i] = iv[i];
//
//  blocks(h,in,inlen);
//  in += inlen;
//  inlen &= 63;
//  in -= inlen;
//
//  for (i = 0;i < inlen;++i) padded[i] = in[i];
//  padded[inlen] = 0x80;
//
//  if (inlen < 56) {
//    for (i = inlen + 1;i < 56;++i) padded[i] = 0;
//    padded[56] = bits >> 56;
//    padded[57] = bits >> 48;
//    padded[58] = bits >> 40;
//    padded[59] = bits >> 32;
//    padded[60] = bits >> 24;
//    padded[61] = bits >> 16;
//    padded[62] = bits >> 8;
//    padded[63] = bits;
//    blocks(h,padded,64);
//  } else {
//    for (i = inlen + 1;i < 120;++i) padded[i] = 0;
//    padded[120] = bits >> 56;
//    padded[121] = bits >> 48;
//    padded[122] = bits >> 40;
//    padded[123] = bits >> 32;
//    padded[124] = bits >> 24;
//    padded[125] = bits >> 16;
//    padded[126] = bits >> 8;
//    padded[127] = bits;
//    blocks(h,padded,128);
//  }
//
//  for (i = 0;i < 32;++i) out[i] = h[i];
//}

void sha224(uint8_t* out, const uint8_t* in, size_t inlen)
{
    uint8_t h[32];
    uint8_t padded[128];
    size_t i;
    size_t bits = inlen << 3;

    for (i = 0; i < 32; ++i) h[i] = iv_224[i];

    blocks(h, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;

    for (i = 0; i < inlen; ++i) padded[i] = in[i];
    padded[inlen] = 0x80;

    if (inlen < 56) {
        for (i = inlen + 1; i < 56; ++i) padded[i] = 0;
        padded[56] = (uint8_t)(bits >> 56);
        padded[57] = (uint8_t)(bits >> 48);
        padded[58] = (uint8_t)(bits >> 40);
        padded[59] = (uint8_t)(bits >> 32);
        padded[60] = (uint8_t)(bits >> 24);
        padded[61] = (uint8_t)(bits >> 16);
        padded[62] = (uint8_t)(bits >> 8);
        padded[63] = (uint8_t)bits;
        blocks(h, padded, 64);
    }
    else {
        for (i = inlen + 1; i < 120; ++i) padded[i] = 0;
        padded[120] = (uint8_t)(bits >> 56);
        padded[121] = (uint8_t)(bits >> 48);
        padded[122] = (uint8_t)(bits >> 40);
        padded[123] = (uint8_t)(bits >> 32);
        padded[124] = (uint8_t)(bits >> 24);
        padded[125] = (uint8_t)(bits >> 16);
        padded[126] = (uint8_t)(bits >> 8);
        padded[127] = (uint8_t)bits;
        blocks(h, padded, 128);
    }

    for (i = 0; i < 28; ++i) out[i] = h[i];
}

//void u32_to_bytes(unsigned char* out, uint32_t in)
//{
//    out[0] = (unsigned char)(in >> 24);
//    out[1] = (unsigned char)(in >> 16);
//    out[2] = (unsigned char)(in >> 8);
//    out[3] = (unsigned char)in;
//}
//void u32_to_bytes(unsigned char* out, uint32_t in)
//{
//    out[0] = (unsigned char)(in >> 24);
//    out[1] = (unsigned char)(in >> 16);
//    out[2] = (unsigned char)(in >> 8);
//    out[3] = (unsigned char)in;
//}

void mgf1_sha256(unsigned char* out, unsigned long outlen,
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

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i + 1) * 32 <= outlen; i++) {
        toByte32(inbuf + inlen, i, 4);
        sha256(out, inbuf, inlen + 4);
        out += 32;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i * 32) {
        toByte32(inbuf + inlen, i, 4);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i * 32);
    }
    free(inbuf);
}

void mgf1_sha_512(unsigned char* out, unsigned long outlen,
    const unsigned char* in, unsigned long inlen)
{
    unsigned char* inbuf = malloc(inlen + 4);
    unsigned char outbuf[64];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i + 1) * 64 <= outlen; i++) {
        u32_to_bytes_(inbuf + inlen, i);
        sha512(out, inbuf, inlen + 4);
        out += 64;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i * 64) {
        u32_to_bytes_(inbuf + inlen, i);
        sha512(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i * 64);
    }
    free(inbuf);
}

//void HMAC(uint8_t* dest, const uint8_t* sk, const uint8_t* src, size_t len)
//{
//#if FIPS205_N == 16
//#define	BLOCKSIZE	64
//#else
//#define	BLOCKSIZE	128
//#endif
//
//    //uint8_t okey[BLOCKSIZE], ikey[BLOCKSIZE];
//    uint8_t buf[BLOCKSIZE + BLOCKSIZE / 2]; // oKey
//    uint8_t* temp = malloc(BLOCKSIZE + len);    //      ikey
//    if (temp)
//    {
//        uint32_t i;
//        //uint8_t temp[64 + SPX_SHA256_OUTPUT_BYTES], *cur = buf;
//        //uint8_t hash[64];
//
//        for (i = 0; i < FIPS205_N; ++i)
//        {
//            temp[i] = sk[i] ^ 0x36;
//        }
//
//        for (i = 0; i < BLOCKSIZE - FIPS205_N; ++i)
//        {
//            temp[FIPS205_N + i] = 0x36;
//        }
//        for (i = 0; i < len; i++)
//            temp[BLOCKSIZE + i] = src[i];
//
//        for (i = 0; i < FIPS205_N; ++i)
//        {
//            buf[i] = sk[i] ^ 0x5C;
//        }
//
//        for (i = 0; i < BLOCKSIZE - FIPS205_N; ++i)
//        {
//            buf[FIPS205_N + i] = 0x5C;
//        }
//
//
//        //cur += BLOCKSIZE - N;
//
//
//
//#if FIPS205_N == 16
//        sha256(buf + BLOCKSIZE, temp, BLOCKSIZE + len, FIPS205_N);
//#else
//        sha512(buf + BLOCKSIZE, temp, BLOCKSIZE + len, FIPS205_N);
//#endif
//
//#if FIPS205_N == 16
//        sha256(temp, buf, BLOCKSIZE + BLOCKSIZE / 2, FIPS205_N);
//#else
//        sha512(temp, buf, BLOCKSIZE + BLOCKSIZE / 2, FIPS205_N);
//#endif
//
//        for (i = 0; i < FIPS205_N; ++i)
//        {
//            dest[i] = temp[i];
//        }
//        free(temp);
//    }
//    
//
//}

void HMAC256(uint8_t* dest, const uint8_t* sk, const uint8_t* src, size_t len)
{
//#if FIPS205_N == 16
#define	BLOCKSIZE	64

    //uint8_t okey[BLOCKSIZE], ikey[BLOCKSIZE];
    uint8_t buf[BLOCKSIZE + BLOCKSIZE / 2]; // oKey
    uint8_t* temp = malloc(BLOCKSIZE + len);    //      ikey
    if (temp)
    {
        uint32_t i;
        //uint8_t temp[64 + SPX_SHA256_OUTPUT_BYTES], *cur = buf;
        //uint8_t hash[64];

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



//#if FIPS205_N == 16
        sha256(buf + BLOCKSIZE, temp, BLOCKSIZE + len/*, FIPS205_N*/);
//#else
//        sha512(buf + BLOCKSIZE, temp, BLOCKSIZE + len, FIPS205_N);
//#endif

//#if FIPS205_N == 16
        sha256(temp, buf, BLOCKSIZE + BLOCKSIZE / 2/*, FIPS205_N*/);
//#else
//      sha512(temp, buf, BLOCKSIZE + BLOCKSIZE / 2, FIPS205_N);
//#endif

        for (i = 0; i < FIPS205_N; ++i)
        {
            dest[i] = temp[i];
        }
        free(temp);
    }


}



//SUCCESS Test_HMAC_256()
//{
//    SUCCESS success;
//    uint8_t key[] ={
//        0x2E, 0xF3, 0x36, 0x59, 0x07, 0x38, 0x5E, 0x5A,
//        0x80, 0xCB, 0xCC, 0x9C, 0x2C, 0x15, 0, 0
//    };
//    uint8_t msg[] = {
//        0x6C, 0xA6, 0x20, 0x6F, 0x10, 0xF1, 0x43, 0xB2,
//        0x44, 0x63, 0xBC, 0x55, 0x29, 0x3B, 0x34, 0xDB
//    };
//    uint8_t read_mac[] = {
//        0xA0, 0xD3, 0x6B, 0x78, 0xD0, 0x45, 0x73, 0xCF,
//        0x36, 0xA7, 0xBC, 0x5F, 0xAC, 0xA2, 0xA2, 0x21,
//        0x94, 0xCA, 0xA9, 0x9D
//    };
//    uint8_t calc_mac[sizeof(read_mac)];
//    HMAC(calc_mac, key, msg, sizeof(msg));
//    success = memcmp(read_mac, calc_mac, FIPS205_N);
//    if (success == 0)
//    {
//        uint8_t key[16] = "key";
//        uint8_t msg[] = "The quick brown fox jumps over the lazy dog";
//        uint8_t read_mac[] = {
//            0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 
//            0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43
//        };
//        HMAC(calc_mac, key, msg, strlen(msg));
//        success = memcmp(read_mac, calc_mac, FIPS205_N);
//    }
//    return success;
//}

//void predcalc_crypto_hashblocks_sha256(uint8_t* statebytes, const uint8_t* in)
//{
//    uint32_t state[8];
//    uint32_t a, b, c, d, e, f, g, h ;
//        
//    uint32_t T1;
//    uint32_t T2;
//    uint32_t w0, w1, w2, w3, w4 = 0, w5 = 0, w6 = 0, w7 = 0, w8 = 0,
//        w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = 0, w15 = 0;
//    static const uint32_t iv_[8] = {
//    0x6a09e667,
//    0xbb67ae85,
//    0x3c6ef372,
//    0xa54ff53a,
//    0x510e527f,
//    0x9b05688c,
//    0x1f83d9ab,
//    0x5be0cd19
//    };
//
//        
//
//#if 0
//    a = load_bigendian(statebytes + 0); state[0] = a;
//    b = load_bigendian(statebytes + 4); state[1] = b;
//    c = load_bigendian(statebytes + 8); state[2] = c;
//    d = load_bigendian(statebytes + 12); state[3] = d;
//    e = load_bigendian(statebytes + 16); state[4] = e;
//    f = load_bigendian(statebytes + 20); state[5] = f;
//    g = load_bigendian(statebytes + 24); state[6] = g;
//    h = load_bigendian(statebytes + 28); state[7] = h;
//#else
//    a = state[0] = 0x6a09e667;
//    b = state[1] = 0xbb67ae85;
//    c = state[2] = 0x3c6ef372;
//    d = state[3] = 0xa54ff53a;
//    e = state[4] = 0x510e527f;
//    f = state[5] = 0x9b05688c;
//    g = state[6] = 0x1f83d9ab;
//    h = state[7] = 0x5be0cd19;
//#endif
//    /*while (inlen >= 64) { */
//    //{
//        w0 = load_bigendian(in + 0);
//        w1 = load_bigendian(in + 4);
//        w2 = load_bigendian(in + 8);
//        w3 = load_bigendian(in + 12);
//#if N > 16
//        w4 = load_bigendian(in + 16);
//        w5 = load_bigendian(in + 20);
//#endif
//#if N > 24
//        w6 = load_bigendian(in + 24);
//        w7 = load_bigendian(in + 28);
//#endif
//        
//        F(w0, 0x428a2f98)
//            F(w1, 0x71374491)
//            F(w2, 0xb5c0fbcf)
//            F(w3, 0xe9b5dba5)
//            F(w4, 0x3956c25b)
//            F(w5, 0x59f111f1)
//            F(w6, 0x923f82a4)
//            F(w7, 0xab1c5ed5)
//            F(w8, 0xd807aa98)
//            F(w9, 0x12835b01)
//            F(w10, 0x243185be)
//            F(w11, 0x550c7dc3)
//            F(w12, 0x72be5d74)
//            F(w13, 0x80deb1fe)
//            F(w14, 0x9bdc06a7)
//            F(w15, 0xc19bf174)
//
//            EXPAND
//
//            F(w0, 0xe49b69c1)
//            F(w1, 0xefbe4786)
//            F(w2, 0x0fc19dc6)
//            F(w3, 0x240ca1cc)
//            F(w4, 0x2de92c6f)
//            F(w5, 0x4a7484aa)
//            F(w6, 0x5cb0a9dc)
//            F(w7, 0x76f988da)
//            F(w8, 0x983e5152)
//            F(w9, 0xa831c66d)
//            F(w10, 0xb00327c8)
//            F(w11, 0xbf597fc7)
//            F(w12, 0xc6e00bf3)
//            F(w13, 0xd5a79147)
//            F(w14, 0x06ca6351)
//            F(w15, 0x14292967)
//
//            EXPAND
//
//            F(w0, 0x27b70a85)
//            F(w1, 0x2e1b2138)
//            F(w2, 0x4d2c6dfc)
//            F(w3, 0x53380d13)
//            F(w4, 0x650a7354)
//            F(w5, 0x766a0abb)
//            F(w6, 0x81c2c92e)
//            F(w7, 0x92722c85)
//            F(w8, 0xa2bfe8a1)
//            F(w9, 0xa81a664b)
//            F(w10, 0xc24b8b70)
//            F(w11, 0xc76c51a3)
//            F(w12, 0xd192e819)
//            F(w13, 0xd6990624)
//            F(w14, 0xf40e3585)
//            F(w15, 0x106aa070)
//
//            EXPAND
//
//            F(w0, 0x19a4c116)
//            F(w1, 0x1e376c08)
//            F(w2, 0x2748774c)
//            F(w3, 0x34b0bcb5)
//            F(w4, 0x391c0cb3)
//            F(w5, 0x4ed8aa4a)
//            F(w6, 0x5b9cca4f)
//            F(w7, 0x682e6ff3)
//            F(w8, 0x748f82ee)
//            F(w9, 0x78a5636f)
//            F(w10, 0x84c87814)
//            F(w11, 0x8cc70208)
//            F(w12, 0x90befffa)
//            F(w13, 0xa4506ceb)
//            F(w14, 0xbef9a3f7)
//            F(w15, 0xc67178f2)
//#if 0
//            a += state[0];
//        b += state[1];
//        c += state[2];
//        d += state[3];
//        e += state[4];
//        f += state[5];
//        g += state[6];
//        h += state[7];
//#else
//        a += 0x6a09e667;
//        b += 0xbb67ae85;
//        c += 0x3c6ef372;
//        d += 0xa54ff53a;
//        e += 0x510e527f;
//        f += 0x9b05688c;
//        g += 0x1f83d9ab;
//        h += 0x5be0cd19;
//#endif
//
//        /*state[0] = a;
//        state[1] = b;
//        state[2] = c;
//        state[3] = d;
//        state[4] = e;
//        state[5] = f;
//        state[6] = g;
//        state[7] = h;*/
//
//        /*in += 64;
//        inlen -= 64;*/
//    //}
//
//#if 0
//            store_bigendian(statebytes + 0, state[0]);
//    store_bigendian(statebytes + 4, state[1]);
//    store_bigendian(statebytes + 8, state[2]);
//    store_bigendian(statebytes + 12, state[3]);
//    store_bigendian(statebytes + 16, state[4]);
//    store_bigendian(statebytes + 20, state[5]);
//    store_bigendian(statebytes + 24, state[6]);
//    store_bigendian(statebytes + 28, state[7]);
//#else
//        store_bigendian(statebytes + 0, a);
//        store_bigendian(statebytes + 4, b);
//        store_bigendian(statebytes + 8, c);
//        store_bigendian(statebytes + 12, d);
//        store_bigendian(statebytes + 16, e);
//        store_bigendian(statebytes + 20, f);
//        store_bigendian(statebytes + 24, g);
//        store_bigendian(statebytes + 28, h);
//#endif
//}

void sha256_predcalc_pk(uint32_t* state, const uint8_t* in_)
{
    //uint32_t state[8];
    uint32_t a, b, c, d, e, f, g, h;

    uint32_t T1;
    uint32_t T2;
    uint32_t w0, w1, w2, w3, w4 = 0, w5 = 0, w6 = 0, w7 = 0, w8 = 0,
        w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = 0, w15 = 0;
    uint8_t in[64] = { 0 };

    memcpy(in, in_, FIPS205_N);
    /*static const uint32_t iv_[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
    };*/
// 0x6a09e667
#if 0
    a = load_bigendian(statebytes + 0); state[0] = a;
    b = load_bigendian(statebytes + 4); state[1] = b;
    c = load_bigendian(statebytes + 8); state[2] = c;
    d = load_bigendian(statebytes + 12); state[3] = d;
    e = load_bigendian(statebytes + 16); state[4] = e;
    f = load_bigendian(statebytes + 20); state[5] = f;
    g = load_bigendian(statebytes + 24); state[6] = g;
    h = load_bigendian(statebytes + 28); state[7] = h;
#else
    a = /*state[0] = */0x6a09e667;
    b = /*state[1] = */0xbb67ae85;
    c = /*state[2] = */0x3c6ef372;
    d = /*state[3] = */0xa54ff53a;
    e = /*state[4] = */0x510e527f;
    f = /*state[5] = */0x9b05688c;
    g = /*state[6] = */0x1f83d9ab;
    h = /*state[7] = */0x5be0cd19;
#endif
    /*while (inlen >= 64) { */
    //{
    w0 = load_bigendian(in + 0);
    w1 = load_bigendian(in + 4);
    w2 = load_bigendian(in + 8);
    w3 = load_bigendian(in + 12);
#if FIPS205_N > 16
    w4 = load_bigendian(in + 16);
    w5 = load_bigendian(in + 20);
#endif
#if FIPS205_N > 24
    w6 = load_bigendian(in + 24);
    w7 = load_bigendian(in + 28);
#endif

    NEXT_STEP
    /*F(w0, 0x428a2f98)
        F(w1, 0x71374491)
        F(w2, 0xb5c0fbcf)
        F(w3, 0xe9b5dba5)
        F(w4, 0x3956c25b)
        F(w5, 0x59f111f1)
        F(w6, 0x923f82a4)
        F(w7, 0xab1c5ed5)
        F(w8, 0xd807aa98)
        F(w9, 0x12835b01)
        F(w10, 0x243185be)
        F(w11, 0x550c7dc3)
        F(w12, 0x72be5d74)
        F(w13, 0x80deb1fe)
        F(w14, 0x9bdc06a7)
        F(w15, 0xc19bf174)

        EXPAND

        F(w0, 0xe49b69c1)
        F(w1, 0xefbe4786)
        F(w2, 0x0fc19dc6)
        F(w3, 0x240ca1cc)
        F(w4, 0x2de92c6f)
        F(w5, 0x4a7484aa)
        F(w6, 0x5cb0a9dc)
        F(w7, 0x76f988da)
        F(w8, 0x983e5152)
        F(w9, 0xa831c66d)
        F(w10, 0xb00327c8)
        F(w11, 0xbf597fc7)
        F(w12, 0xc6e00bf3)
        F(w13, 0xd5a79147)
        F(w14, 0x06ca6351)
        F(w15, 0x14292967)

        EXPAND

        F(w0, 0x27b70a85)
        F(w1, 0x2e1b2138)
        F(w2, 0x4d2c6dfc)
        F(w3, 0x53380d13)
        F(w4, 0x650a7354)
        F(w5, 0x766a0abb)
        F(w6, 0x81c2c92e)
        F(w7, 0x92722c85)
        F(w8, 0xa2bfe8a1)
        F(w9, 0xa81a664b)
        F(w10, 0xc24b8b70)
        F(w11, 0xc76c51a3)
        F(w12, 0xd192e819)
        F(w13, 0xd6990624)
        F(w14, 0xf40e3585)
        F(w15, 0x106aa070)

        EXPAND

        F(w0, 0x19a4c116)
        F(w1, 0x1e376c08)
        F(w2, 0x2748774c)
        F(w3, 0x34b0bcb5)
        F(w4, 0x391c0cb3)
        F(w5, 0x4ed8aa4a)
        F(w6, 0x5b9cca4f)
        F(w7, 0x682e6ff3)
        F(w8, 0x748f82ee)
        F(w9, 0x78a5636f)
        F(w10, 0x84c87814)
        F(w11, 0x8cc70208)
        F(w12, 0x90befffa)
        F(w13, 0xa4506ceb)
        F(w14, 0xbef9a3f7)
        F(w15, 0xc67178f2)*/

    state[0] = a + 0x6a09e667;
    state[1] = b + 0xbb67ae85;
    state[2] = c + 0x3c6ef372;
    state[3] = d + 0xa54ff53a;
    state[4] = e + 0x510e527f;
    state[5] = f + 0x9b05688c;
    state[6] = g + 0x1f83d9ab;
    state[7] = h + 0x5be0cd19;

    //state[0] = a;
    //state[1] = b;
    //state[2] = c;
    //state[3] = d;
    //state[4] = e;
    //state[5] = f;
    //state[6] = g;
    //state[7] = h;

}







void crypto_hashblocks_sha256_2_(uint8_t *out, uint32_t* state, const uint8_t* in)
{
    //uint32_t state[8];
    uint32_t a, b, c, d, e, f, g, h;

    uint32_t T1;
    uint32_t T2;
    uint32_t w0, w1, w2, w3, w4 , w5 , w6 , w7 , w8 ,
        w9 , w10 , w11 , w12 , w13 , w14 , w15 ;
    

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    
    w0 = load_bigendian(in + 0);
    w1 = load_bigendian(in + 4);
    w2 = load_bigendian(in + 8);
    w3 = load_bigendian(in + 12);

    w4 = load_bigendian(in + 16);
    w5 = load_bigendian(in + 20);


    w6 = load_bigendian(in + 24);
    w7 = load_bigendian(in + 28);
    w8 = load_bigendian(in + 32);
    w9 = load_bigendian(in + 36);
    w10 = load_bigendian(in + 40);
    w11 = load_bigendian(in + 44);
    w12 = load_bigendian(in + 48);
    w13 = load_bigendian(in + 52);
    w14 = load_bigendian(in + 56);
    w15 = load_bigendian(in + 60);

#if 0
    NEXT_STEP
#else
    F(w0, 0x428a2f98)
        F(w1, 0x71374491)
        F(w2, 0xb5c0fbcf)
        F(w3, 0xe9b5dba5)
        F(w4, 0x3956c25b)
        F(w5, 0x59f111f1)
        F(w6, 0x923f82a4)
        F(w7, 0xab1c5ed5)
        F(w8, 0xd807aa98)
        F(w9, 0x12835b01)
        F(w10, 0x243185be)
        F(w11, 0x550c7dc3)
        F(w12, 0x72be5d74)
        F(w13, 0x80deb1fe)
        F(w14, 0x9bdc06a7)
        F(w15, 0xc19bf174)

        EXPAND

        F(w0, 0xe49b69c1)
        F(w1, 0xefbe4786)
        F(w2, 0x0fc19dc6)
        F(w3, 0x240ca1cc)
        F(w4, 0x2de92c6f)
        F(w5, 0x4a7484aa)
        F(w6, 0x5cb0a9dc)
        F(w7, 0x76f988da)
        F(w8, 0x983e5152)
        F(w9, 0xa831c66d)
        F(w10, 0xb00327c8)
        F(w11, 0xbf597fc7)
        F(w12, 0xc6e00bf3)
        F(w13, 0xd5a79147)
        F(w14, 0x06ca6351)
        F(w15, 0x14292967)

        EXPAND

        F(w0, 0x27b70a85)
        F(w1, 0x2e1b2138)
        F(w2, 0x4d2c6dfc)
        F(w3, 0x53380d13)
        F(w4, 0x650a7354)
        F(w5, 0x766a0abb)
        F(w6, 0x81c2c92e)
        F(w7, 0x92722c85)
        F(w8, 0xa2bfe8a1)
        F(w9, 0xa81a664b)
        F(w10, 0xc24b8b70)
        F(w11, 0xc76c51a3)
        F(w12, 0xd192e819)
        F(w13, 0xd6990624)
        F(w14, 0xf40e3585)
        F(w15, 0x106aa070)

        EXPAND

        F(w0, 0x19a4c116)
        F(w1, 0x1e376c08)
        F(w2, 0x2748774c)
        F(w3, 0x34b0bcb5)
        F(w4, 0x391c0cb3)
        F(w5, 0x4ed8aa4a)
        F(w6, 0x5b9cca4f)
        F(w7, 0x682e6ff3)
        F(w8, 0x748f82ee)
        F(w9, 0x78a5636f)
        F(w10, 0x84c87814)
        F(w11, 0x8cc70208)
        F(w12, 0x90befffa)
        F(w13, 0xa4506ceb)
        F(w14, 0xbef9a3f7)
        F(w15, 0xc67178f2)
#endif


    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
#if FIPS205_N > 16
    e += state[4];
    f += state[5];
#if FIPS205_N > 24
    g += state[6];
    h += state[7];
#endif
#endif
    store_bigendian(out, a);
    store_bigendian(out + 4, b);
    store_bigendian(out + 8, c);
    store_bigendian(out + 12, d);
#if FIPS205_N > 16
    store_bigendian(out + 16, e);
    store_bigendian(out + 20, f);
#if FIPS205_N > 24
    store_bigendian(out + 24, g);
    store_bigendian(out + 28, h);
#endif
#endif

}



size_t crypto_hashblocks_sha256_currents_(uint32_t* state, const uint8_t* in, size_t inlen)
{
    //uint32_t state[8];
    uint32_t a, b, c, d, e, f, g, h;

    uint32_t T1;
    uint32_t T2;
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8,
        w9, w10, w11, w12, w13, w14, w15;

    if (inlen < 64)
        return inlen;
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    while (inlen >= 64)
    {
        w0 = load_bigendian(in + 0);
        w1 = load_bigendian(in + 4);
        w2 = load_bigendian(in + 8);
        w3 = load_bigendian(in + 12);

        w4 = load_bigendian(in + 16);
        w5 = load_bigendian(in + 20);


        w6 = load_bigendian(in + 24);
        w7 = load_bigendian(in + 28);
        w8 = load_bigendian(in + 32);
        w9 = load_bigendian(in + 36);
        w10 = load_bigendian(in + 40);
        w11 = load_bigendian(in + 44);
        w12 = load_bigendian(in + 48);
        w13 = load_bigendian(in + 52);
        w14 = load_bigendian(in + 56);
        w15 = load_bigendian(in + 60);

        NEXT_STEP
        /*F(w0, 0x428a2f98)
            F(w1, 0x71374491)
            F(w2, 0xb5c0fbcf)
            F(w3, 0xe9b5dba5)
            F(w4, 0x3956c25b)
            F(w5, 0x59f111f1)
            F(w6, 0x923f82a4)
            F(w7, 0xab1c5ed5)
            F(w8, 0xd807aa98)
            F(w9, 0x12835b01)
            F(w10, 0x243185be)
            F(w11, 0x550c7dc3)
            F(w12, 0x72be5d74)
            F(w13, 0x80deb1fe)
            F(w14, 0x9bdc06a7)
            F(w15, 0xc19bf174)

            EXPAND

            F(w0, 0xe49b69c1)
            F(w1, 0xefbe4786)
            F(w2, 0x0fc19dc6)
            F(w3, 0x240ca1cc)
            F(w4, 0x2de92c6f)
            F(w5, 0x4a7484aa)
            F(w6, 0x5cb0a9dc)
            F(w7, 0x76f988da)
            F(w8, 0x983e5152)
            F(w9, 0xa831c66d)
            F(w10, 0xb00327c8)
            F(w11, 0xbf597fc7)
            F(w12, 0xc6e00bf3)
            F(w13, 0xd5a79147)
            F(w14, 0x06ca6351)
            F(w15, 0x14292967)

            EXPAND

            F(w0, 0x27b70a85)
            F(w1, 0x2e1b2138)
            F(w2, 0x4d2c6dfc)
            F(w3, 0x53380d13)
            F(w4, 0x650a7354)
            F(w5, 0x766a0abb)
            F(w6, 0x81c2c92e)
            F(w7, 0x92722c85)
            F(w8, 0xa2bfe8a1)
            F(w9, 0xa81a664b)
            F(w10, 0xc24b8b70)
            F(w11, 0xc76c51a3)
            F(w12, 0xd192e819)
            F(w13, 0xd6990624)
            F(w14, 0xf40e3585)
            F(w15, 0x106aa070)

            EXPAND

            F(w0, 0x19a4c116)
            F(w1, 0x1e376c08)
            F(w2, 0x2748774c)
            F(w3, 0x34b0bcb5)
            F(w4, 0x391c0cb3)
            F(w5, 0x4ed8aa4a)
            F(w6, 0x5b9cca4f)
            F(w7, 0x682e6ff3)
            F(w8, 0x748f82ee)
            F(w9, 0x78a5636f)
            F(w10, 0x84c87814)
            F(w11, 0x8cc70208)
            F(w12, 0x90befffa)
            F(w13, 0xa4506ceb)
            F(w14, 0xbef9a3f7)
            F(w15, 0xc67178f2)*/

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
            in += 64;
            inlen -= 64;
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
#ifdef _PREDCALC
void sha256_with_predcalc2_(uint8_t* out, const uint32_t* predcalc, uint8_t* in, size_t inlen)
{
    //uint8_t h[32];
    uint8_t padded[64];
    size_t i;
    

    size_t bits = (64 + inlen) * 8;


    for (i = 0; i < inlen; ++i) padded[i] = in[i];
    padded[inlen] = 0x80;

    //if (inlen < 56) 
    {
        for (i = inlen + 1; i < 56; ++i) padded[i] = 0;

        padded[56] = (uint8_t)(bits >> 56);
        padded[57] = (uint8_t)(bits >> 48);
        padded[58] = (uint8_t)(bits >> 40);
        padded[59] = (uint8_t)(bits >> 32);
        padded[60] = (uint8_t)(bits >> 24);
        padded[61] = (uint8_t)(bits >> 16);
        padded[62] = (uint8_t)(bits >> 8);
        padded[63] = (uint8_t)bits;
        
        
        crypto_hashblocks_sha256_2_(out, predcalc, (const uint8_t*)padded);
        
    }
  
}
// один блок, починається з pk
void sha256_with_predcalc_ (uint8_t* out, uint32_t *predcalc_pk, uint8_t* in, size_t inlen)
{
        
    size_t i;
    uint32_t state[8];
    uint8_t padded [128];
    memcpy(state, predcalc_pk, 32);
    size_t curlen = crypto_hashblocks_sha256_currents_(
        state, in, inlen);
    size_t bits = (64 + inlen) * 8;
    in = in + inlen - curlen;
    inlen = curlen;
    
    for (i = 0; i < inlen; ++i) padded[i] = in[i];
    padded[inlen] = 0x80;

    if (inlen < 56) 
    {
        for (i = inlen + 1; i < 56; ++i) padded[i] = 0;

        padded[56] = (uint8_t)(bits >> 56);
        padded[57] = (uint8_t)(bits >> 48);
        padded[58] = (uint8_t)(bits >> 40);
        padded[59] = (uint8_t)(bits >> 32);
        padded[60] = (uint8_t)(bits >> 24);
        padded[61] = (uint8_t)(bits >> 16);
        padded[62] = (uint8_t)(bits >> 8);
        padded[63] = (uint8_t)bits;

        //*(uint64_t*)(padded + 56) = 0x3003000000000000;
        crypto_hashblocks_sha256_2_(out, state, padded);
        //blocks(h, padded, 64);
    }
    else {
        for (i = inlen + 1; i < 120; ++i) padded[i] = 0;
        padded[120] = (uint8_t)(bits >> 56);
        padded[121] = (uint8_t)(bits >> 48);
        padded[122] = (uint8_t)(bits >> 40);
        padded[123] = (uint8_t)(bits >> 32);
        padded[124] = (uint8_t)(bits >> 24);
        padded[125] = (uint8_t)(bits >> 16);
        padded[126] = (uint8_t)(bits >> 8);
        padded[127] = (uint8_t)bits;
        crypto_hashblocks_sha256_currents_(
            state, padded, 128);
        store_bigendian(out, state[0]);
        store_bigendian(out + 4, state[1]);
        store_bigendian(out + 8, state[2]);
        store_bigendian(out + 12, state[3]);
#if FIPS205_N > 16
        store_bigendian(out + 16, state[4]);
        store_bigendian(out + 20, state[5]);
#endif
#if FIPS205_N > 24
        store_bigendian(out + 24, state[6]);
        store_bigendian(out + 28, state[7]);
#endif

    }

    //for (i = 0; i < 32; ++i) out[i] = h[i];
}
#endif
//int test_predcalc_pk_sha256()
//{
//    size_t i;
//    uint8_t pk[N], sk[N];
//    uint8_t adr[22];
//    uint8_t in[64 + 22 + N] = {0};
//    uint8_t out1[32], out2[32];
//    uint32_t state[8];
//
//    srand(0);
//    for (i = 0; i < N; ++i)
//    {
//        pk[i] = rand() % 256;
//        sk[i] = rand() % 256;
//    }
//    for (i = 0; i < 22; ++i)
//        adr [i] = rand() % 256;
//    memcpy(in, pk, N);
//    memcpy(in + 64, adr, 22);
//    memcpy(in + 64 + 22, sk, N);
//    sha256(out1, in, 64 + 22 + N);
//    predcalc_pk_sha256(state, in);
//    sha256_with_predcalc2_(out2, state, in + 64);
//    int res = 0;
//    for (i = 0; i < N; ++i)
//    {
//        if (out1[i] != out2[i])
//            res = 1;
//    }
//    return res;
//
//
//}

////int test_predcalc_crypto_hashblocks_sha256()
////{
////    __declspec (align(64)) uint8_t statebytes1[32], statebytes2[32];
////    uint8_t in[64] = {0};
////    size_t i;
////    
////    for (i = 0; i < 32; ++i) statebytes1[i] = iv[i];
////    for (i = 0; i < 32; ++i) statebytes2[i] = iv[i];
////    srand(0);
////    for (i = 0; i < N; ++i)
////        in[i] = rand() % 256;
////
////    //sha256(statebytes1, in, N);
////    crypto_hashblocks_sha256(statebytes1, in, 64);
////    
////    predcalc_crypto_hashblocks_sha256(statebytes2, in, 64);
////    int res = 0;
////    for (i = 0; i < 32; ++i)
////    {
////        if (statebytes1[i] != statebytes2[i])
////            res = 1;
////    }
////    return res;
////
////}
//
//void sha256_with_predcalc2(uint8_t* out, uint8_t* predcalc, uint8_t* in, size_t inlen)
//{
//    uint8_t h[32];
//    uint8_t padded[128];
//    unsigned int i;
//    size_t bits = (inlen) << 3;
//
//    /*for (i = 0; i < 32; ++i) h[i] = iv[i];
//
//    blocks(h, in, inlen);
//    in += inlen;
//    inlen &= 63;*/
//    memcpy(h, predcalc, 32);
//    //in -= inlen;
//    in += 64;
//    inlen -= 64;
//
//    for (i = 0; i < inlen; ++i) padded[i] = in[i];
//    padded[inlen] = 0x80;
//
//    //if (inlen < 56) 
//    {
//        for (i = inlen + 1; i < 56; ++i) padded[i] = 0;
//        padded[56] = bits >> 56;
//        padded[57] = bits >> 48;
//        padded[58] = bits >> 40;
//        padded[59] = bits >> 32;
//        padded[60] = bits >> 24;
//        padded[61] = bits >> 16;
//        padded[62] = bits >> 8;
//        padded[63] = bits;
//        blocks(h, padded, 64);
//    }
//    /*else {
//        for (i = inlen + 1; i < 120; ++i) padded[i] = 0;
//        padded[120] = bits >> 56;
//        padded[121] = bits >> 48;
//        padded[122] = bits >> 40;
//        padded[123] = bits >> 32;
//        padded[124] = bits >> 24;
//        padded[125] = bits >> 16;
//        padded[126] = bits >> 8;
//        padded[127] = bits;
//        blocks(h, padded, 128);
//    }*/
//
//    for (i = 0; i < 32; ++i) out[i] = h[i];
//}

void sha256_with_predcalc(uint8_t* out, uint8_t* predcalc, uint8_t* in, size_t inlen)
{
    uint8_t h[32];
    uint8_t padded[128];
    size_t i;
    size_t bits = (inlen) << 3;

    /*for (i = 0; i < 32; ++i) h[i] = iv[i];

    blocks(h, in, inlen);
    in += inlen;
    inlen &= 63;*/
    memcpy(h, predcalc, 32);
    //in -= inlen;
    in += 64;
    inlen -= 64;

    blocks(h, in, inlen);
    in += inlen;
    inlen &= 63;

    for (i = 0; i < inlen; ++i) padded[i] = in[i];
    padded[inlen] = 0x80;

    //if (inlen < 56) 
    {
        for (i = inlen + 1; i < 56; ++i) padded[i] = 0;
        padded[56] = (uint8_t)(bits >> 56);
        padded[57] = (uint8_t)(bits >> 48);
        padded[58] = (uint8_t)(bits >> 40);
        padded[59] = (uint8_t)(bits >> 32);
        padded[60] = (uint8_t)(bits >> 24);
        padded[61] = (uint8_t)(bits >> 16);
        padded[62] = (uint8_t)(bits >> 8);
        padded[63] = (uint8_t)bits;
        blocks(h, padded, 64);
    }
    /*else {
        for (i = inlen + 1; i < 120; ++i) padded[i] = 0;
        padded[120] = bits >> 56;
        padded[121] = bits >> 48;
        padded[122] = bits >> 40;
        padded[123] = bits >> 32;
        padded[124] = bits >> 24;
        padded[125] = bits >> 16;
        padded[126] = bits >> 8;
        padded[127] = bits;
        blocks(h, padded, 128);
    }*/

    for (i = 0; i < 32; ++i) out[i] = h[i];
}

// res, i, s, pk, adr, sk, N
void sha256_chain_with_predcalc(uint8_t* res, int i, int s, uint32_t* predcalc_pk, uint8_t* adr, uint8_t* src2, int n)
{

    int j, is = i + s, inlen = 22 + n;
    uint64_t bits = (inlen + 64) * 8;
    uint8_t padded[64];
    memcpy(res, src2, FIPS205_N);
    memcpy(padded, adr, 22);
    memcpy(padded + 22, src2, n);
    padded[inlen] = 0x80;
    for (j = inlen + 1; j < 62; ++j) padded[j] = 0;
    /*padded[56] = bits >> 56;
    padded[57] = bits >> 48;
    padded[58] = bits >> 40;
    padded[59] = bits >> 32;
    padded[60] = bits >> 24;
    padded[61] = bits >> 16;*/
    padded[62] = (uint8_t)(bits >> 8);
    padded[63] = (uint8_t)bits;

    for (j = i; j < is; ++j)
    {
        //ShortSetAddress4 (ShortHashAddressOFFSET, j);
        padded[21] = j;
        crypto_hashblocks_sha256_2_(res, predcalc_pk, padded);
        memcpy(padded + 22, res, n);
    }
}

