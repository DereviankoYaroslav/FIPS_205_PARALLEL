#ifndef SHA512_defined_h
#define SHA512_defined_h
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>   // covers AVX, SSE, FMA, etc.
#endif
#include "FIPS_205_Params.h"

#define ROR64(dword, n) (((dword) >> ((n) )) | ((dword ) << (64 - ((n) ))))

#define SHR64(dword, n) ((dword) >> n)
//
#define s0(dword)    (ROR64(dword,1) ^ ROR64(dword, 8) ^ SHR64(dword, 7))
#define s1(dword)    (ROR64(dword,19) ^ ROR64(dword, 61) ^ SHR64(dword, 6))
#define S1(dword)    (ROR64(dword,14) ^ ROR64(dword, 18) ^ ROR64(dword, 41))
#define S0(dword)    (ROR64(dword,28) ^ ROR64(dword, 34) ^ ROR64(dword, 39))

//#define s0_128(word)    (ROR32(word,7) ^ ROR32(word, 18) ^ SHR32(word, 3))

// ch := (e and f) xor ((not e) and g)
#define ch(e,f,g)       ((e & f) ^ (~e & g))
//  maj := (a and b) xor (a and c) xor (b and c)
#define maj(a, b, c)    ((a & b) ^ (a & c) ^ (b & c))



#define n1		_mm_set1_epi64x (1)
#define n1_     _mm_set1_epi64x (63)
#define n8		_mm_set1_epi64x (8)
#define n8_     _mm_set1_epi64x (56)

#define n19		_mm_set1_epi64x (19)
#define n19_     _mm_set1_epi64x (45)
#define n61		_mm_set1_epi64x (61)
#define n61_     _mm_set1_epi64x (3)

#define n14		_mm_set1_epi64x (14)
#define n14_     _mm_set1_epi64x (50)
#define n18		_mm_set1_epi64x (18)
#define n18_     _mm_set1_epi64x (46)
#define n41		_mm_set1_epi64x (41)
#define n41_     _mm_set1_epi64x (23)

#define n28		_mm_set1_epi64x (28)
#define n28_     _mm_set1_epi64x (36)
#define n34		_mm_set1_epi64x (34)
#define n34_     _mm_set1_epi64x (30)
#define n39		_mm_set1_epi64x (39)
#define n39_     _mm_set1_epi64x (25)


#define ROR64_256(dword, n, n_)      _mm256_or_si256(_mm256_srl_epi64(dword, n), _mm256_sll_epi64(dword, n_))


//
#define SHR64_256(dword, n)			_mm256_srli_epi64(dword, n)

//#define s0(dword)    (ROR64(dword,1) ^ ROR64(dword, 8) ^ SHR64(dword, 7))
#define s0_256(dword)   _mm256_xor_si256(			\
						_mm256_xor_si256(			\
							ROR64_256(dword,n1, n1_), ROR64_256(dword, n8, n8_)), \
							SHR64_256(dword, 7))
/*
#define s1(dword)    (ROR64(dword,19) ^ ROR64(dword, 61) ^ SHR64(dword, 6))


*/
#define s1_256(dword)    _mm256_xor_si256(			\
						_mm256_xor_si256(			\
							ROR64_256(dword,n19, n19_), ROR64_256(dword, n61, n61_)), \
							SHR64_256(dword, 6))
							//_mm256_srli_epi64(dword, 6))
							/*SHR64_256(dword, n6))*/
// #define S1(dword)    (ROR64(dword,14) ^ ROR64(dword, 18) ^ ROR64(dword, 41))
#define S1_256(dword)    _mm256_xor_si256(			\
						_mm256_xor_si256(			\
							ROR64_256(dword,n14, n14_), ROR64_256(dword, n18, n18_)), \
							ROR64_256(dword, n41, n41_))
// #define S0(dword)    (ROR64(dword,28) ^ ROR64(dword, 34) ^ ROR64(dword, 39))
#define S0_256(dword)     _mm256_xor_si256(			\
						_mm256_xor_si256(			\
							ROR64_256(dword,n28, n28_), ROR64_256(dword, n34, n34_)), \
							ROR64_256(dword, n39, n39_))

/*
#define ch(e,f,g)       ((e & f) ^ (~e & g))
//  maj := (a and b) xor (a and c) xor (b and c)
#define maj(a, b, c)    ((a & b) ^ (a & c) ^ (b & c))

*/
#define ch_256(e, f, g)	_mm256_xor_si256(		\
					_mm256_and_si256 (e, f),	\
					_mm256_andnot_si256(e, g))

#define maj_256(a, b, c)	_mm256_xor_si256(		\
							_mm256_xor_si256(		\
								_mm256_and_si256 (a, b),	\
								_mm256_and_si256 (a, c)),	\
								_mm256_and_si256 (b, c))	\
					

#define M(w0,w14,w9,w1) w0 = s1(w14) + w9 + s0(w1) + w0;

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
  T1 = h + S1(e) + ch(e,f,g) + k + w; \
  T2 = S0(a) + maj(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;
#endif

#define BLOCK					\
F(w0, 0x428a2f98d728ae22ULL)	\
F(w1, 0x7137449123ef65cdULL)	\
F(w2, 0xb5c0fbcfec4d3b2fULL)	\
F(w3, 0xe9b5dba58189dbbcULL)	\
F(w4, 0x3956c25bf348b538ULL)	\
F(w5, 0x59f111f1b605d019ULL)	\
F(w6, 0x923f82a4af194f9bULL)	\
F(w7, 0xab1c5ed5da6d8118ULL)	\
F(w8, 0xd807aa98a3030242ULL)	\
F(w9, 0x12835b0145706fbeULL)	\
F(w10, 0x243185be4ee4b28cULL)	\
F(w11, 0x550c7dc3d5ffb4e2ULL)	\
F(w12, 0x72be5d74f27b896fULL)	\
F(w13, 0x80deb1fe3b1696b1ULL)	\
F(w14, 0x9bdc06a725c71235ULL)	\
F(w15, 0xc19bf174cf692694ULL)	\
EXPAND							\
F(w0, 0xe49b69c19ef14ad2ULL)	\
F(w1, 0xefbe4786384f25e3ULL)	\
F(w2, 0x0fc19dc68b8cd5b5ULL)	\
F(w3, 0x240ca1cc77ac9c65ULL)	\
F(w4, 0x2de92c6f592b0275ULL)	\
F(w5, 0x4a7484aa6ea6e483ULL)	\
F(w6, 0x5cb0a9dcbd41fbd4ULL)	\
F(w7, 0x76f988da831153b5ULL)	\
F(w8, 0x983e5152ee66dfabULL)	\
F(w9, 0xa831c66d2db43210ULL)	\
F(w10, 0xb00327c898fb213fULL)	\
F(w11, 0xbf597fc7beef0ee4ULL)	\
F(w12, 0xc6e00bf33da88fc2ULL)	\
F(w13, 0xd5a79147930aa725ULL)	\
F(w14, 0x06ca6351e003826fULL)	\
F(w15, 0x142929670a0e6e70ULL)	\
EXPAND							\
F(w0, 0x27b70a8546d22ffcULL)	\
F(w1, 0x2e1b21385c26c926ULL)	\
F(w2, 0x4d2c6dfc5ac42aedULL)	\
F(w3, 0x53380d139d95b3dfULL)	\
F(w4, 0x650a73548baf63deULL)	\
F(w5, 0x766a0abb3c77b2a8ULL)	\
F(w6, 0x81c2c92e47edaee6ULL)	\
F(w7, 0x92722c851482353bULL)	\
F(w8, 0xa2bfe8a14cf10364ULL)	\
F(w9, 0xa81a664bbc423001ULL)	\
F(w10, 0xc24b8b70d0f89791ULL)	\
F(w11, 0xc76c51a30654be30ULL)	\
F(w12, 0xd192e819d6ef5218ULL)	\
F(w13, 0xd69906245565a910ULL)	\
F(w14, 0xf40e35855771202aULL)	\
F(w15, 0x106aa07032bbd1b8ULL)	\
EXPAND							\
F(w0, 0x19a4c116b8d2d0c8ULL)	\
F(w1, 0x1e376c085141ab53ULL)	\
F(w2, 0x2748774cdf8eeb99ULL)	\
F(w3, 0x34b0bcb5e19b48a8ULL)	\
F(w4, 0x391c0cb3c5c95a63ULL)	\
F(w5, 0x4ed8aa4ae3418acbULL)	\
F(w6, 0x5b9cca4f7763e373ULL)	\
F(w7, 0x682e6ff3d6b2b8a3ULL)	\
F(w8, 0x748f82ee5defb2fcULL)	\
F(w9, 0x78a5636f43172f60ULL)	\
F(w10, 0x84c87814a1f0ab72ULL)	\
F(w11, 0x8cc702081a6439ecULL)	\
F(w12, 0x90befffa23631e28ULL)	\
F(w13, 0xa4506cebde82bde9ULL)	\
F(w14, 0xbef9a3f7b2c67915ULL)	\
F(w15, 0xc67178f2e372532bULL)	\
EXPAND							\
F(w0, 0xca273eceea26619cULL)	\
F(w1, 0xd186b8c721c0c207ULL)	\
F(w2, 0xeada7dd6cde0eb1eULL)	\
F(w3, 0xf57d4f7fee6ed178ULL)	\
F(w4, 0x06f067aa72176fbaULL)	\
F(w5, 0x0a637dc5a2c898a6ULL)	\
F(w6, 0x113f9804bef90daeULL)	\
F(w7, 0x1b710b35131c471bULL)	\
F(w8, 0x28db77f523047d84ULL)	\
F(w9, 0x32caab7b40c72493ULL)	\
F(w10, 0x3c9ebe0a15c9bebcULL)	\
F(w11, 0x431d67c49c100d4cULL)	\
F(w12, 0x4cc5d4becb3e42b6ULL)	\
F(w13, 0x597f299cfc657e2aULL)	\
F(w14, 0x5fcb6fab3ad6faecULL)	\
F(w15, 0x6c44198c4a475817ULL)	

