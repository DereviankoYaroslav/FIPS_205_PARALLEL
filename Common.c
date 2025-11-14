
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "FIPS_205_Params.h"
#include "Common.h"

void base_2b_old(uint32_t* base_b, const uint8_t* X, uint32_t b, uint32_t out_len)
{
	uint32_t in = 0, bits = 0, total = 0, mod = 1 << b;
	for (uint32_t out = 0; out < out_len; ++out)
	{
		while (bits < b)
		{
			total = (total << 8) + X[in];
			++in;
			bits += 8;
		}
		bits -= b;
		base_b[out] = (total >> bits) % mod;
	}

}

void base_4_new(uint32_t* base_b, const uint8_t* X, uint32_t out_len)
{
	uint32_t in = 0, out;
	for (out = 0; out < out_len/2*2; out += 2)
	{
		base_b[out] = X[in] >> 4;
		base_b[out + 1] = X[in] & 0xF;
		++in;
	}
	if (out != out_len)
		base_b[out] = X[in] >> 4;
}

void print_params()
{

#if defined (STORE) && FIPS205_N == 16
	printf("STORE - 128\n");
#endif
#if defined (STORE) && FIPS205_N == 24
	printf("STORE - 192\n");
#endif
#if defined (STORE) && FIPS205_N == 32
	printf("STORE - 256\n");
#endif
#if defined (FAST) && FIPS205_N == 16
	printf("FAST - 128\n");
#endif
#if defined (FAST) && FIPS205_N == 24
	printf("FAST - 192\n");
#endif
#if defined (FAST) && FIPS205_N == 32
	printf("FAST - 256\n");
#endif
	printf("n = %d\n", FIPS205_N);
	printf("h = %d\n", FIPS205_H);
	printf("d = %d\n", FIPS205_D);
	printf("h' = %d\n", FIPS205_H_);
	printf("a = %d\n", FIPS205_A);
	printf("k = %d\n", FIPS205_K);
	printf("w = %d\n", FIPS205_W);
	printf("log(w) = %d\n", FIPS205_LOGW);
	printf("m = %d\n\n", FIPS205_M);
	
	printf("len1 = %d\n", FIPS205_LEN1);
	printf("len2 = %d\n", FIPS205_LEN2);
	printf("len = %d\n\n", FIPS205_LEN);

	printf("pk_bytes = %d\n", FIPS205_PK_BYTES);
	printf("sk_bytes = %d\n", FIPS205_SK_BYTES);
	printf("sig_bytes = %d\n", FIPS205_SIG_BYTES);


	/*
	



	*/
	//#define	SIG_BYTES	7856




}

// Algorithm 2 toInt(𝑋, 𝑛)
// Converts a byte string to an integer.
uint64_t toInt64(const uint8_t* X, size_t n)
{
	//1: 𝑡𝑜𝑡𝑎𝑙 ← 0
	uint64_t total = 0;
	// 2: for 𝑖 from 0 to 𝑛 − 1 do
	size_t i;
	for (i = 0; i < n; ++i)
	{
		//3: 𝑡𝑜𝑡𝑎𝑙 ← 256 ⋅ 𝑡𝑜𝑡𝑎𝑙 + 𝑋[𝑖]
		total = total * 256 + X[i];
		// 4: end for
	}
	return total;

}

uint32_t toInt32(const uint8_t* X, size_t n)
{
	//1: 𝑡𝑜𝑡𝑎𝑙 ← 0
	uint32_t total = 0;
	// 2: for 𝑖 from 0 to 𝑛 − 1 do
	size_t i;
	for (i = 0; i < n; ++i)
	{
		//3: 𝑡𝑜𝑡𝑎𝑙 ← 256 ⋅ 𝑡𝑜𝑡𝑎𝑙 + 𝑋[𝑖]
		total = total * 256 + X[i];
		// 4: end for
	}
	return total;

}

#if 1
uint64_t DigestParse(uint32_t* idxleaf, const uint8_t* digest)
#else
uint64_t DigestParse(uint8_t* md, uint32_t* idxleaf, const uint8_t* digest)
#endif
{
	//uint8_t md[(K * A + 7) / 8];
	uint8_t tmp_idxtree[(FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8];
	uint8_t tmp_idxleaf[(FIPS205_H + 8 * FIPS205_D - 1) / (8 * FIPS205_D)];
	uint64_t idxtree;

	//memcpy(md, digest, (K * A + 7) / 8);
	// 7 tmp_idx_tree
	memcpy(tmp_idxtree, digest + (FIPS205_K * FIPS205_A + 7) / 8, sizeof(tmp_idxtree));

	memcpy(tmp_idxleaf, digest + (FIPS205_K * FIPS205_A + 7) / 8 + sizeof(tmp_idxtree), sizeof(tmp_idxleaf));

	idxtree = toInt64(tmp_idxtree, (FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8) & (((uint64_t)1 << (FIPS205_H - FIPS205_H / FIPS205_D)) - 1);

	*idxleaf = toInt32(tmp_idxleaf, ((FIPS205_H + 8 * FIPS205_D - 1) / (8 * FIPS205_D))) % ((uint64_t)1 << (FIPS205_H / FIPS205_D));

	return idxtree;
}

#if FIPS205_N == 16
#ifndef FAST
void base12(uint32_t* out, const uint8_t* X, uint32_t out_len)
{
	int i = 0;
	for (uint32_t j = 0; j < (FIPS205_K  * FIPS205_A + 7)/8; j += 3, i += 2)
	{
		out[i] = (((uint32_t)X[j]) << 4) | (X[j + 1] >> 4);
		out[i + 1] = ((uint32_t)(X[j + 1] & 0xF)) << 8 | (X[j + 2]);
	}
	
}
#define fors_base  base12
#else
void base6(uint32_t* out, const uint8_t* X, uint32_t out_len)
{
	int i = 0, j;
	for (j = 0; j < (FIPS205_K * FIPS205_A + 7) / 8 - 2; j += 3, i += 4)
	{
		out[i] = (X[j] >> 2);
		out[i + 1] = ((X[j] & 3) << 4) | (X[j + 1]>> 4);
		out[i + 2] = ((X[j + 1]  & 0xF) << 2) | (X[j + 2] >> 6) ;
		out[i + 3] = X[j + 2] & 0x3F;
	}
	out[out_len - 1] = X[j] >> 2;

}
#define fors_base  base6
#endif
#endif

#if FIPS205_N == 24 
#ifndef FAST
void base14_24(uint32_t* out, const uint8_t* X, uint32_t out_len)
{
	int i = 0, j;
	for (j = 0; j < 28; j += 7, i += 4)
	{
		out[i] = ((uint32_t)X[j] << 6) | (X[j + 1] >> 2);
		out[i + 1] = (((uint32_t)(X[j + 1] & 3)<< 12)) | ((uint32_t)X[j + 2] << 4) | (X[j + 3] >> 4);
		out[i + 2] = (((uint32_t)(X[j + 3] & 0xF)) << 10) | ((uint32_t)X[j + 4] << 2) | (X[j + 5] >> 6);
		out[i + 3] = (((uint32_t)(X[j + 5] & 0x3F)) << 8) | X[j + 6];

	}
	out[i] = ((uint32_t)X[j] << 6) | (X[j + 1] >> 2);
	

}
#define fors_base  base14



#else
//base8(x2, md, FIPS205_K)
void base8(uint32_t* out, const uint8_t* X, uint32_t out_len)
{
	for (int i = 0; i < out_len; ++i)
		out[i] = X[i];
}
#define fors_base  base8
#endif
#endif

#if FIPS205_N == 32 
#ifndef FAST
void base14_32(uint32_t* out, const uint8_t* X, uint32_t out_len)
{
	int i = 0, j;
	for (j = 0; j < 35; j += 7, i += 4)
	{
		out[i] = ((uint32_t)X[j] << 6) | (X[j + 1] >> 2);
		out[i + 1] = (((uint32_t)(X[j + 1] & 3) << 12)) | ((uint32_t)X[j + 2] << 4) | (X[j + 3] >> 4);
		out[i + 2] = (((uint32_t)(X[j + 3] & 0xF)) << 10) | ((uint32_t)X[j + 4] << 2) | (X[j + 5] >> 6);
		out[i + 3] = (((uint32_t)(X[j + 5] & 0x3F)) << 8) | X[j + 6];

	}
	out[i] = ((uint32_t)X[j] << 6) | (X[j + 1] >> 2);
	out[i + 1] = (((uint32_t)(X[j + 1] & 3) << 12)) | ((uint32_t)X[j + 2] << 4) | (X[j + 3] >> 4);
}
#define fors_base  base14

#else
//base8(x2, md, FIPS205_K)
void base9(uint32_t* out, const uint8_t* X, uint32_t out_len)
{
		int i = 0, j;
	for (j = 0; j < 36; j += 9, i += 8)
	{
		out[i] = ((uint32_t)X[j] << 1) | (X[j + 1] >> 7);
		out[i + 1] = (((uint32_t)(X[j + 1] & 0x7F) << 2)) | (X[j + 2] >> 6);
		out[i + 2] = (((uint32_t)(X[j + 2] & 0x3F) << 3)) | (X[j + 3] >> 5);
		out[i + 3] = (((uint32_t)(X[j + 3] & 0x1F)) << 4) | (X[j + 4] >> 4);
		out[i + 4] = (((uint32_t)(X[j + 4] & 0xF)) << 5) | (X[j + 5] >> 3);
		out[i + 5] = (((uint32_t)(X[j + 5] & 0x7)) << 6) | (X[j + 6] >> 2);
		out[i + 6] = (((uint32_t)(X[j + 6] & 0x3)) << 7) | (X[j + 7] >> 1);
		out[i + 7] = (((uint32_t)(X[j + 7] & 0x1)) << 8) | (X[j + 8] );
	}
	out[i] = ((uint32_t)X[j] << 1) | (X[j + 1] >> 7);
	out[i + 1] = (((uint32_t)(X[j + 1] & 0x7F) << 2)) | (X[j + 2] >> 6);
	out[i + 2] = (((uint32_t)(X[j + 2] & 0x3F) << 3)) | (X[j + 3] >> 5);

	

}
#define fors_base  base9
#endif
#endif




