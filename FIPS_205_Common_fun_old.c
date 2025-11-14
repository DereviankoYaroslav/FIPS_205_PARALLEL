#include <stdlib.h>
#include <stdio.h>
#include "FIPS_205_Common_fun_old.h"

/*
Algorithm 1 len2 = gen_len2(𝑛, 𝑙𝑔𝑤)
*/
size_t gen_len2(size_t n, size_t lgw)
{
	// 1: 𝑤 ← 2^𝑙𝑔𝑤 ▷				Equation 5.1
	// 2: 𝑙𝑒𝑛1 ← ⌊8⋅𝑛 + 𝑙𝑔𝑤−1*/
	size_t w = (size_t)1 << lgw;
	size_t len1 = (8 * n + lgw - 1) / lgw;
	// 3: 𝑚𝑎𝑥_𝑐ℎ𝑒𝑐𝑘𝑠𝑢𝑚 = 𝑙𝑒𝑛1 ⋅ (𝑤 − 1) ▷ maximum possible checksum value
	size_t max_check_sum = len1 * (w - 1);
	// 4 𝑙𝑒𝑛2 ← 1 ▷ maximum value that may be signed using
	size_t len2 = 1;
	// 5: 𝑐𝑎𝑝𝑎𝑐𝑖𝑡𝑦 ← 𝑤 ▷ 𝑙𝑒𝑛2 hash chains is 𝑤𝑙𝑒𝑛2 − 1 = 𝑐𝑎𝑝𝑎𝑐𝑖𝑡𝑦 − 1
	size_t capacity = w;
	// 6: while 𝑐𝑎𝑝𝑎𝑐𝑖𝑡𝑦 ≤ 𝑚𝑎𝑥_𝑐ℎ𝑒𝑐𝑘𝑠𝑢𝑚 do 7: 𝑙𝑒𝑛2 ← 𝑙𝑒𝑛2 + 1
	while (capacity <= max_check_sum)
	{
		++len2;
		// 8: 𝑐𝑎𝑝𝑎𝑐𝑖𝑡𝑦 ← 𝑐𝑎𝑝𝑎𝑐𝑖𝑡𝑦 ⋅ 𝑤
		capacity *= w;

	}
	printf("len1 = %zd\tlen2 = %zd\n", len1, len2);
	return len2;
}

size_t gen_m(size_t h, size_t h_, size_t k, size_t a)
{
	size_t calc_m = (h - h_ + 7) / 8 + (h_ + 7) / 8 + (k * a + 7) / 8;
	return calc_m;
}

SUCCESS test_gen_len2()
{
	SUCCESS success = OK;
	size_t n = 16, lgw = 4;
	size_t len2 = gen_len2(16, 4);
	success |= len2 != 3;
	len2 = gen_len2(24, 4);
	success |= len2 != 3;
	len2 = gen_len2(32, 4);
	success |= len2 != 3;
	return success;

}

//// Algorithm 2 toInt(𝑋, 𝑛)
//// Converts a byte string to an integer.
//uint64_t toInt64(const uint8_t* X, size_t n)
//{
//	//1: 𝑡𝑜𝑡𝑎𝑙 ← 0
//	uint64_t total = 0;
//	// 2: for 𝑖 from 0 to 𝑛 − 1 do
//	size_t i;
//	for (i = 0; i < n; ++i)
//	{
//		//3: 𝑡𝑜𝑡𝑎𝑙 ← 256 ⋅ 𝑡𝑜𝑡𝑎𝑙 + 𝑋[𝑖]
//		total = total * 256 + X[i];
//		// 4: end for
//	}
//	return total;
//
//}
//
//uint32_t toInt32(const uint8_t* X, size_t n)
//{
//	//1: 𝑡𝑜𝑡𝑎𝑙 ← 0
//	uint32_t total = 0;
//	// 2: for 𝑖 from 0 to 𝑛 − 1 do
//	size_t i;
//	for (i = 0; i < n; ++i)
//	{
//		//3: 𝑡𝑜𝑡𝑎𝑙 ← 256 ⋅ 𝑡𝑜𝑡𝑎𝑙 + 𝑋[𝑖]
//		total = total * 256 + X[i];
//		// 4: end for
//	}
//	return total;
//
//}
//Algorithm 3 toByte(𝑥, 𝑛)
//Converts an integer to a byte string.
//Input: Integer 𝑥, string length 𝑛.Output : Byte string of length 𝑛 containing binary representation of 𝑥 in big - endian byte - order.
void toByte64(uint8_t* S, uint64_t x, size_t n)
{
	//1 : 𝑡𝑜𝑡𝑎𝑙 ← 𝑥
	size_t total = x;

	//	2 : //	for 𝑖 from 0 to 𝑛 − 1 do
	size_t i;
	for (i = 0; i < n; ++i)
	{
		//		3 : 4 :
		//		𝑆[𝑛 − 1 − 𝑖] ← 𝑡𝑜𝑡𝑎𝑙 mod 256 𝑡𝑜𝑡𝑎𝑙 ← 𝑡𝑜𝑡𝑎𝑙 ≫ 8
		S[n - 1 - i] = total % 256;
		total >>= 8;

		//		5 :
		//		end for
	}
	//		6: return 𝑆
	//return S;
}

void toByte32(uint8_t* S, uint32_t x_, size_t n)
{
	//1 : 𝑡𝑜𝑡𝑎𝑙 ← 𝑥
	uint64_t x = x_;
	size_t total = x;

	//	2 : //	for 𝑖 from 0 to 𝑛 − 1 do
	size_t i;
	for (i = 0; i < n; ++i)
	{
		//		3 : 4 :
		//		𝑆[𝑛 − 1 − 𝑖] ← 𝑡𝑜𝑡𝑎𝑙 mod 256 𝑡𝑜𝑡𝑎𝑙 ← 𝑡𝑜𝑡𝑎𝑙 ≫ 8
		S[n - 1 - i] = total % 256;
		total >>= 8;

		//		5 :
		//		end for
	}
	//		6: return 𝑆
	//return S;
}

SUCCESS test_toInt_toByte()
{
	//uint64_t toInt(const uint8_t * X, size_t n);
	SUCCESS success = OK;
	for (size_t i = 0; i < 256; ++i)
	{
		uint8_t S[8];
		uint64_t X = ((uint64_t)rand() << (64 - 15)) |
			((uint64_t)rand() << (64 - 30)) |
			((uint64_t)rand() << (64 - 45))|
			rand (), X1;
		toByte64(S, X, 8);
		X1 = toInt64(S, 8);
		success |= X != X1;
	}

	return success;

}
//Algorithm 4 base_2b(𝑋, 𝑏, 𝑜𝑢𝑡_𝑙𝑒𝑛)
//Computes the base 2𝑏 representation of 𝑋.Input: Byte string 𝑋 of length at least ⌈𝑜𝑢𝑡_8𝑙𝑒𝑛⋅𝑏⌉, integer 𝑏, output length 𝑜𝑢𝑡_𝑙𝑒𝑛.Output : Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range[0, …, 2𝑏 −1].
// Рядок байтів 𝑋 перетворюється в масив цілих завдовжки кожне ціле завдовжки b бітів
void base_2b(uint32_t* base_b, const uint8_t* X, size_t b, size_t out_len)
{
	//1 : 𝑖𝑛 ← 0
	size_t in = 0, out;
	//2 : 𝑏𝑖𝑡𝑠 ← 0
	size_t bits = 0;
	//3 : 𝑡𝑜𝑡𝑎𝑙 ← 0
	uint32_t total = 0, mod_2b = 1 << b;


	//4 : for 𝑜𝑢𝑡 from 0 to 𝑜𝑢𝑡_𝑙𝑒𝑛 − 1 do

	for (out = 0; out < out_len; ++out)
	{
		//5 : while 𝑏𝑖𝑡𝑠 < 𝑏 do
		while (bits < b)
		{
			//	6 : 𝑡𝑜𝑡𝑎𝑙 ←(𝑡𝑜𝑡𝑎𝑙 ≪ 8) + 𝑋[𝑖𝑛]
			total = (total << 8) + X[in];
			//	7 : 𝑖𝑛 ← 𝑖𝑛 + 1
			++in;
			//	8 : 𝑏𝑖𝑡𝑠 ← 𝑏𝑖𝑡𝑠 + 8
			bits += 8;
			//	9 : end while
		}
		//	10 : 𝑏𝑖𝑡𝑠 ← 𝑏𝑖𝑡𝑠 − 𝑏
		bits -= b;
		//	11 : 𝑏𝑎𝑠𝑒𝑏[𝑜𝑢𝑡] ←(𝑡𝑜𝑡𝑎𝑙 ≫ 𝑏𝑖𝑡𝑠) mod 2𝑏
		base_b[out] = (total >> bits) % mod_2b;


		//	12 : end for
	}
	//	13 : return 𝑏𝑎𝑠𝑒𝑏
}

// W = 16, b = 4
// + csum
uint32_t base_2b_(uint32_t* base_b, const uint8_t* X, uint32_t out_len)
{
	//1 : 𝑖𝑛 ← 0
	//size_t in = 0, out, csum = 0;
	////2 : 𝑏𝑖𝑡𝑠 ← 0
	//size_t bits = 0;
	////3 : 𝑡𝑜𝑡𝑎𝑙 ← 0
	//uint32_t total = 0, mod_2b = 1 << b;


	//4 : for 𝑜𝑢𝑡 from 0 to 𝑜𝑢𝑡_𝑙𝑒𝑛 − 1 do
#if 0
	for (out = 0; out < out_len; ++out)
	{
		//5 : while 𝑏𝑖𝑡𝑠 < 𝑏 do
		while (bits < b)
		{
			//	6 : 𝑡𝑜𝑡𝑎𝑙 ←(𝑡𝑜𝑡𝑎𝑙 ≪ 8) + 𝑋[𝑖𝑛]
			total = (total << 8) + X[in];
			//	7 : 𝑖𝑛 ← 𝑖𝑛 + 1
			++in;
			//	8 : 𝑏𝑖𝑡𝑠 ← 𝑏𝑖𝑡𝑠 + 8
			bits += 8;
			//	9 : end while
		}
		//	10 : 𝑏𝑖𝑡𝑠 ← 𝑏𝑖𝑡𝑠 − 𝑏
		bits -= b;
		//	11 : 𝑏𝑎𝑠𝑒𝑏[𝑜𝑢𝑡] ←(𝑡𝑜𝑡𝑎𝑙 ≫ 𝑏𝑖𝑡𝑠) mod 2𝑏
		base_b[out] = (total >> bits) % mod_2b;
		csum += W - 1 - base_b[out];


		//	12 : end for
	}
#else
	uint32_t in, out, csum = 0;
	for (in = 0, out = 0; out < out_len - 3; ++in, out+=2)
	{
		base_b[out] = X[in]  / 16;
		//csum += W - 1 - base_b[out];
		csum += base_b[out];
		base_b[out + 1] = X[in]  % 16;
		csum += base_b[out + 1];
	}
	csum = FIPS205_W * FIPS205_LEN1 - FIPS205_LEN1 - csum;
	//csum <<= ((8 - ((LEN2 * LOGW) % 8)) % 8);
	
	//toByte32(temp, (uint32_t)csum, (LEN2 * LOGW + 7) / 8);
	//base_2b(msg + LEN1, temp, LOGW, LEN2);
	base_b[out] = csum / 256;
	csum %= 256;
	base_b[out + 1] = (csum )  / 16;
	base_b[out + 2] = csum  %  16;
	return out + 3;
#endif

	//	13 : return 𝑏𝑎𝑠𝑒𝑏
	return csum;
}


//#if 1
//uint64_t DigestParse(uint32_t* idxleaf, const uint8_t* digest)
//#else
//uint64_t DigestParse(uint8_t *md, uint32_t * idxleaf, const uint8_t *digest)
//#endif
//{
//	//uint8_t md[(K * A + 7) / 8];
//	uint8_t tmp_idxtree[(FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8];
//	uint8_t tmp_idxleaf[(FIPS205_H + 8 * FIPS205_D - 1) / (8 * FIPS205_D)];
//	uint64_t idxtree;
//		
//	//memcpy(md, digest, (K * A + 7) / 8);
//	// 7 tmp_idx_tree
//	memcpy(tmp_idxtree, digest + (FIPS205_K * FIPS205_A + 7) / 8, sizeof(tmp_idxtree));
//	
//	memcpy(tmp_idxleaf, digest + (FIPS205_K * FIPS205_A + 7) / 8 + sizeof(tmp_idxtree), sizeof(tmp_idxleaf));
//	
//	idxtree = toInt64(tmp_idxtree, (FIPS205_H - FIPS205_H / FIPS205_D + 7) / 8) & (((uint64_t)1 << (FIPS205_H - FIPS205_H / FIPS205_D)) - 1);
//	
//	*idxleaf = toInt32(tmp_idxleaf, ((FIPS205_H + 8 * FIPS205_D - 1) / (8 * FIPS205_D))) % ((uint64_t)1 << (FIPS205_H / FIPS205_D));
//
//	return idxtree;
//}



