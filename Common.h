#ifndef COMMON_H
#define COMMON_H
#include <inttypes.h>
#include <stdlib.h>
#include "FIPS_205_Params.h"
uint64_t DigestParse(uint32_t* idxleaf, const uint8_t* digest);
static uint32_t rand32()
{
	uint32_t res = rand() << (32 - 15);
	res |= rand() << 2;
	res |= rand() % 4;
	return res;
}

static uint64_t rand64()
{
	uint64_t res = (uint64_t)rand() << (64 - 15);
	res |= (uint64_t)rand() << (64 - 30);
	res |= (uint64_t)rand() << (64 - 45);
	res |= (uint64_t)rand() << (64 - 60);
	res |= (uint64_t)rand() % 16;
	return res;
}

static void toByte32_(uint8_t* byte, uint32_t value)
{
	byte[3] = (uint8_t)(value & 0xFF); value >>= 8;
	byte[2] = (uint8_t)(value & 0xFF); value >>= 8;
	byte[1] = (uint8_t)(value & 0xFF); value >>= 8;
	byte[0] = (uint8_t)(value & 0xFF); 
}

static void toByte16(uint8_t* byte, uint16_t value)
{
	
	byte[1] = (uint8_t)(value & 0xFF); value >>= 8;
	byte[0] = (uint8_t)(value & 0xFF);
}

void base_2b_old(uint32_t* base_b, const uint8_t* X, uint32_t b, uint32_t out_len);
void base_4_new(uint32_t* base_b, const uint8_t* X, uint32_t out_len);

//void base12(uint32_t* out, const uint8_t* X, uint32_t out_len);
#if FIPS205_N == 16
#ifndef FAST
void base12(uint32_t* out, const uint8_t* X, uint32_t out_len);
#define fors_base  base12
#else
void base6(uint32_t* out, const uint8_t* X, uint32_t out_len);
#define fors_base  base6
#endif
#endif

#if FIPS205_N == 24 
#ifndef FAST
void base14_24(uint32_t* out, const uint8_t* X, uint32_t out_len);
#define fors_base  base14_24
#else
void base8(uint32_t* out, const uint8_t* X, uint32_t out_len);
#define fors_base  base8
#endif
#endif

#if FIPS205_N == 32 
#ifndef FAST
void base14_32(uint32_t* out, const uint8_t* X, uint32_t out_len);
#define fors_base  base14_32
#else
void base9(uint32_t* out, const uint8_t* X, uint32_t out_len);
#define fors_base  base9
#endif
#endif


void print_params();

#endif
