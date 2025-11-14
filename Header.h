#ifndef COMMON_H
#define COMMON_H
#include <inttypes.h>
static void toByte32(uint8_t* byte, uint32_t value)
{
	byte[3] = (uint8_t)(value & 0xFF); value >>= 8;
	byte[2] = (uint8_t)(value & 0xFF); value >>= 8;
	byte[1] = (uint8_t)(value & 0xFF); value >>= 8;
	byte[0] = (uint8_t)(value & 0xFF); 
}
#endif
