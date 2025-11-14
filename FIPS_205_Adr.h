#ifndef FIPS_205_ADR_h
#define FIPS_205_ADR_h
#include <string.h>
#include "FIPS_205_Params.h"
#include "AVXconst.h"
//#include "FIPS_205_Common_fun.h"
#define	WOTS_HASH	0
#define	WOTS_PK		1
#define	TREE		2	
#define	FORS_TREE	3
#define FORS_ROOTS	4
#define WOTS_PRF	5
#define FORS_PRF	6

static void toBytes(uint8_t* bytes, uint64_t value) {
	bytes[0] = (value >> 56) & 0xFF;
	bytes[1] = (value >> 48) & 0xFF;
	bytes[2] = (value >> 40) & 0xFF;
	bytes[3] = (value >> 32) & 0xFF;
	bytes[4] = (value >> 24) & 0xFF;
	bytes[5] = (value >> 16) & 0xFF;
	bytes[6] = (value >> 8) & 0xFF;
	bytes[7] = (value >> 0) & 0xFF;
}

#ifndef SHA
#define	ADR_SIZE				32
#define	LayerAddressOFFSET		0
#define	TreeAddressOFFSET		4
#define	TypeOFFSET				16
#define	KeyPairAddressOFFSET	20
#define	ChainAddressOFFSET		24
#define	TreeHeightOFFSET		24
#define	HashAddressOFFSET		28
#define	TreeIndexOFFSET			28
#define setChainAddress(adr, value)	adr [ChainAddressOFFSET + 3] = value
#define setHashAddress(adr, value)	adr [HashAddressOFFSET + 3] = value
#define setKeyPairAddress(adr, value)	adr [KeyPairAddressOFFSET + 3] = value
#define setLayerAddress(adr, value)		adr [LayerAddressOFFSET + 3] = value
#define setTreeAddress(adr, value)		toBytes (adr + TreeAddressOFFSET + 4, value)
#define setTreeHeight(adr, value)		adr [TreeHeightOFFSET + 3] = value
#define setTreeIndex(adr, value)		adr [TreeIndexOFFSET + 3] = value
#define setType(adr, value)				adr [TypeOFFSET + 3] = value

#define getKeyPairAddress(adr)				(adr [KeyPairAddressOFFSET + 3])
#define getTreeIndex(adr)					(adr [TreeIndexOFFSET + 3])
#else
#define	ADR_SIZE				22
#define	LayerAddressOFFSET		0
#define	TreeAddressOFFSET		1
#define	TypeOFFSET				9
#define	KeyPairAddressOFFSET	10
#define	ChainAddressOFFSET		14
#define	TreeHeightOFFSET		14
#define	HashAddressOFFSET		18
#define	TreeIndexOFFSET			18
#define setChainAddress(adr, value)		adr [ChainAddressOFFSET + 3] = (value)
#define setHashAddress(adr, value)		adr [HashAddressOFFSET + 3] = (value)
#define setKeyPairAddress(adr, value)	{adr [KeyPairAddressOFFSET + 3] = (uint8_t)(value);adr [KeyPairAddressOFFSET + 2]=(uint8_t)((uint32_t)(value) >> 8);}  
#define setLayerAddress(adr, value)		adr [LayerAddressOFFSET] = value
#define setTreeAddress(adr, value)		toBytes (adr + TreeAddressOFFSET, value)
#define setTreeHeight(adr, value)		adr [TreeHeightOFFSET + 3] = value
#define setTreeIndex(adr, value)		{adr [TreeIndexOFFSET + 3] = (uint8_t)(value);adr [TreeIndexOFFSET + 2]=(uint8_t)((uint32_t)(value) >> 8); adr [TreeIndexOFFSET + 1]=(uint8_t)((uint32_t)(value) >> 16);}
#define setType(adr, value)				{memset (adr + TypeOFFSET, 0, ADR_SIZE - TypeOFFSET); adr [TypeOFFSET] = (value);}
#define setType1(adr, value)				adr [TypeOFFSET] = value;

#define getKeyPairAddress(adr)				((((uint32_t)(adr [KeyPairAddressOFFSET + 2])) << 8) + adr [KeyPairAddressOFFSET + 3])
#define getTreeIndex(adr)					((((uint32_t)(adr [TreeIndexOFFSET + 2])) << 8) + adr [TreeIndexOFFSET + 3])
#define getType(adr)					(adr [TypeOFFSET])
#endif

SUCCESS test_addr();

static __m256i ChangeTreeIndex(__m256i src, uint32_t value)
{
    
    uint8_t* val8 = (uint8_t*)&value;
    uint16_t t16_low = ((uint16_t)val8[0] << 8) | val8[1];
    uint16_t t16_high = ((uint16_t)val8[2] << 8) | val8[3];

    __m256i r = _mm256_or_si256(
        _mm256_or_si256(
            _mm256_andnot_si256(TreeIndexMaskaLow, _mm256_set1_epi16(t16_low)),
            _mm256_andnot_si256(TreeIndexMaskaHigh, _mm256_set1_epi16(t16_high))),
        _mm256_and_si256(
            _mm256_and_si256(TreeIndexMaskaLow, TreeIndexMaskaHigh),
            src));
    return r;
}

static __m256i ChangeType(__m256i src, uint8_t value)
{
    return _mm256_or_si256(_mm256_andnot_si256(TYPE_MASKA, src),
        _mm256_and_si256(_mm256_set1_epi8(value), TYPE_MASKA));
}












//// a != b
//#if 1
//
//typedef uint8_t B4[4];
//typedef uint8_t B8[8];
//typedef uint8_t B12[12];
//
//typedef struct _WOTS_hash_Address
//{
//	// type = WOTS_HASH
//	B4 key_pair_Address;
//	B4 chain_Address;
//	B4 hash_Address;
//}WOTS_hash_Address;
//
//typedef struct _WOTSpublic_key_compression_Address
//{
//	// type = WOTS_PK
//	B4 key_pair_Address;
//	B4 padding[2];	// 0
//
//}WOTSpublic_key_compression_Address;
//
//typedef struct _Hash_tree_Address
//{
//	// type = TREE
//	B4 padding;		// 0
//	B4 tree_height;
//	B4 tree_index;
//
//}Hash_tree_Address;
//
//typedef struct _FORS_tree_Address
//{
//	// type = FORS_TREE
//	// layer_Address = 0;
//	B4 key_pair_Address;
//	B4 tree_height;
//	B4 tree_index;
//}FORS_tree_Address;
//
//typedef struct _FORS_tree_roots_compression_Address
//{
//
//	// types = FORS_ROOTS
//	// layer_Address = 0;
//	B4 key_pair_Address;
//	B8 padding; // 0
//
//}FORS_tree_roots_compression_Address;
//typedef struct _WOTSkey_generation_Address
//{
//	// type = WOTS_PRF
//	B4 key_pair_Address;
//	B4 chain_Address;
//	B4 hash_Address; // = 0
//}WOTSkey_generation_Address;
//
//typedef struct _FORS_key_generation_Address
//{
//	// type = FORS_PRF
//	B4 key_pair_Address;
//	B4 tree_height; // 0
//	B4 tree_index; // 
//}FORS_key_generation_Address;
//
//typedef struct _ADR
//{
//	B4 layer_Address;
//	B12 tree_Address;
//	B4 type;
//	union {
//		WOTS_hash_Address wha;
//		WOTSpublic_key_compression_Address wpkca;
//		Hash_tree_Address hta;
//		FORS_tree_Address fta;
//		FORS_tree_roots_compression_Address ftrca;
//		WOTSkey_generation_Address wga;
//		FORS_key_generation_Address fkga;
//	};
//
//}ADR, * PADR;
//
//
//
//#define SetAddress4(adr, offset, value){			\
//	uint32_t value_ = value;					\
//	uint8_t* p = adr + offset + 4;	\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = value_;								\
//}
//
//#define SetAddress4_0(adr, offset){			\
//	uint32_t* p = (uint32_t*)(adr + offset) ;	\
//	*p = 0;									\
//}
//
//#define SetAddressType4_0(adr, value){				\
//	uint32_t* p = (uint32_t*)adr + 4;				\
//	p [1] = 0; p [2] = 0; p[3] = 0;	\
//	SetAddress4(adr, TypeAndClearOFFSET, value);\
//}
//
//#define SetAddress8(adr, offset, value){			\
//	uint64_t value_ = value;						\
//	uint8_t* p = (uint8_t*)adr + offset + 12;	\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	*--p = 0;				\
//	*--p = 0;				\
//	*--p = 0;				\
//	*--p = 0;				\
//}
//
//#define	GetAddress4(adr, offset, value){	\
//	uint8_t *p = /*(uint8_t *)*/adr +offset;								\
//	value = ((((0 + (*p))*256 + *(p + 1)) *256 + *(p+2))*256 + *(p+3));	\
//}
//#define SetFromGet4(dest, src, offset) *(uint32_t*)(dest +offset) = *(uint32_t*)(src +offset) 
//
//#define	GetAddress8(adr, offset, value){								\
//	uint8_t *p = /*(uint8_t *)*/adr +offset + 4;								\
//	value = ((((0 + (*p))*256 + *(p + 1)) *256 + *(p+2))*256 + *(p+3));	\
//	value = ((((value * 256 + (*(p + 4)))*256 + *(p + 5)) *256 + *(p+6))*256 + *(p+7));	\
//}	
//
//#define ShortSetAddress1(adr, offset, value)	(*((adr) + (offset)) = (value))
//#define ShortSetAddress4(adr, offset, value)	SetAddress4 (adr, offset, value)
//#define ShortSetAddress4_0(adr, offset)			SetAddress4_0 (adr, offset)
//#define ShortSetAddress8(adr, offset, value)	{			\
//	uint8_t* p = (uint8_t*)adr + offset + 8;	\
//	uint64_t value_ = value;					\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//	value_ /= 256;								\
//	*--p = (uint8_t)(value_ % 256);				\
//}
//
//#define ShortSetAddressType1(adr, type8)\
//	*(adr + ShortTypeAndClearOFFSET) = type8;					\
//	memset (adr + ShortTypeAndClearOFFSET + 1, 0, 12);
//
//#define ShortGetAddressType1(adr)\
//	*(adr + ShortTypeAndClearOFFSET)
//	
//	
//#define ShortGetAddress1(adr, offset)	(*((adr) + (offset)))
//#define ShortGetAddress4(adr, offset, value)	GetAddress4 (adr, offset, value)
////#define ShortGetAddress8(adr, offset, value)	GetAddress8 (adr, offset, value)
//#define	ShortGetAddress8(adr, offset, value){								\
//	uint8_t *p = (uint8_t *)adr +offset;								\
//	value = ((((0 + (*p))*256 + *(p + 1)) *256 + *(p+2))*256 + *(p+3));	\
//	value = ((((value * 256 + (*(p + 4)))*256 + *(p + 5)) *256 + *(p+6))*256 + *(p+7));	\
//}	
//#define ShortSetFromGet4(dest, src, offset) *(uint32_t*)(dest +offset) = *(uint32_t*)(src +offset) 
//
//
//static _inline void setLayerAddress(PADR adr, uint32_t value)
//{
//	//adr->layer_Address = ToBigEndian32(value);
//	///*adr->layer_Address = */toByte (adr->layer_Address, value, 4);
//#if 1
//	toByte32(adr->layer_Address, value, 4);
//#else
//	uint8_t* p = adr->layer_Address + 4;
//	uint8_t* p = (uint8_t*)adr->layer_Address + 4;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = value;
//#endif
//}
//
//static _inline void setLayerAddress_(PADR adr, uint32_t value)
//{
//	//adr->layer_Address = ToBigEndian32(value);
//	///*adr->layer_Address = */toByte (adr->layer_Address, value, 4);
//	
//	toByte32(adr->layer_Address, value, 4);
//}
//// setKeyPairAddress
//static _inline void setTreeAddress(PADR adr, uint64_t value)
//{
//	//ToBigEndian96(adr->tree_Address, value);
//#if 1
//	toByte64(adr->tree_Address, value, 12);
//#else
//	uint8_t* p = (uint8_t*)adr->tree_Address +12;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	*--p = 0;
//	*--p = 0;
//	*--p = 0;
//	*--p = 0;
//#endif
//	
//
//}
//
//// ADRS.setTypeAndClear(𝑌)
//static _inline void setTypeAndClear(PADR adr, uint32_t value)
//{
//	//adr->type = ToBigEndian32(Y);
//#if 1
//	toByte32(adr->type, value, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->type + 4;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = value;
//#endif
//	memset((uint32_t*)adr + 5, 0, 12);
//}
//
//static _inline void setKeyPairAddress(PADR adr, uint32_t value)
//{
//	//uint32_t* p = (uint32_t*)adr;
//	//p[5] = ToBigEndian32(i);
//#if 1
//	toByte32(adr->wha.key_pair_Address, value, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->wha.key_pair_Address + 4;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = value;
//#endif
//}
//
//static _inline void setChainAddress(PADR adr, uint32_t value)
//{
//	//uint32_t* p = (uint32_t*)adr;
//	//p[6] = ToBigEndian32(i);
//#if 1
//	toByte32(adr->wha.chain_Address, value, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->wha.chain_Address + 4;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = value;
//#endif
//}
//
//static _inline void setTreeHeight(PADR adr, uint32_t value)
//{
//#if 1
//	toByte32(adr->hta.tree_height, value, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->hta.tree_height + 4;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = value;
//#endif
//
//}
//
//static _inline void setHashAddress(PADR adr, uint32_t value)
//{
//#if 1
//	toByte32(adr->wha.hash_Address, value, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->wha.hash_Address + 4;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = value;
//#endif
//}
//
//static _inline void setTreeIndex(PADR adr, uint32_t value)
//{
//	//uint32_t* p = (uint32_t*)adr;
//	//p[7] = ToBigEndian32(i);
//	#if 1
//		toByte32(adr->hta.tree_index, value, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->hta.tree_index + 4;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = (uint8_t)(value % 256);
//	value /= 256;
//	*--p = value;
//#endif
//
//}
//
////static _inline uint32_t getLayer_Address_(PADR adr)
////{
////	
////}
//static _inline uint32_t getLayerAddress(PADR adr)
//{
//#if 3
//	return toInt32(adr->layer_Address, 4);
//#else
//	{
//		uint32_t value = 0;
//		uint8_t* p = (uint8_t*)adr->layer_Address;
//		value = *p++;
//		value = value * 256 + *p++;
//		value = value * 256 + *p++;
//		value = value * 256 + *p++;
//		return value;
//	}
//#endif
//}
//
//static _inline uint64_t getTreeAddress(PADR adr)
//{
//#if 3
//	return toInt64(adr->tree_Address, 12);
//#else
//	uint8_t* p = (uint8_t*)adr->tree_Address;
//	uint64_t value = *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	return value;
//
//#endif
//
//}
//
//static _inline uint32_t getType(PADR adr)
//{
//#if 3
//	return toInt32(adr->type, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->type;
//	uint32_t value = *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	return value;
//#endif
//}
//
//static _inline uint32_t getKeyPairAddress(PADR adr)
//{
//	//uint32_t* p = (uint32_t*)adr;
//	//return p[5];
//	//return ToBigEndian32(p[5]);
//#if 3
//	return toInt32(adr->wha.key_pair_Address, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->wha.key_pair_Address;
//	uint32_t value = *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	return value;
//#endif
//}
//
//static _inline uint32_t getTreeIndex(PADR adr)
//{
//	//uint32_t* p = (uint32_t*)adr;
//	//return p[7];
//	//return ToBigEndian32(p[7]);
//#if 1
//	return toInt32(adr->hta.tree_index, 4);
//#else
//	uint8_t* p = (uint8_t*)adr->hta.tree_index;
//	uint32_t value = *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	value = value * 256 + *p++;
//	return value;
//#endif
//}
//
//typedef struct _ADR_C
//{
//	uint8_t layer_Address;
//	B8 tree_Address;
//	uint8_t type;
//	union {
//		WOTS_hash_Address wha;
//		WOTSpublic_key_compression_Address wpkca;
//		Hash_tree_Address hta;
//		FORS_tree_Address fta;
//		FORS_tree_roots_compression_Address ftrca;
//		WOTSkey_generation_Address wga;
//		FORS_key_generation_Address fkga;
//	};
//
//}ADR_C, * PADR_C;
//
//static _inline void setLayerAddress_c(PADR_C adr, uint8_t value)
//{
//	adr->layer_Address = value;
//}
//
//static _inline void setTreeAddress_c(PADR_C adr, uint64_t value)
//{
//	/*adr->tree_Address[0] = value[0];
//	adr->tree_Address[1] = value[1];
//	adr->tree_Address[2] = value[2];*/
//	//memcpy(adr->tree_Address, value, 8);
//	//adr->tree_Address = ToBigEndian64(value);
//	toByte64(adr->tree_Address, value, 8);
//}
//
//// ADRS.setTypeAndClear(𝑌)
//static _inline void setTypeAndClear_c(PADR_C adr, uint8_t Y)
//{
//	adr->type = Y;
//	memset((uint8_t*)adr + 10, 0, 12);
//}
//static _inline void setType_c(PADR_C adr, uint32_t Y)
//{
//	adr->type = Y;
//	memset((uint8_t*)adr + 10, 0, 12);
//	toByte32(&adr->type, Y, 1);
//}
//
//static _inline void setKeyPairAddress_c(PADR_C adr, uint32_t i)
//{
//	//uint8_t* p = (uint8_t*)adr;
//	//memcpy(p + 10, (uint8_t*)&i, 4);
//	//p[5] = i;
//	toByte32(adr->wha.key_pair_Address, i, 4);
//}
//
//static _inline void setChainAddress_c(PADR_C adr, uint32_t i)
//{
//	/*uint8_t* p = (uint8_t*)adr;
//	memcpy(p + 14, (uint8_t*)&i, 4);*/
//	//p[6] = i;
//	toByte32(adr->wha.chain_Address, i, 4);
//}
//
//static _inline void setTreeHeight_c(PADR_C adr, uint32_t i)
//{
//	//uint8_t* p = (uint8_t*)adr;
//	//memcpy(p + 14, (uint8_t*)&i, 4);
//	//p[6] = i;
//	toByte32(adr->fta.tree_height, i, 4);
//}
//
//static _inline void setHashAddress_c(PADR_C adr, uint32_t i)
//{
//	/*uint8_t* p = (uint8_t*)adr;
//	memcpy(p + 18, (uint8_t*)&i, 4);*/
//	//p[7] = i;
//	toByte32(adr->wga.hash_Address, i, 4);
//}
//
//static _inline void setTreeIndex_c(PADR_C adr, uint32_t i)
//{
//	//uint8_t* p = (uint8_t*)adr;
//	//memcpy(p + 18, (uint8_t*)&i, 4);
//	//p[7] = i;
//	toByte32(adr->fta.tree_index, i, 4);
//}
//
//static _inline uint32_t getKeyPairAddress_c(PADR_C adr)
//{
//	/*uint8_t* p = (uint8_t*)adr;
//	uint32_t value;
//	memcpy((uint8_t*)&value, p + 10, 4);*/
//	return toInt32(adr->wha.key_pair_Address, 4);
//	
//}
//
//static _inline uint32_t getTreeIndex_c(PADR_C adr)
//{
//	/*uint8_t* p = (uint8_t*)adr;
//	uint32_t value;
//	memcpy((uint8_t*)&value, p + 18, 4);
//	return value;*/
//	return toInt32(adr->fta.tree_index, 4);
//
//}
///*
//	B4 layer_Address;
//	B12 tree_Address;
//	uint32_t type;
//*/
//static _inline void toShort(PADR_C Adr_c, const PADR Adr)
//{
//	uint32_t value = getLayerAddress(Adr);
//	setLayerAddress_c(Adr_c, value);
//	uint64_t value64 = getTreeAddress(Adr);
//	setTreeAddress_c(Adr_c, value64);
//	value = getType(Adr);
//	setType_c(Adr_c, value);
//	memcpy((uint8_t*)Adr_c + 10, (uint8_t*)Adr + 20, 12);
//	/*memcpy(Adr_c->tree_Address, temp + 4, 8);
//	toByte32(&Adr_c->type, Adr->type, 1);
//	memcpy((uint8_t*)Adr_c + 10, (uint8_t*)Adr + 20, 12);*/
//}
//
//
//
//#else
//static uint32_t ToBigEndian32(uint32_t a)
//{
//#ifdef LITTLE_ENDIAN
//	uint32_t b;
//	uint8_t* a8 = (uint8_t*)&a, * b8 = (uint8_t*)&b;
//	b8[3] = a8[0]; b8[2] = a8[1]; b8[1] = a8[2]; b8[0] = a8[3];
//#else
//	b = a;
//#endif
//	return b;
//}
//
//static uint64_t ToBigEndian64(uint64_t a)
//{
//#ifdef LITTLE_ENDIAN
//	uint32_t b;
//	uint8_t* a8 = (uint8_t*)&a, * b8 = (uint8_t*)&b;
//	for (size_t i = 0; i < 8; ++i)
//		b8[i] = a8[7 - i];
//#else
//	b = a;
//#endif
//	return b;
//}
//
//static void ToBigEndian96( uint32_t b[3], const uint32_t a [3])
//{
//#ifdef LITTLE_ENDIAN
//	
//	uint8_t* a8 = (uint8_t*)a, * b8 = (uint8_t*)b;
//	for (size_t i = 0; i < 12; ++i)
//	{
//		b8[i] = a8[11 - i];
//	}
//#else
//	b[0] = a[0]; b[1] = a[1]; b[2] = a[2];
//#endif
//	
//}
//
//
//typedef struct _WOTS_hash_Address
//{
//	// type = WOTS_HASH
//	uint32_t key_pair_Address;
//	uint32_t chain_Address;
//	uint32_t hash_Address;
//}WOTS_hash_Address;
//
//typedef struct _WOTSpublic_key_compression_Address
//{
//	// type = WOTS_PK
//	uint32_t key_pair_Address;
//	uint32_t padding[2];	// 0
//
//}WOTSpublic_key_compression_Address;
//
//typedef struct _Hash_tree_Address
//{
//	// type = TREE
//	uint32_t padding;		// 0
//	uint32_t tree_height;
//	uint32_t tree_index;
//
//}Hash_tree_Address;
//
//typedef struct _FORS_tree_Address
//{
//	// type = FORS_TREE
//	// layer_Address = 0;
//	uint32_t key_pair_Address;
//	uint32_t tree_height;
//	uint32_t tree_index;
//}FORS_tree_Address;
//
//typedef struct _FORS_tree_roots_compression_Address
//{
//
//	// types = FORS_ROOTS
//	// layer_Address = 0;
//	uint32_t key_pair_Address;
//	uint32_t padding[2]; // 0
//
//}FORS_tree_roots_compression_Address;
//typedef struct _WOTSkey_generation_Address
//{
//	// type = WOTS_PRF
//	uint32_t key_pair_Address;
//	uint32_t chain_Address; 
//	uint32_t hash_Address; // = 0
//}WOTSkey_generation_Address;
//
//typedef struct _FORS_key_generation_Address
//{
//	// type = FORS_PRF
//	uint32_t key_pair_Address;
//	uint32_t tree_height; // 0
//	uint32_t tree_index; // 
//}FORS_key_generation_Address;
//
//typedef struct _ADR
//{
//	uint32_t layer_Address;
//	uint32_t tree_Address[3];
//	uint32_t type;
//	union {
//		WOTS_hash_Address wha;
//		WOTSpublic_key_compression_Address wpkca;
//		Hash_tree_Address hta;
//		FORS_tree_Address fta;
//		FORS_tree_roots_compression_Address ftrca;
//		WOTSkey_generation_Address wga;
//		FORS_key_generation_Address fkga;
//	};
//	
//}ADR, *PADR;
//
//static _inline void setLayerAddress(PADR adr, uint8_t value)
//{	
//	adr->layer_Address = ToBigEndian32(value);
//	///*adr->layer_Address = */toByte (adr->layer_Address, value, 4);
//}
//// setKeyPairAddress
//static _inline void setTreeAddress(PADR adr, uint32_t value[3])
//{
//	ToBigEndian96(adr->tree_Address, value);
//
//}
//
//// ADRS.setTypeAndClear(𝑌)
//static _inline void setTypeAndClear(PADR adr, uint32_t Y)
//{
//	adr->type = ToBigEndian32(Y);
//	memset((uint32_t*)adr + 5, 0, 12);
//}
//
//static _inline void setKeyPairAddress(PADR adr, uint32_t i)
//{
//	uint32_t* p = (uint32_t*)adr;
//	p[5] = ToBigEndian32(i);
//}
//
//static _inline void setChainAddress(PADR adr, uint32_t i)
//{
//	uint32_t* p = (uint32_t*)adr;
//	p[6] = ToBigEndian32(i);
//}
//
//static _inline void setTreeHeight(PADR adr, uint32_t i)
//{
//	uint32_t* p = (uint32_t*)adr;
//	p[6] = ToBigEndian32(i);
//}
//
//static _inline void setHashAddress (PADR adr, uint32_t i)
//{
//	uint32_t* p = (uint32_t*)adr;
//	p[7] = ToBigEndian32(i);
//}
//
//static _inline void setTreeIndex(PADR adr, uint32_t i)
//{
//	uint32_t* p = (uint32_t*)adr;
//	p[7] = ToBigEndian32(i);
//}
//
////static _inline uint32_t getLayer_Address_(PADR adr)
////{
////	
////}
//
//static _inline uint32_t getKeyPairAddress(PADR adr)
//{
//	uint32_t* p = (uint32_t*)adr;
//	//return p[5];
//	return ToBigEndian32(p[5]);
//}
//
//static _inline uint32_t getTreeIndex(PADR adr)
//{
//	uint32_t* p = (uint32_t*)adr;
//	//return p[7];
//	return ToBigEndian32(p[7]);
//}
//
//typedef struct _ADR_C
//{
//	uint8_t layer_Address;
//	uint64_t tree_Address;
//	uint8_t type;
//	union {
//		WOTS_hash_Address wha;
//		WOTSpublic_key_compression_Address wpkca;
//		Hash_tree_Address hta;
//		FORS_tree_Address fta;
//		FORS_tree_roots_compression_Address ftrca;
//		WOTSkey_generation_Address wga;
//		FORS_key_generation_Address fkga;
//	};
//
//}ADR_C, * PADR_C;
//
//static _inline void setLayerAddress_c(PADR_C adr, uint8_t value)
//{
//	adr->layer_Address = value;
//}
//
//static _inline void setTreeAddress_c(PADR_C adr, uint64_t value)
//{
//	/*adr->tree_Address[0] = value[0];
//	adr->tree_Address[1] = value[1];
//	adr->tree_Address[2] = value[2];*/
//	//memcpy(adr->tree_Address, value, 8);
//	adr->tree_Address = ToBigEndian64(value);
//
//}
//
//// ADRS.setTypeAndClear(𝑌)
//static _inline void setTypeAndClear_c(PADR_C adr, uint8_t Y)
//{
//	adr->type = Y;
//	memset((uint8_t*)adr + 10, 0, 12);
//}
//
//static _inline void setKeyPairAddress_c(PADR_C adr, uint32_t i)
//{
//	uint8_t* p = (uint8_t*)adr;
//	memcpy(p + 10, (uint8_t*)&i, 4);
//	//p[5] = i;
//}
//
//static _inline void setChainAddress_c(PADR_C adr, uint32_t i)
//{
//	uint8_t* p = (uint8_t*)adr;
//	memcpy(p + 14, (uint8_t*)&i, 4);
//	//p[6] = i;
//}
//
//static _inline void setTreeHeight_c(PADR_C adr, uint32_t i)
//{
//	uint8_t* p = (uint8_t*)adr;
//	memcpy(p + 14, (uint8_t*)&i, 4);
//	//p[6] = i;
//}
//
//static _inline void setHashAddress_c(PADR_C adr, uint32_t i)
//{
//	uint8_t* p = (uint8_t*)adr;
//	memcpy(p + 18, (uint8_t*)&i, 4);
//	//p[7] = i;
//}
//
//static _inline void setTreeIndex_c(PADR_C adr, uint32_t i)
//{
//	uint8_t* p = (uint8_t*)adr;
//	memcpy(p + 18, (uint8_t*)&i, 4);
//	//p[7] = i;
//}
//
//static _inline uint32_t getKeyPairAddress_c(PADR_C adr)
//{
//	uint8_t* p = (uint8_t*)adr;
//	uint32_t value;
//	memcpy((uint8_t*)&value, p + 10, 4);
//	return value;
//}
//
//static _inline uint32_t getTreeIndex_c(PADR_C adr)
//{
//	uint8_t* p = (uint8_t*)adr;
//	uint32_t value;
//	memcpy((uint8_t*)&value, p + 18, 4);
//	return value;
//	
//}
//
//static _inline void toShort(uint8_t * Adr_c, const uint8_t *Adr)
//{
//	//uint32_t layer_Address = Adr->layer_Address;
//	
//
//	//toByte32(&Adr_c->layer_Address, layer_Address, 1);
//	Adr_c[0] = Adr[3];
//	//uint8_t temp[12];
//	memcpy(Adr_c + 1, Adr + 8, 8);
//	Adr_c[9] = Adr[19];
//	memcpy(Adr_c + 10, Adr + 20, 12);
//	/*memcpy(Adr_c->tree_Address, temp + 4, 8);
//	toByte32(&Adr_c->type, Adr->type, 1);
//	memcpy((uint8_t*)Adr_c + 10, (uint8_t*)Adr + 20, 12);*/
//}
//#endif
//
//int test_addr();
#endif