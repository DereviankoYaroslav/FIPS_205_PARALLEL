#ifndef FIPS_205_ADR_OLD_h

#if defined(_MSC_VER)
#define INLINE _inline
#else
#define INLINE inline
#endif

#define FIPS_205_ADR_OLD_h
#include <string.h>
#include "FIPS_205_Params.h"
#include "FIPS_205_Common_fun_old.h"
#define	WOTS_HASH_OLD	0
#define	WOTS_PK_OLD		1
#define	TREE_OLD		2	
#define	FORS_TREE_OLD	3
#define FORS_ROOTS_OLD	4
#define WOTS_PRF_OLD	5
#define FORS_PRF_OLD	6

typedef uint8_t B4[4];
typedef uint8_t B8[8];
typedef uint8_t B12[12];

typedef struct _WOTS_hash_Address
{
	// type = WOTS_HASH
	B4 key_pair_Address_OLD;
	B4 chain_Address_OLD;
	B4 hash_Address_OLD;
}WOTS_hash_Address_OLD;

typedef struct _WOTSpublic_key_compression_Address
{
	// type = WOTS_PK
	B4 key_pair_Address_OLD;
	B4 padding_OLD[2];	// 0

}WOTSpublic_key_compression_Address_OLD;

typedef struct _Hash_tree_Address
{
	// type = TREE
	B4 padding_OLD;		// 0
	B4 tree_height_OLD;
	B4 tree_index_OLD;

}Hash_tree_Address_OLD;

typedef struct _FORS_tree_Address
{
	// type = FORS_TREE
	// layer_Address = 0;
	B4 key_pair_Address_OLD;
	B4 tree_height_OLD;
	B4 tree_index_OLD;
}FORS_tree_Address_OLD;

typedef struct _FORS_tree_roots_compression_Address
{

	// types = FORS_ROOTS
	// layer_Address = 0;
	B4 key_pair_Address_OLD;
	B8 padding_OLD; // 0

}FORS_tree_roots_compression_Address_OLD;
typedef struct _WOTSkey_generation_Address
{
	// type = WOTS_PRF
	B4 key_pair_Address_OLD;
	B4 chain_Address_OLD;
	B4 hash_Address_OLD; // = 0
}WOTSkey_generation_Address_OLD;

typedef struct _FORS_key_generation_Address
{
	// type = FORS_PRF
	B4 key_pair_Address_OLD;
	B4 tree_height_OLD; // 0
	B4 tree_index_OLD; // 
}FORS_key_generation_Address_OLD;

typedef struct _ADR
{
	B4 layer_Address_OLD;
	B12 tree_Address_OLD;
	B4 type_OLD;
	union {
		WOTS_hash_Address_OLD wha;
		WOTSpublic_key_compression_Address_OLD wpkca;
		Hash_tree_Address_OLD hta;
		FORS_tree_Address_OLD fta;
		FORS_tree_roots_compression_Address_OLD ftrca;
		WOTSkey_generation_Address_OLD wga;
		FORS_key_generation_Address_OLD fkga;
	};

}ADR_OLD, * PADR_OLD;

#define	LayerAddressOFFSET_OLD		0
#define	TreeAddressOFFSET_OLD		4
#define	TypeAndClearOFFSET_OLD		16
#define	KeyPairAddressOFFSET_OLD	20
#define	ChainAddressOFFSET_OLD		24
#define	TreeHeightOFFSET_OLD		24
#define	HashAddressOFFSET_OLD		28
#define	TreeIndexOFFSET_OLD			28

#define	ShortLayerAddressOFFSET_OLD		0
#define	ShortTreeAddressOFFSET_OLD		1
#define	ShortTypeAndClearOFFSET_OLD		9
#define	ShortKeyPairAddressOFFSET_OLD	10
#define	ShortChainAddressOFFSET_OLD		14
#define	ShortTreeHeightOFFSET_OLD		14
#define	ShortHashAddressOFFSET_OLD		18
#define	ShortTreeIndexOFFSET_OLD		18

#define SetAddress4_OLD(adr, offset, value){			\
	uint32_t value_ = value;					\
	uint8_t* p = adr + offset + 4;	\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = value_;								\
}

#define SetAddress4_0_OLD(adr, offset){			\
	uint32_t* p = (uint32_t*)(adr + offset) ;	\
	*p = 0;									\
}

#define SetAddressType4_0_OLD(adr, value){				\
	uint32_t* p = (uint32_t*)adr + 4;				\
	p [1] = 0; p [2] = 0; p[3] = 0;	\
	SetAddress4_OLD(adr, TypeAndClearOFFSET, value);\
}

#define SetAddress8_OLD(adr, offset, value){			\
	uint64_t value_ = value;						\
	uint8_t* p = (uint8_t*)adr + offset + 12;	\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	*--p = 0;				\
	*--p = 0;				\
	*--p = 0;				\
	*--p = 0;				\
}

#define	GetAddress4_OLD(adr, offset, value){	\
	uint8_t *p = /*(uint8_t *)*/adr +offset;								\
	value = ((((0 + (*p))*256 + *(p + 1)) *256 + *(p+2))*256 + *(p+3));	\
}
#define SetFromGet4_OLD(dest, src, offset) *(uint32_t*)(dest +offset) = *(uint32_t*)(src +offset) 

#define	GetAddress8_OLD(adr, offset, value){								\
	uint8_t *p = /*(uint8_t *)*/adr +offset + 4;								\
	value = ((((0 + (*p))*256 + *(p + 1)) *256 + *(p+2))*256 + *(p+3));	\
	value = ((((value * 256 + (*(p + 4)))*256 + *(p + 5)) *256 + *(p+6))*256 + *(p+7));	\
}	

#define ShortSetAddress1_OLD(adr, offset, value)	(*((adr) + (offset)) = (value))
#define ShortSetAddress4_OLD(adr, offset, value)	SetAddress4_OLD (adr, offset, value)
#define ShortSetAddress4_0_OLD(adr, offset)			SetAddress4_0_OLD (adr, offset)
#define ShortSetAddress8_OLD(adr, offset, value)	{			\
	uint8_t* p = (uint8_t*)adr + offset + 8;	\
	uint64_t value_ = value;					\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
	value_ /= 256;								\
	*--p = (uint8_t)(value_ % 256);				\
}

#define ShortSetAddressType1_OLD(adr, type8)\
	*(adr + ShortTypeAndClearOFFSET_OLD) = type8;					\
	memset (adr + ShortTypeAndClearOFFSET_OLD + 1, 0, 12);

#define ShortGetAddressType1_OLD(adr)\
	*(adr + ShortTypeAndClearOFFSET_OLD)
	
	
#define ShortGetAddress1_OLD(adr, offset)	(*((adr) + (offset)))
#define ShortGetAddress4_OLD(adr, offset, value)	GetAddress4_OLD (adr, offset, value)
//#define ShortGetAddress8(adr, offset, value)	GetAddress8 (adr, offset, value)
#define	ShortGetAddress8_OLD(adr, offset, value){								\
	uint8_t *p = (uint8_t *)adr +offset;								\
	value = ((((0 + (*p))*256 + *(p + 1)) *256 + *(p+2))*256 + *(p+3));	\
	value = ((((value * 256 + (*(p + 4)))*256 + *(p + 5)) *256 + *(p+6))*256 + *(p+7));	\
}	
#define ShortSetFromGet4_OLD(dest, src, offset) *(uint32_t*)(dest +offset) = *(uint32_t*)(src +offset) 


static INLINE void setLayerAddress_OLD(PADR_OLD adr, uint32_t value)
{
	//adr->layer_Address = ToBigEndian32(value);
	///*adr->layer_Address = */toByte (adr->layer_Address, value, 4);
#if 1
	toByte32(adr->layer_Address_OLD, value, 4);
#else
	uint8_t* p = adr->layer_Address + 4;
	uint8_t* p = (uint8_t*)adr->layer_Address + 4;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = value;
#endif
}

static INLINE void setLayerAddress_(PADR_OLD adr, uint32_t value)
{
	//adr->layer_Address = ToBigEndian32(value);
	///*adr->layer_Address = */toByte (adr->layer_Address, value, 4);
	
	toByte32(adr->layer_Address_OLD, value, 4);
}
// setKeyPairAddress
static INLINE void setTreeAddress_OLD(PADR_OLD adr, uint64_t value)
{
	//ToBigEndian96(adr->tree_Address, value);
#if 1
	toByte64(adr->tree_Address_OLD, value, 12);
#else
	uint8_t* p = (uint8_t*)adr->tree_Address +12;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	*--p = 0;
	*--p = 0;
	*--p = 0;
	*--p = 0;
#endif
	

}

// ADRS.setTypeAndClear(𝑌)
static INLINE void setTypeAndClear_OLD(PADR_OLD adr, uint32_t value)
{
	//adr->type = ToBigEndian32(Y);
#if 1
	toByte32(adr->type_OLD, value, 4);
#else
	uint8_t* p = (uint8_t*)adr->type + 4;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = value;
#endif
	memset((uint32_t*)adr + 5, 0, 12);
}

static INLINE void setKeyPairAddress_OLD(PADR_OLD adr, uint32_t value)
{
	//uint32_t* p = (uint32_t*)adr;
	//p[5] = ToBigEndian32(i);
#if 1
	toByte32(adr->wha.key_pair_Address_OLD, value, 4);
#else
	uint8_t* p = (uint8_t*)adr->wha.key_pair_Address + 4;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = value;
#endif
}

static INLINE void setChainAddress_OLD(PADR_OLD adr, uint32_t value)
{
	//uint32_t* p = (uint32_t*)adr;
	//p[6] = ToBigEndian32(i);
#if 1
	toByte32(adr->wha.chain_Address_OLD, value, 4);
#else
	uint8_t* p = (uint8_t*)adr->wha.chain_Address + 4;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = value;
#endif
}

static INLINE void setTreeHeight_OLD(PADR_OLD adr, uint32_t value)
{
#if 1
	toByte32(adr->hta.tree_height_OLD, value, 4);
#else
	uint8_t* p = (uint8_t*)adr->hta.tree_height + 4;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = value;
#endif

}

static INLINE void setHashAddress_OLD(PADR_OLD adr, uint32_t value)
{
#if 1
	toByte32(adr->wha.hash_Address_OLD, value, 4);
#else
	uint8_t* p = (uint8_t*)adr->wha.hash_Address + 4;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = value;
#endif
}

static INLINE void setTreeIndex_OLD(PADR_OLD adr, uint32_t value)
{
	//uint32_t* p = (uint32_t*)adr;
	//p[7] = ToBigEndian32(i);
	#if 1
		toByte32(adr->hta.tree_index_OLD, value, 4);
#else
	uint8_t* p = (uint8_t*)adr->hta.tree_index + 4;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = (uint8_t)(value % 256);
	value /= 256;
	*--p = value;
#endif

}

//static _inline uint32_t getLayer_Address_(PADR adr)
//{
//	
//}
static INLINE uint32_t getLayerAddress_OLD(PADR_OLD adr)
{
#if 1
	return toInt32(adr->layer_Address_OLD, 4);
#else
	{
		uint32_t value = 0;
		uint8_t* p = (uint8_t*)adr->layer_Address;
		value = *p++;
		value = value * 256 + *p++;
		value = value * 256 + *p++;
		value = value * 256 + *p++;
		return value;
	}
#endif
}

static INLINE uint64_t getTreeAddress_OLD(PADR_OLD adr)
{
#if 1
	return toInt64(adr->tree_Address_OLD, 12);
#else
	uint8_t* p = (uint8_t*)adr->tree_Address;
	uint64_t value = *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	return value;

#endif

}

static INLINE uint32_t getType_OLD(PADR_OLD adr)
{
#if 1
	return toInt32(adr->type_OLD, 4);
#else
	uint8_t* p = (uint8_t*)adr->type;
	uint32_t value = *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	return value;
#endif
}

static INLINE uint32_t getKeyPairAddress_OLD(PADR_OLD adr)
{
	//uint32_t* p = (uint32_t*)adr;
	//return p[5];
	//return ToBigEndian32(p[5]);
#if 1
	return toInt32(adr->wha.key_pair_Address_OLD, 4);
#else
	uint8_t* p = (uint8_t*)adr->wha.key_pair_Address;
	uint32_t value = *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	return value;
#endif
}

static INLINE uint32_t getTreeIndex_OLD(PADR_OLD adr)
{
	//uint32_t* p = (uint32_t*)adr;
	//return p[7];
	//return ToBigEndian32(p[7]);
#if 1
	return toInt32(adr->hta.tree_index_OLD, 4);
#else
	uint8_t* p = (uint8_t*)adr->hta.tree_index;
	uint32_t value = *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	value = value * 256 + *p++;
	return value;
#endif
}

typedef struct _ADR_C
{
	uint8_t layer_Address_OLD;
	B8 tree_Address_OLD;
	uint8_t type_OLD;
	union {
		WOTS_hash_Address_OLD wha;
		WOTSpublic_key_compression_Address_OLD wpkca;
		Hash_tree_Address_OLD hta;
		FORS_tree_Address_OLD fta;
		FORS_tree_roots_compression_Address_OLD ftrca;
		WOTSkey_generation_Address_OLD wga;
		FORS_key_generation_Address_OLD fkga;
	};

}ADR_C_OLD, * PADR_C_OLD;

static INLINE void setLayerAddress_c_OLD(PADR_C_OLD adr, uint8_t value)
{
	adr->layer_Address_OLD = value;
}

static INLINE void setTreeAddress_c_OLD(PADR_C_OLD adr, uint64_t value)
{
	/*adr->tree_Address[0] = value[0];
	adr->tree_Address[1] = value[1];
	adr->tree_Address[2] = value[2];*/
	//memcpy(adr->tree_Address, value, 8);
	//adr->tree_Address = ToBigEndian64(value);
	toByte64(adr->tree_Address_OLD, value, 8);
}

// ADRS.setTypeAndClear(𝑌)
static INLINE void setTypeAndClear_c_OLD(PADR_C_OLD adr, uint8_t Y)
{
	adr->type_OLD = Y;
	memset((uint8_t*)adr + 10, 0, 12);
}
static INLINE void setType_c_OLD(PADR_C_OLD adr, uint32_t Y)
{
	adr->type_OLD = Y;
	memset((uint8_t*)adr + 10, 0, 12);
	toByte32(&adr->type_OLD, Y, 1);
}

static INLINE void setKeyPairAddress_c_OLD(PADR_C_OLD adr, uint32_t i)
{
	//uint8_t* p = (uint8_t*)adr;
	//memcpy(p + 10, (uint8_t*)&i, 4);
	//p[5] = i;
	toByte32(adr->wha.key_pair_Address_OLD, i, 4);
}

static INLINE void setChainAddress_c_OLD(PADR_C_OLD adr, uint32_t i)
{
	/*uint8_t* p = (uint8_t*)adr;
	memcpy(p + 14, (uint8_t*)&i, 4);*/
	//p[6] = i;
	toByte32(adr->wha.chain_Address_OLD, i, 4);
}

static INLINE void setTreeHeight_c_OLD(PADR_C_OLD adr, uint32_t i)
{
	//uint8_t* p = (uint8_t*)adr;
	//memcpy(p + 14, (uint8_t*)&i, 4);
	//p[6] = i;
	toByte32(adr->fta.tree_height_OLD, i, 4);
}

static INLINE void setHashAddress_c_OLD(PADR_C_OLD adr, uint32_t i)
{
	/*uint8_t* p = (uint8_t*)adr;
	memcpy(p + 18, (uint8_t*)&i, 4);*/
	//p[7] = i;
	toByte32(adr->wga.hash_Address_OLD, i, 4);
}

static INLINE void setTreeIndex_c_OLD(PADR_C_OLD adr, uint32_t i)
{
	//uint8_t* p = (uint8_t*)adr;
	//memcpy(p + 18, (uint8_t*)&i, 4);
	//p[7] = i;
	toByte32(adr->fta.tree_index_OLD, i, 4);
}

static INLINE uint32_t getKeyPairAddress_c_OLD(PADR_C_OLD adr)
{
	/*uint8_t* p = (uint8_t*)adr;
	uint32_t value;
	memcpy((uint8_t*)&value, p + 10, 4);*/
	return toInt32(adr->wha.key_pair_Address_OLD, 4);
	
}

static INLINE uint32_t getTreeIndex_c_OLD(PADR_C_OLD adr)
{
	/*uint8_t* p = (uint8_t*)adr;
	uint32_t value;
	memcpy((uint8_t*)&value, p + 18, 4);
	return value;*/
	return toInt32(adr->fta.tree_index_OLD, 4);

}
/*
	B4 layer_Address;
	B12 tree_Address;
	uint32_t type;
*/
static INLINE void toShort_OLD(PADR_C_OLD Adr_c, const PADR_OLD Adr)
{
	uint32_t value = getLayerAddress_OLD(Adr);
	setLayerAddress_c_OLD(Adr_c, value);
	uint64_t value64 = getTreeAddress_OLD(Adr);
	setTreeAddress_c_OLD(Adr_c, value64);
	value = getType_OLD(Adr);
	setType_c_OLD(Adr_c, value);
	memcpy((uint8_t*)Adr_c + 10, (uint8_t*)Adr + 20, 12);
	/*memcpy(Adr_c->tree_Address, temp + 4, 8);
	toByte32(&Adr_c->type, Adr->type, 1);
	memcpy((uint8_t*)Adr_c + 10, (uint8_t*)Adr + 20, 12);*/
}




#endif
