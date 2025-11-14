#ifndef FIPS_205_ADR_h
#define FIPS_205_ADR_h
#include <string.h>
#include "FIPS_205_Params.h"
#include "AVXconst.h"

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

#endif