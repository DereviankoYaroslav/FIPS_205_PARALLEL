#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "FIPS_205_Params.h"
#include "FIPS_205_Adr.h"
SUCCESS test_addr()
{
#ifdef SHA
//#define	LayerAddressOFFSET		0
//#define	TreeAddressOFFSET		1
//#define	TypeAndClearOFFSET		9
//#define	KeyPairAddressOFFSET	10
//#define	ChainAddressOFFSET		14
//#define	TreeHeightOFFSET		14
//#define	HashAddressOFFSET		18
	uint8_t adr[22] = {0};
#else
	uint8_t adr[32] = { 0 };
#endif

	setLayerAddress(adr, 1);
	setTreeAddress(adr, 0x0123456789ABCDEF);
	setType(adr, 6);
	setKeyPairAddress(adr, 7);
	setChainAddress(adr, 8);
	setTreeHeight(adr, 9);
	setHashAddress(adr, 10);
#ifdef SHA
	uint8_t etalon_adr[22] = { 1,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		6,
		0, 0, 0, 7,
		0, 0, 0, 9,
		0, 0, 0, 10
	};
#else
	uint8_t etalon_adr[32] = { 
		0, 0, 0, 1,
		0, 0, 0, 0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0, 0, 0, 6,
		0, 0, 0, 7,
		0, 0, 0, 9,
		0, 0, 0, 10
};

#endif
	SUCCESS res = memcmp (adr, etalon_adr, sizeof (adr));
	uint32_t value1 = getKeyPairAddress(adr);
	uint32_t value2 = getTreeIndex(adr);
	res |= value1 != 7;
	res |= value2 != 10;

	return res;

}
