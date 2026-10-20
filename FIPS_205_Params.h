#ifndef FIPS_205_Params_h
#define FIPS_205_Params_h
#include <inttypes.h>
#include <stddef.h> 
typedef	int SUCCESS;
#define		OK		0
#define		ERROR	1
//#define LITTLE_ENDIAN

extern char smodes[][20];
extern size_t smodes_count;

#define	SLH_DSA_SHA2_128s	0
#define	SLH_DSA_SHAKE_128s	1
#define	SLH_DSA_SHA2_128f	2
#define	SLH_DSA_SHAKE_128f	3
#define	SLH_DSA_SHA2_192s	4
#define	SLH_DSA_SHAKE_192s	5
#define	SLH_DSA_SHA2_192f	6
#define	SLH_DSA_SHAKE_192f	7
#define	SLH_DSA_SHA2_256s	8
#define	SLH_DSA_SHAKE_256s	9
#define	SLH_DSA_SHA2_256f	10
#define	SLH_DSA_SHAKE_256f	11

//#define FIPS_205_MODE	SLH_DSA_SHA2_128s // +
//#define FIPS_205_MODE	SLH_DSA_SHAKE_128s
//#define FIPS_205_MODE	SLH_DSA_SHA2_128f // +
//#define FIPS_205_MODE	SLH_DSA_SHAKE_128f

//#define FIPS_205_MODE	SLH_DSA_SHA2_192s // +
//#define FIPS_205_MODE	SLH_DSA_SHAKE_192s
//#define FIPS_205_MODE	SLH_DSA_SHA2_192f // +
//#define FIPS_205_MODE	SLH_DSA_SHAKE_192f

//#define FIPS_205_MODE	SLH_DSA_SHA2_256s // +
//#define FIPS_205_MODE	SLH_DSA_SHAKE_256s
#define FIPS_205_MODE	SLH_DSA_SHA2_256f // +
//#define FIPS_205_MODE	SLH_DSA_SHAKE_256f

#if ((FIPS_205_MODE % 2) == 0)
#define	SHA
#else
#define SHAKE
#endif // FIPS_205_MODE & 2 == 0

#if ((FIPS_205_MODE % 4) < 2)
#define STORE
#else 
#define FAST
#endif 

#if FIPS_205_MODE == SLH_DSA_SHAKE_128s || FIPS_205_MODE == SLH_DSA_SHA2_128s 

#define FIPS205_N			16
#define FIPS205_H			63
#define FIPS205_D			7
#define FIPS205_H_			9
#define FIPS205_A			12
#define	FIPS205_K			14
#define	FIPS205_LOGW		4
#define	FIPS205_M			30

#define	FIPS205_SIG_BYTES	7856
#elif FIPS_205_MODE == SLH_DSA_SHAKE_128f || FIPS_205_MODE == SLH_DSA_SHA2_128f 

#define FIPS205_N			16
#define FIPS205_H			66
#define FIPS205_D			22
#define FIPS205_H_			3
#define FIPS205_A			6
#define	FIPS205_K			33
#define	FIPS205_LOGW		4
#define	FIPS205_M			34

#define	FIPS205_SIG_BYTES	17088
#elif FIPS_205_MODE == SLH_DSA_SHAKE_192s || FIPS_205_MODE == SLH_DSA_SHA2_192s
#define FIPS205_N			24
#define FIPS205_H			63
#define FIPS205_D			7
#define FIPS205_H_			9
#define FIPS205_A			14
#define	FIPS205_K			17
#define	FIPS205_LOGW		4
#define	FIPS205_M			39

#define	FIPS205_SIG_BYTES	16224
#elif FIPS_205_MODE == SLH_DSA_SHAKE_192f || FIPS_205_MODE == SLH_DSA_SHA2_192f

#define FIPS205_N			24
#define FIPS205_H			66
#define FIPS205_D			22
#define FIPS205_H_			3
#define FIPS205_A			8
#define	FIPS205_K			33
#define	FIPS205_LOGW		4
#define	FIPS205_M			42

#define	FIPS205_SIG_BYTES	35664
#elif FIPS_205_MODE == SLH_DSA_SHAKE_256s || FIPS_205_MODE == SLH_DSA_SHA2_256s
#define FIPS205_N			32
#define FIPS205_H			64
#define FIPS205_D			8
#define FIPS205_H_			8
#define FIPS205_A			14
#define	FIPS205_K			22
#define	FIPS205_LOGW		4
#define	FIPS205_M			47

#define	FIPS205_SIG_BYTES	29792
#elif FIPS_205_MODE == SLH_DSA_SHAKE_256f || FIPS_205_MODE == SLH_DSA_SHA2_256f
#define FIPS205_N			32
#define FIPS205_H			68
#define FIPS205_D			17
#define FIPS205_H_			4
#define FIPS205_A			9
#define	FIPS205_K			35
#define	FIPS205_LOGW		4
#define	FIPS205_M			49

#define	FIPS205_SIG_BYTES	49856
#else
#error bad mode
#endif
//#if FIPS_MODE == SLH_DSA_SHAKE_128f || FIPS_MODE == SLH_DSA_SHAKE_128s ||\
//		SLH_DSA_SHAKE_192f || FIPS_MODE == SLH_DSA_SHAKE_192s ||\
//		SLH_DSA_SHAKE_256f || FIPS_MODE == SLH_DSA_SHAKE_256s 
#if FIPS_205_MODE % 2 == 1
#define	SHAKE
#endif

#define	FIPS205_LEN2		3
#define	FIPS205_PK_BYTES	(2 * FIPS205_N)
#define	FIPS205_SK_BYTES	(4 * FIPS205_N)
#define FIPS205_LEN1		((8 * FIPS205_N + FIPS205_LOGW - 1) / FIPS205_LOGW)
#define FIPS205_LEN			(FIPS205_LEN1 + FIPS205_LEN2)
#define	FIPS205_W			16

#ifdef _PREDCALC
void sha256_predcalc_pk(uint32_t* predcalc_pk, const uint8_t* pk);
void sha512_predcalc_pk(uint64_t* predcalc_pk, const uint8_t* pk);

#endif

#ifdef _GETTIME
extern uint64_t fors_skGenTime;
extern uint64_t fors_signTime;
extern uint64_t fors_pkFromSigTime;

extern uint64_t wots_signTime;
extern uint64_t wots_pkFromSigTime;
extern uint64_t wots_pkGenTime;

extern uint64_t xmss_signTime;
extern uint64_t xmss_pkFromSigTime;

extern uint64_t ht_signTime ;
extern uint64_t ht_verifyTime;

extern uint64_t xmss_nodeTime;
extern uint64_t fors_nodeTime;

#endif

#endif
