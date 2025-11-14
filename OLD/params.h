#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H
#include "../FIPS_205_Params.h"

#define SPX_N   FIPS205_N
#if (FIPS_205_MODE - 2) % 4 == 0
#   define FAST 1
#else
#define  FAST   0
#endif

    

#if  FAST == 1
#if SPX_N == 16
//#define SPX_N 16
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 66
/* Number of subtree layer. */
#define SPX_D 22
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 6
#define SPX_FORS_TREES 33
/* Winternitz parameter, */
#define SPX_WOTS_W 16
#elif SPX_N == 24
#define SPX_FULL_HEIGHT 66
/* Number of subtree layer. */
#define SPX_D 22
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 8
#define SPX_FORS_TREES 33
/* Winternitz parameter, */
#define SPX_WOTS_W 16
#else
#define SPX_FULL_HEIGHT 68
/* Number of subtree layer. */
#define SPX_D 17
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 9
#define SPX_FORS_TREES 35
#define SPX_WOTS_W 16
/* Winternitz parameter, */
#endif
#endif
#if  FAST == 0
#if SPX_N == 16
#define SPX_FULL_HEIGHT 63
/* Number of subtree layer. */
#define SPX_D 7
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 12
#define SPX_FORS_TREES 14
/* Winternitz parameter, */
#define SPX_WOTS_W 16
#elif SPX_N == 24
#define SPX_FULL_HEIGHT 63
/* Number of subtree layer. */
#define SPX_D 7
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 17
/* Winternitz parameter, */
#define SPX_WOTS_W 16
#else

    /* Height of the hypertree. */
#define SPX_FULL_HEIGHT 64
/* Number of subtree layer. */
#define SPX_D 8
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 22
/* Winternitz parameter, */
#define SPX_WOTS_W 16
#endif
#endif
#define SPX_WOTS_LOGW 4
#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)
#define SPX_WOTS_LEN2 3
#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
#error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +\
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define SPX_OPTRAND_BYTES 32

#include "sha256_offsets.h"

#endif
