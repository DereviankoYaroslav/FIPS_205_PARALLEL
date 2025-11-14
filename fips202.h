#if 1
#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_224_RATE 144
#define SHA3_256_RATE 136
#define SHA3_384_RATE 104
#define SHA3_512_RATE 72

#define FIPS202_NAMESPACE(s) pqcrystals_fips202_ref##s

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

#define shake128_init FIPS202_NAMESPACE(_shake128_init)
void shake128_init(keccak_state* state);
#define shake128_absorb FIPS202_NAMESPACE(_shake128_absorb)
void shake128_absorb(keccak_state* state, const uint8_t* in, size_t inlen);
#define shake128_finalize FIPS202_NAMESPACE(_shake128_finalize)
void shake128_finalize(keccak_state* state);
#define shake128_squeezeblocks FIPS202_NAMESPACE(_shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t* out, size_t nblocks, keccak_state* state);
#define shake128_squeeze FIPS202_NAMESPACE(_shake128_squeeze)
void shake128_squeeze(uint8_t* out, size_t outlen, keccak_state* state);

#define shake256_init FIPS202_NAMESPACE(_shake256_init)
void shake256_init(keccak_state* state);
#define shake256_absorb FIPS202_NAMESPACE(_shake256_absorb)
void shake256_absorb(keccak_state* state, const uint8_t* in, size_t inlen);
#define shake256_finalize FIPS202_NAMESPACE(_shake256_finalize)
void shake256_finalize(keccak_state* state);
#define shake256_squeezeblocks FIPS202_NAMESPACE(_shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t* out, size_t nblocks, keccak_state* state);
#define shake256_squeeze FIPS202_NAMESPACE(_shake256_squeeze)
void shake256_squeeze(uint8_t* out, size_t outlen, keccak_state* state);

#define shake128 FIPS202_NAMESPACE(_shake128)
void shake128(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);
#define shake256 FIPS202_NAMESPACE(_shake256)
void shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(_sha3_256)
void sha3_256(uint8_t h[32], const uint8_t* in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(_sha3_512)
void sha3_512(uint8_t h[64], const uint8_t* in, size_t inlen);
void sha3_384(uint8_t h[48], const uint8_t* in, size_t inlen);
void sha3_224(uint8_t h[28], const uint8_t* in, size_t inlen);

void sha3_512_init(uint64_t s[25]);
unsigned int sha3_512_absorb(
    uint64_t s[25],
    unsigned int r,
    unsigned int pos,
    const uint8_t* m,
    size_t mlen);
void sha3_512_finalize(uint64_t s[25], unsigned int r, unsigned int pos);
void sha3_512_squeeze(uint8_t* dest, uint64_t s[25]);

void shake128_(uint8_t* out, const uint8_t* in, size_t inlen);
void shake256_(uint8_t* out, const uint8_t* in, size_t inlen);

void short_shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);
#ifdef _PREDCALC
int fast_shake256_blocks(uint64_t* state, const uint8_t* in, size_t inlen);
#endif

//void KeccakF1600_StatePermute(uint64_t state[25]);


#endif

#else
#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define FIPS202_NAMESPACE(s) pqcrystals_fips202_ref##s

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

#define SHA3_256_RATE 136
#define SHA3_384_RATE 104
#define SHA3_512_RATE 72

typedef struct {
  uint64_t s[25];
} keccak_state;

#define shake128_absorb FIPS202_NAMESPACE(_shake128_absorb)
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_squeezeblocks FIPS202_NAMESPACE(_shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

#define shake256_absorb FIPS202_NAMESPACE(_shake256_absorb)
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_squeezeblocks FIPS202_NAMESPACE(_shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);
#define shake128 FIPS202_NAMESPACE(_shake128)
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define shake256 FIPS202_NAMESPACE(_shake256)
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(_sha3_256)
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(_sha3_512)
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

#endif
#endif

