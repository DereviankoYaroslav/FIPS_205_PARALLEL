#if 1
/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#if defined(_MSC_VER)
#  define ALIGN64 __declspec(align(64))
#else
#  define ALIGN64 __attribute__((aligned(64)))
#endif

#include <stddef.h>
#include <stdint.h>

#include "fips202.h"

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

 /*************************************************
 * Name:        load64
 *
 * Description: Load 8 bytes into uint64_t in little-endian order
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns the loaded 64-bit unsigned integer
 **************************************************/
static uint64_t load64(const uint8_t x[8]) {
    unsigned int i;
    uint64_t r = 0;

    for (i = 0; i < 8; i++)
        r |= (uint64_t)x[i] << 8 * i;

    return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
*
* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
*              - uint64_t u: input 64-bit unsigned integer
**************************************************/
static void store64(uint8_t x[8], uint64_t u) {
    unsigned int i;

    for (i = 0; i < 8; i++)
        x[i] = u >> 8 * i;
}

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};

/*************************************************
* Name:        KeccakF1600_StatePermute
*
* Description: The Keccak F1600 Permutation
*
* Arguments:   - uint64_t *state: pointer to input/output Keccak state
**************************************************/
static void KeccakF1600_StatePermute(uint64_t state[25])
{
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    //copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < NROUNDS; round += 2)
    {
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= (uint64_t)KeccakF_RoundConstants[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka, 3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De;
        BCa = ROL(Abe, 1);
        Agi ^= Di;
        BCe = ROL(Agi, 6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu, 8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= (uint64_t)KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    //copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

/*************************************************
* Name:        keccak_init
*
* Description: Initializes the Keccak state.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
static void keccak_init(keccak_state* state)
{
    unsigned int i;
    for (i = 0; i < 25; i++)
        state->s[i] = 0;
    state->pos = 0;
}

/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak; incremental.
*
* Arguments:   - uint64_t *s:      pointer to Keccak state
*              - unsigned int r:   rate in bytes (e.g., 168 for SHAKE128)
*              - unsigned int pos: position in current block to be absorbed
*              - const uint8_t *m: pointer to input to be absorbed into s
*              - size_t mlen:      length of input in bytes
*
* Returns new position pos in current block
**************************************************/
static unsigned int keccak_absorb(uint64_t s[25],
    unsigned int r,
    unsigned int pos,
    const uint8_t* m,
    size_t mlen)
{
    unsigned int i;
    uint8_t t[8] = { 0 };

    if (pos & 7) {
        i = pos & 7;
        while (i < 8 && mlen > 0) {
            t[i++] = *m++;
            mlen--;
            pos++;
        }
        s[(pos - i) / 8] ^= load64(t);
    }

    if (pos && mlen >= r - pos) {
        for (i = 0; i < (r - pos) / 8; i++)
            s[pos / 8 + i] ^= load64(m + 8 * i);
        m += r - pos;
        mlen -= r - pos;
        pos = 0;
        KeccakF1600_StatePermute(s);
    }

    while (mlen >= r) {
        for (i = 0; i < r / 8; i++)
            s[i] ^= load64(m + 8 * i);
        m += r;
        mlen -= r;
        KeccakF1600_StatePermute(s);
    }

    for (i = 0; i < mlen / 8; i++)
        s[pos / 8 + i] ^= load64(m + 8 * i);
    m += 8 * i;
    mlen -= 8 * i;
    pos += 8 * i;

    if (mlen) {
        for (i = 0; i < 8; i++)
            t[i] = 0;
        for (i = 0; i < mlen; i++)
            t[i] = m[i];
        s[pos / 8] ^= load64(t);
        pos += mlen;
    }

    return pos;
}

/*************************************************
* Name:        keccak_finalize
*
* Description: Finalize absorb step.
*
* Arguments:   - uint64_t *s:      pointer to Keccak state
*              - unsigned int r:   rate in bytes (e.g., 168 for SHAKE128)
*              - unsigned int pos: position in current block to be absorbed
*              - uint8_t p:        domain separation byte
**************************************************/
static void keccak_finalize(uint64_t s[25], unsigned int r, unsigned int pos, uint8_t p)
{
    unsigned int i, j;

    i = pos >> 3;
    j = pos & 7;
    s[i] ^= (uint64_t)p << 8 * j;
    s[r / 8 - 1] ^= 1ULL << 63;
}

/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental. Assumes zero bytes of current
*              block have already been squeezed.
*
* Arguments:   - uint8_t *out:   pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to out)
*              - uint64_t *s:    pointer to input/output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks(uint8_t* out,
    size_t nblocks,
    uint64_t s[25],
    unsigned int r)
{
    unsigned int i;

    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
        for (i = 0; i < r / 8; i++)
            store64(out + 8 * i, s[i]);
        out += r;
        nblocks--;
    }
}

/*************************************************
* Name:        keccak_squeeze
*
* Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *out:     pointer to output
*              - size_t outlen:    number of bytes to be squeezed (written to out)
*              - uint64_t *s:      pointer to input/output Keccak state
*              - unsigned int r:   rate in bytes (e.g., 168 for SHAKE128)
*              - unsigned int pos: number of bytes in current block already squeezed
*
* Returns new position pos in current block
**************************************************/
static unsigned int keccak_squeeze(uint8_t* out,
    size_t outlen,
    uint64_t s[25],
    unsigned int r,
    unsigned int pos)
{
    unsigned int i;
    uint8_t t[8];

    if (pos & 7) {
        store64(t, s[pos / 8]);
        i = pos & 7;
        while (i < 8 && outlen > 0) {
            *out++ = t[i++];
            outlen--;
            pos++;
        }
    }

    if (pos && outlen >= r - pos) {
        for (i = 0; i < (r - pos) / 8; i++)
            store64(out + 8 * i, s[pos / 8 + i]);
        out += r - pos;
        outlen -= r - pos;
        pos = 0;
    }

    while (outlen >= r) {
        KeccakF1600_StatePermute(s);
        for (i = 0; i < r / 8; i++)
            store64(out + 8 * i, s[i]);
        out += r;
        outlen -= r;
    }

    if (!outlen)
        return pos;
    else if (!pos)
        KeccakF1600_StatePermute(s);

    for (i = 0; i < outlen / 8; i++)
        store64(out + 8 * i, s[pos / 8 + i]);
    out += 8 * i;
    outlen -= 8 * i;
    pos += 8 * i;

    store64(t, s[pos / 8]);
    for (i = 0; i < outlen; i++)
        out[i] = t[i];
    pos += outlen;
    return pos;
}

/*************************************************
* Name:        shake128_init
*
* Description: Initilizes Keccak state for use as SHAKE128 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized)
*                                     Keccak state
**************************************************/
void shake128_init(keccak_state* state)
{
    keccak_init(state);
}

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output
*                                     Keccak state
*              - const uint8_t *in:   pointer to input to be absorbed into s
*              - size_t inlen:        length of input in bytes
**************************************************/
void shake128_absorb(keccak_state* state, const uint8_t* in, size_t inlen)
{
    state->pos = keccak_absorb(state->s, SHAKE128_RATE, state->pos, in, inlen);
}

/*************************************************
* Name:        shake128_finalize
*
* Description: Finalize absorb step of the SHAKE128 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake128_finalize(keccak_state* state)
{
    keccak_finalize(state->s, SHAKE128_RATE, state->pos, 0x1F);
    state->pos = 0;
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
*              SHAKE128_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes zero bytes of current block
*              have already been squeezed (state->pos = 0).
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t nblocks:  number of blocks to be squeezed
*                                 (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeezeblocks(uint8_t* out, size_t nblocks, keccak_state* state)
{
    keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}

/*************************************************
* Name:        shake128_squeeze
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t outlen :  number of bytes to be squeezed
*                                 (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeeze(uint8_t* out, size_t outlen, keccak_state* state)
{
    state->pos = keccak_squeeze(out, outlen, state->s, SHAKE128_RATE, state->pos);
}

/*************************************************
* Name:        shake256_init
*
* Description: Initilizes Keccak state for use as SHAKE256 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized)
*                                     Keccak state
**************************************************/
void shake256_init(keccak_state* state)
{
    keccak_init(state);
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of the SHAKE256 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output
*                                     Keccak state
*              - const uint8_t *in:   pointer to input to be absorbed into s
*              - size_t inlen:        length of input in bytes
**************************************************/
void shake256_absorb(keccak_state* state, const uint8_t* in, size_t inlen)
{
    state->pos = keccak_absorb(state->s, SHAKE256_RATE, state->pos, in, inlen);
}

/*************************************************
* Name:        shake256_finalize
*
* Description: Finalize absorb step of the SHAKE256 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake256_finalize(keccak_state* state)
{
    keccak_finalize(state->s, SHAKE256_RATE, state->pos, 0x1F);
    state->pos = 0;
}

/*************************************************
* Name:        shake256_squeezeblocks
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
*              SHAKE256_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes zero bytes of current block
*              have already been squeezed (state->pos = 0).
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t nblocks:  number of blocks to be squeezed
*                                 (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeezeblocks(uint8_t* out, size_t nblocks, keccak_state* state)
{
    keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
}

/*************************************************
* Name:        shake256_squeeze
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t outlen :  number of bytes to be squeezed
*                                 (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeeze(uint8_t* out, size_t outlen, keccak_state* state)
{
    state->pos = keccak_squeeze(out, outlen, state->s, SHAKE256_RATE, state->pos);
}

/*************************************************
* Name:        shake128
*
* Description: SHAKE128 XOF with non-incremental API
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake128(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    keccak_state state;

    shake128_init(&state);
    shake128_absorb(&state, in, inlen);
    shake128_finalize(&state);
    shake128_squeeze(out, outlen, &state);
}

// for outlen = 32
void shake128_(uint8_t* out, const uint8_t* in, size_t inlen)
{
    keccak_state state;
    size_t outlen = 32;

    shake128_init(&state);
    shake128_absorb(&state, in, inlen);
    shake128_finalize(&state);
    shake128_squeeze(out, outlen, &state);
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    keccak_state state;

    shake256_init(&state);
    shake256_absorb(&state, in, inlen);
    shake256_finalize(&state);
    shake256_squeeze(out, outlen, &state);
}
#ifdef _PREDCALC
//inlen < BLOCK_SIZE
void short_shake256 (uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    ALIGN64 uint64_t s[25] = { 0 };
    uint8_t* ps = (uint8_t*)s;
    memcpy(ps, in, inlen);
    
    s[inlen / 8] = 0x1F;
    s[16] ^= 1ULL << 63;
    KeccakF1600_StatePermute(s);
    memcpy(out, s, outlen);
}
#endif

//void shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
//{
//    keccak_state state;
//    // size_t outlen = 64;
//
//    shake256_init(&state);
//    shake256_absorb(&state, in, inlen);
//    shake256_finalize(&state);
//    shake256_squeeze(out, outlen, &state);
//}
// for outlen = 32
void shake256_(uint8_t* out, const uint8_t* in, size_t inlen)
{
    keccak_state state;
    size_t outlen = 64;

    shake256_init(&state);
    shake256_absorb(&state, in, inlen);
    shake256_finalize(&state);
    shake256_squeeze(out, outlen, &state);
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (32 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sha3_256(uint8_t h[32], const uint8_t* in, size_t inlen)
{
    uint64_t s[25] = { 0 };
    unsigned int pos;

    pos = keccak_absorb(s, SHA3_256_RATE, 0, in, inlen);
    keccak_finalize(s, SHA3_256_RATE, pos, 0x06);
    keccak_squeeze(h, 32, s, SHA3_256_RATE, 0);
}

void sha3_224(uint8_t h[28], const uint8_t* in, size_t inlen)
{
    uint64_t s[25] = { 0 };
    unsigned int pos;

    pos = keccak_absorb(s, SHA3_224_RATE, 0, in, inlen);
    keccak_finalize(s, SHA3_224_RATE, pos, 0x06);
    keccak_squeeze(h, 28, s, SHA3_224_RATE, 0);
}

void sha3_384(uint8_t h[48], const uint8_t* in, size_t inlen)
{
    uint64_t s[25] = { 0 };
    unsigned int pos;

    pos = keccak_absorb(s, SHA3_384_RATE, 0, in, inlen);
    keccak_finalize(s, SHA3_384_RATE, pos, 0x06);
    keccak_squeeze(h, 48, s, SHA3_384_RATE, 0);
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (64 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sha3_512(uint8_t h[64], const uint8_t* in, size_t inlen)
{
    uint64_t s[25] = { 0 };
    unsigned int pos;

    pos = keccak_absorb(s, SHA3_512_RATE, 0, in, inlen);
    keccak_finalize(s, SHA3_512_RATE, pos, 0x06);
    keccak_squeeze(h, 64, s, SHA3_512_RATE, 0);
}

void sha3_512_init(uint64_t s[25])
{
    //memset(s, 0, 25 * 8);
    size_t i;
    for (i = 0; i < 25; ++i)
        s[i] = 0;
}

/*
uint64_t s[25],
                                  unsigned int r,
                                  unsigned int pos,
                                  const uint8_t *m,
                                  size_t mlen)
*/
unsigned int sha3_512_absorb(
    uint64_t s[25],
    unsigned int r,
    unsigned int pos,
    const uint8_t* m,
    size_t mlen)
{
    pos = keccak_absorb(s, SHA3_512_RATE, pos, m, mlen);
    return pos;
}

void sha3_512_finalize(uint64_t s[25], unsigned int r, unsigned int pos)
{
    keccak_finalize(s, SHA3_512_RATE, pos, 0x06);
}

void sha3_512_squeeze(uint8_t* dest, uint64_t s[25])
{
    keccak_squeeze(dest, 64, s, SHA3_512_RATE, 0);
}

int test_sha3()
{
    // empty message
    uint8_t dest_wait[][64] = {
        {
            0x6B, 0x4E, 0x03, 0x42, 0x36, 0x67, 0xDB, 0xB7,
            0x3B, 0x6E, 0x15, 0x45, 0x4F, 0x0E, 0xB1, 0xAB,
            0xD4, 0x59, 0x7F, 0x9A, 0x1B, 0x07, 0x8E, 0x3F,
            0x5B, 0x5A, 0x6B, 0xC7
        },    // 224
        {
            0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66,
            0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62,
            0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA,
            0x82, 0xD8, 0x0A, 0x4B, 0x80, 0xF8, 0x43, 0x4A
        },      // 256
        {
            0x0C, 0x63, 0xA7, 0x5B, 0x84, 0x5E, 0x4F, 0x7D,
            0x01, 0x10, 0x7D, 0x85, 0x2E, 0x4C, 0x24, 0x85,
            0xC5, 0x1A, 0x50, 0xAA, 0xAA, 0x94, 0xFC, 0x61,
            0x99, 0x5E, 0x71, 0xBB, 0xEE, 0x98, 0x3A, 0x2A,
            0xC3, 0x71, 0x38, 0x31, 0x26, 0x4A, 0xDB, 0x47,
            0xFB, 0x6B, 0xD1, 0xE0, 0x58, 0xD5, 0xF0, 0x04
        },      // 385
        {
            0xA6, 0x9F, 0x73, 0xCC, 0xA2, 0x3A, 0x9A, 0xC5,
            0xC8, 0xB5, 0x67, 0xDC, 0x18, 0x5A, 0x75, 0x6E,
            0x97, 0xC9, 0x82, 0x16, 0x4F, 0xE2, 0x58, 0x59,
            0xE0, 0xD1, 0xDC, 0xC1, 0x47, 0x5C, 0x80, 0xA6,
            0x15, 0xB2, 0x12, 0x3A, 0xF1, 0xF5, 0xF9, 0x4C,
            0x11, 0xE3, 0xE9, 0x40, 0x2C, 0x3A, 0xC5, 0x58,
            0xF5, 0x00, 0x19, 0x9D, 0x95, 0xB6, 0xD3, 0xE3,
            0x01, 0x75, 0x85, 0x86, 0x28, 0x1D, 0xCD, 0x26
        },
        {
             0x7F, 0x9C, 0x2B, 0xA4, 0xE8, 0x8F, 0x82, 0x7D,
             0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3E     // shake128

        },
        {
             0x46, 0xB9, 0xDD, 0x2B, 0x0B, 0xA8, 0x8D, 0x13,    // shake256
             0x23, 0x3B, 0x3F, 0xEB, 0x74, 0x3E, 0xEB, 0x24
        }

    };
    int success[6] = { 0 };
    uint8_t src[1] = { 0 };
    uint8_t dest[64];
    sha3_224(dest, src, 0);
    success[0] = memcmp(dest, dest_wait[0], 28);
    sha3_256(dest, src, 0);
    success[1] = memcmp(dest, dest_wait[1], 32);
    sha3_384(dest, src, 0);
    success[2] = memcmp(dest, dest_wait[2], 48);
    sha3_512(dest, src, 0);
    success[3] = memcmp(dest, dest_wait[3], 64);
    shake128(dest, 16, src, 0);
    success[4] = memcmp(dest, dest_wait[4], 16);
    shake256(dest, 16, src, 0);
    success[5] = memcmp(dest, dest_wait[5], 16);
    return success[0] | success[1] | success[2] | success[3] | success[4] | success[5];

}

//// inlen <= BlockSize
//void short_shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
//{
//    keccak_state state = { 0 };
//    uint64_t* s = state.s;
//    memcpy(s, in, inlen);
//    s[inlen / 8] = 0x1F;
//    s[16] ^= 1ULL << 63;
//    KeccakF1600_StatePermute(s);
//    memcpy(out, s, outlen);
//}

#else

/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#include <stddef.h>
#include <stdint.h>
#include "fips202.h"

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

/*************************************************
* Name:        load64
*
* Description: Load 8 bytes into uint64_t in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns the loaded 64-bit unsigned integer
**************************************************/
static uint64_t load64(const uint8_t x[8]) {
  unsigned int i;
  uint64_t r = 0;

  for(i=0;i<8;i++)
    r |= (uint64_t)x[i] << 8*i;

  return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
*
* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
*              - uint64_t u: input 64-bit unsigned integer
**************************************************/
static void store64(uint8_t x[8], uint64_t u) {
  unsigned int i;

  for(i=0;i<8;i++)
    x[i] = u >> 8*i;
}

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};

/*************************************************
* Name:        KeccakF1600_StatePermute
*
* Description: The Keccak F1600 Permutation
*
* Arguments:   - uint64_t *state: pointer to input/output Keccak state
**************************************************/
static void KeccakF1600_StatePermute(uint64_t state[25])
{
        int round;

        uint64_t Aba, Abe, Abi, Abo, Abu;
        uint64_t Aga, Age, Agi, Ago, Agu;
        uint64_t Aka, Ake, Aki, Ako, Aku;
        uint64_t Ama, Ame, Ami, Amo, Amu;
        uint64_t Asa, Ase, Asi, Aso, Asu;
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        Aba = state[ 0];
        Abe = state[ 1];
        Abi = state[ 2];
        Abo = state[ 3];
        Abu = state[ 4];
        Aga = state[ 5];
        Age = state[ 6];
        Agi = state[ 7];
        Ago = state[ 8];
        Agu = state[ 9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for( round = 0; round < NROUNDS; round += 2 )
        {
            //    prepareTheta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= (uint64_t)KeccakF_RoundConstants[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka,  3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = ROL(Abe,  1);
            Agi ^= Di;
            BCe = ROL(Agi,  6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL(Amu,  8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= (uint64_t)KeccakF_RoundConstants[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        state[ 0] = Aba;
        state[ 1] = Abe;
        state[ 2] = Abi;
        state[ 3] = Abo;
        state[ 4] = Abu;
        state[ 5] = Aga;
        state[ 6] = Age;
        state[ 7] = Agi;
        state[ 8] = Ago;
        state[ 9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;
}

/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - const uint8_t *m: pointer to input to be absorbed into s
*              - size_t mlen: length of input in bytes
*              - uint8_t p: domain-separation byte for different
*                           Keccak-derived functions
**************************************************/
static void keccak_absorb(uint64_t s[25],
                          unsigned int r,
                          const uint8_t *m,
                          size_t mlen,
                          uint8_t p)
{
  size_t i;
  uint8_t t[200] = {0};

  /* Zero state */
  for(i=0;i<25;i++)
    s[i] = 0;

  while(mlen >= r) {
    for(i=0;i<r/8;i++)
      s[i] ^= load64(m + 8*i);

    KeccakF1600_StatePermute(s);
    mlen -= r;
    m += r;
  }

  for(i=0;i<mlen;i++)
    t[i] = m[i];
  t[i] = p;
  t[r-1] |= 128;
  for(i=0;i<r/8;i++)
    s[i] ^= load64(t + 8*i);
}

/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *h: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to h)
*              - uint64_t *s: pointer to input/output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks(uint8_t *out,
                                 size_t nblocks,
                                 uint64_t s[25],
                                 unsigned int r)
{
  unsigned int i;
  while(nblocks > 0) {
    KeccakF1600_StatePermute(s);
    for(i=0;i<r/8;i++)
      store64(out + 8*i, s[i]);
    out += r;
    --nblocks;
  }
}

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF.
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output
*                                     Keccak state
*              - const uint8_t *in:   pointer to input to be absorbed into s
*              - size_t inlen:        length of input in bytes
**************************************************/
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb(state->s, SHAKE128_RATE, in, inlen, 0x1F);
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
*              SHAKE128_RATE bytes each. Modifies the state. Can be called
*              multiple times to keep squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t nblocks:  number of blocks to be squeezed
*                                 (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of the SHAKE256 XOF.
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - keccak_state *s:   pointer to (uninitialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb(state->s, SHAKE256_RATE, in, inlen, 0x1F);
}

/*************************************************
* Name:        shake256_squeezeblocks
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
*              SHAKE256_RATE bytes each. Modifies the state. Can be called
*              multiple times to keep squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t nblocks:  number of blocks to be squeezed
*                                 (written to output)
*              - keccak_State *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
}

/*************************************************
* Name:        shake128
*
* Description: SHAKE128 XOF with non-incremental API
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  unsigned int i;
  size_t nblocks = outlen/SHAKE128_RATE;
  uint8_t t[SHAKE128_RATE];
  keccak_state state;

  shake128_absorb(&state, in, inlen);
  shake128_squeezeblocks(out, nblocks, &state);

  out += nblocks*SHAKE128_RATE;
  outlen -= nblocks*SHAKE128_RATE;

  if(outlen) {
    shake128_squeezeblocks(t, 1, &state);
    for(i=0;i<outlen;i++)
      out[i] = t[i];
  }
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  unsigned int i;
  size_t nblocks = outlen/SHAKE256_RATE;
  uint8_t t[SHAKE256_RATE];
  keccak_state state;

  shake256_absorb(&state, in, inlen);
  shake256_squeezeblocks(out, nblocks, &state);

  out += nblocks*SHAKE256_RATE;
  outlen -= nblocks*SHAKE256_RATE;

  if(outlen) {
    shake256_squeezeblocks(t, 1, &state);
    for(i=0;i<outlen;i++)
      out[i] = t[i];
  }
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (32 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];
  uint8_t t[SHA3_256_RATE];

  keccak_absorb(s, SHA3_256_RATE, in, inlen, 0x06);
  keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

  for(i=0;i<32;i++)
    h[i] = t[i];
}

void sha3_384(uint8_t h[48], const uint8_t* in, size_t inlen)
{
    uint64_t s[25] = { 0 };
    unsigned int pos;

    pos = keccak_absorb(s, SHA3_384_RATE, 0, in, inlen);
    keccak_finalize(s, SHA3_384_RATE, pos, 0x06);
    keccak_squeeze(h, 32, s, SHA3_384_RATE, 0);
}



/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (64 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sha3_512(uint8_t *h, const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];
  uint8_t t[SHA3_512_RATE];

  keccak_absorb(s, SHA3_512_RATE, in, inlen, 0x06);
  keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);

  for(i=0;i<64;i++)
    h[i] = t[i];
}   

#endif

int test_shake256()
{
    uint8_t in[SHA3_256_RATE * 2 + 3];
    size_t i;
    for (i = 0; i < sizeof(in); ++i)
    {
        in[i] = rand() % 256;
    }
    uint8_t out[32];
    shake256(out, 32, in, sizeof(in));
    return 0;
}

#define BLOCK  { \
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;  \
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;  \
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;  \
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;  \
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;  \
        Da = BCu ^ ROL(BCe, 1);             \
        De = BCa ^ ROL(BCi, 1);             \
        Di = BCe ^ ROL(BCo, 1);             \
        Do = BCi ^ ROL(BCu, 1);             \
        Du = BCo ^ ROL(BCa, 1);             \
                     \
        Aba ^= Da;             \
        BCa = Aba;             \
        Age ^= De;             \
        BCe = ROL(Age, 44);             \
        Aki ^= Di;             \
        BCi = ROL(Aki, 43);             \
        Amo ^= Do;             \
        BCo = ROL(Amo, 21);             \
        Asu ^= Du;             \
        BCu = ROL(Asu, 14);             \
        Eba = BCa ^ ((~BCe) & BCi);             \
        Eba ^= (uint64_t)KeccakF_RoundConstants[round];\
        Ebe = BCe ^ ((~BCi) & BCo);             \
        Ebi = BCi ^ ((~BCo) & BCu);             \
        Ebo = BCo ^ ((~BCu) & BCa);             \
        Ebu = BCu ^ ((~BCa) & BCe);             \
             \
        Abo ^= Do;             \
        BCa = ROL(Abo, 28);             \
        Agu ^= Du;             \
        BCe = ROL(Agu, 20);             \
        Aka ^= Da;             \
        BCi = ROL(Aka, 3);             \
        Ame ^= De;             \
        BCo = ROL(Ame, 45);             \
        Asi ^= Di;             \
        BCu = ROL(Asi, 61);             \
        Ega = BCa ^ ((~BCe) & BCi);             \
        Ege = BCe ^ ((~BCi) & BCo);             \
        Egi = BCi ^ ((~BCo) & BCu);             \
        Ego = BCo ^ ((~BCu) & BCa);             \
        Egu = BCu ^ ((~BCa) & BCe);             \
             \
        Abe ^= De;             \
        BCa = ROL(Abe, 1);             \
        Agi ^= Di;             \
        BCe = ROL(Agi, 6);             \
        Ako ^= Do;             \
        BCi = ROL(Ako, 25);             \
        Amu ^= Du;             \
        BCo = ROL(Amu, 8);             \
        Asa ^= Da;             \
        BCu = ROL(Asa, 18);             \
        Eka = BCa ^ ((~BCe) & BCi);             \
        Eke = BCe ^ ((~BCi) & BCo);             \
        Eki = BCi ^ ((~BCo) & BCu);             \
        Eko = BCo ^ ((~BCu) & BCa);             \
        Eku = BCu ^ ((~BCa) & BCe);             \
             \
        Abu ^= Du;             \
        BCa = ROL(Abu, 27);             \
        Aga ^= Da;             \
        BCe = ROL(Aga, 36);             \
        Ake ^= De;             \
        BCi = ROL(Ake, 10);             \
        Ami ^= Di;             \
        BCo = ROL(Ami, 15);             \
        Aso ^= Do;             \
        BCu = ROL(Aso, 56);             \
        Ema = BCa ^ ((~BCe) & BCi);             \
        Eme = BCe ^ ((~BCi) & BCo);             \
        Emi = BCi ^ ((~BCo) & BCu);             \
        Emo = BCo ^ ((~BCu) & BCa);             \
        Emu = BCu ^ ((~BCa) & BCe);             \
             \
        Abi ^= Di;              \
        BCa = ROL(Abi, 62);             \
        Ago ^= Do;             \
        BCe = ROL(Ago, 55);             \
        Aku ^= Du;             \
        BCi = ROL(Aku, 39);             \
        Ama ^= Da;             \
        BCo = ROL(Ama, 41);             \
        Ase ^= De;             \
        BCu = ROL(Ase, 2);             \
        Esa = BCa ^ ((~BCe) & BCi);             \
        Ese = BCe ^ ((~BCi) & BCo);             \
        Esi = BCi ^ ((~BCo) & BCu);             \
        Eso = BCo ^ ((~BCu) & BCa);             \
        Esu = BCu ^ ((~BCa) & BCe);             \
             \
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;             \
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;             \
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;             \
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;             \
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;             \
             \
        Da = BCu ^ ROL(BCe, 1);             \
        De = BCa ^ ROL(BCi, 1);             \
        Di = BCe ^ ROL(BCo, 1);             \
        Do = BCi ^ ROL(BCu, 1);             \
        Du = BCo ^ ROL(BCa, 1);             \
             \
        Eba ^= Da;              \
        BCa = Eba;             \
        Ege ^= De;             \
        BCe = ROL(Ege, 44);             \
        Eki ^= Di;             \
        BCi = ROL(Eki, 43);             \
        Emo ^= Do;             \
        BCo = ROL(Emo, 21);             \
        Esu ^= Du;             \
        BCu = ROL(Esu, 14);             \
        Aba = BCa ^ ((~BCe) & BCi);             \
        Aba ^= (uint64_t)KeccakF_RoundConstants[round + 1];              \
        Abe = BCe ^ ((~BCi) & BCo);               \
        Abi = BCi ^ ((~BCo) & BCu);              \
        Abo = BCo ^ ((~BCu) & BCa);              \
        Abu = BCu ^ ((~BCa) & BCe);              \
              \
        Ebo ^= Do;               \
        BCa = ROL(Ebo, 28);              \
        Egu ^= Du;              \
        BCe = ROL(Egu, 20);              \
        Eka ^= Da;              \
        BCi = ROL(Eka, 3);              \
        Eme ^= De;              \
        BCo = ROL(Eme, 45);              \
        Esi ^= Di;              \
        BCu = ROL(Esi, 61);              \
        Aga = BCa ^ ((~BCe) & BCi);              \
        Age = BCe ^ ((~BCi) & BCo);              \
        Agi = BCi ^ ((~BCo) & BCu);              \
        Ago = BCo ^ ((~BCu) & BCa);              \
        Agu = BCu ^ ((~BCa) & BCe);              \
              \
        Ebe ^= De;              \
        BCa = ROL(Ebe, 1);              \
        Egi ^= Di;              \
        BCe = ROL(Egi, 6);              \
        Eko ^= Do;              \
        BCi = ROL(Eko, 25);              \
        Emu ^= Du;              \
        BCo = ROL(Emu, 8);              \
        Esa ^= Da;              \
        BCu = ROL(Esa, 18);              \
        Aka = BCa ^ ((~BCe) & BCi);              \
        Ake = BCe ^ ((~BCi) & BCo);              \
        Aki = BCi ^ ((~BCo) & BCu);              \
        Ako = BCo ^ ((~BCu) & BCa);              \
        Aku = BCu ^ ((~BCa) & BCe);              \
              \
        Ebu ^= Du;               \
        BCa = ROL(Ebu, 27);              \
        Ega ^= Da;              \
        BCe = ROL(Ega, 36);              \
        Eke ^= De;              \
        BCi = ROL(Eke, 10);              \
        Emi ^= Di;              \
        BCo = ROL(Emi, 15);              \
        Eso ^= Do;              \
        BCu = ROL(Eso, 56);              \
        Ama = BCa ^ ((~BCe) & BCi);              \
        Ame = BCe ^ ((~BCi) & BCo);              \
        Ami = BCi ^ ((~BCo) & BCu);              \
        Amo = BCo ^ ((~BCu) & BCa);              \
        Amu = BCu ^ ((~BCa) & BCe);              \
              \
        Ebi ^= Di;              \
        BCa = ROL(Ebi, 62);              \
        Ego ^= Do;              \
        BCe = ROL(Ego, 55);              \
        Eku ^= Du;              \
        BCi = ROL(Eku, 39);              \
        Ema ^= Da;              \
        BCo = ROL(Ema, 41);              \
        Ese ^= De;              \
        BCu = ROL(Ese, 2);              \
        Asa = BCa ^ ((~BCe) & BCi);              \
        Ase = BCe ^ ((~BCi) & BCo);              \
        Asi = BCi ^ ((~BCo) & BCu);              \
        Aso = BCo ^ ((~BCu) & BCa);              \
        Asu = BCu ^ ((~BCa) & BCe);              \
       }              

int fast_shake256_blocks(uint64_t* state, const uint8_t* in, size_t inlen)
{
    int round;

    uint64_t Aba = 0, Abe = 0, Abi = 0, Abo = 0, Abu = 0;
    uint64_t Aga = 0, Age = 0, Agi = 0, Ago = 0, Agu = 0;
    uint64_t Aka = 0, Ake = 0, Aki = 0, Ako = 0, Aku = 0;
    uint64_t Ama = 0, Ame = 0, Ami = 0, Amo = 0, Amu = 0;
    uint64_t Asa = 0, Ase = 0, Asi = 0, Aso = 0, Asu = 0;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    //copyFromState(A, state)

    //memset(state, 0, 25 * 8);
    size_t blocks = inlen / SHAKE256_RATE, i;
    uint64_t* in64 = (uint64_t*)in;
    //memcpy(state, in, SHAKE256_RATE);
    //in += SHAKE256_RATE;
    //inlen -= SHAKE256_RATE;

    //memset(state + 17, 0, 64);
    //in += SHAKE256_RATE;
    //--inlen;
    
    /*Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];*/
    //uint64_t* uin64;
    for (i = 0; i < blocks  ; ++i)
    {
        //in64 = (uint64_t*)in;
#if 0
        Aba = state[0] ^ in64 [0];
        Abe = state[1] ^ in64[1];
        Abi = state[2] ^ in64[2];
        Abo = state[3] ^ in64[3];
        Abu = state[4] ^ in64[4];
        Aga = state[5] ^ in64[5];
        Age = state[6] ^ in64[6];
        Agi = state[7] ^ in64[7];
        Ago = state[8] ^ in64[8];
        Agu = state[9] ^ in64[9];
        Aka = state[10] ^ in64[10];
        Ake = state[11] ^ in64[11];
        Aki = state[12] ^ in64[12];
        Ako = state[13] ^ in64[13];
        Aku = state[14] ^ in64[14];
        Ama = state[15] ^ in64[15];
        Ame = state[16] ^ in64[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];
#else
        Aba ^= in64[0];
        Abe ^= in64[1];
        Abi ^= in64[2];
        Abo ^= in64[3];
        Abu ^= in64[4];
        Aga ^= in64[5];
        Age ^= in64[6];
        Agi ^= in64[7];
        Ago ^= in64[8];
        Agu ^= in64[9];
        Aka ^= in64[10];
        Ake ^= in64[11];
        Aki ^= in64[12];
        Ako ^= in64[13];
        Aku ^= in64[14];
        Ama ^= in64[15];
        Ame ^= in64[16];
        //Ami = state[17];
        //Amo = state[18];
        //Amu = state[19];
        //Asa = state[20];
        //Ase = state[21];
        //Asi = state[22];
        //Aso = state[23];
        //Asu = state[24];
#endif
                
        for (round = 0; round < NROUNDS; round += 2)
        {
            BLOCK
        }
        /*state[0] = Aba ;
        state[1] = Abe;
        state[2] = Abi;
        state[3] = Abo;
        state[4] = Abu;
        state[5] = Aga;
        state[6] = Age;
        state[7] = Agi;
        state[8] = Ago;
        state[9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku ;
        state[15] = Ama ;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;*/
        in64 += SHAKE256_RATE/8 ;
        inlen-= SHAKE256_RATE;
    }
    // last full block
    /*uin64 = (uint64_t*)(in);
    for (round = 0; round < NROUNDS; round += 2)
    {
        BLOCK
    }
    */
    //uint8_t* state8 = (uint8_t*) state;
    //in = (uint8_t*)in64;
    memset(state, 0, 17 * 8);
    memcpy(state, in64, inlen);

    /*for (i = 0; i < inlen / 8; ++i)
        state[i] ^= in64[i];*/
    state[inlen/8] = 0x1F;
    state[16] ^= 0x8000000000000000L;
    Aba ^= state[0];
    Abe ^= state[1];
    Abi ^= state[2];
    Abo ^= state[3];
    Abu ^= state[4];
    Aga ^= state[5];
    Age ^= state[6];
    Agi ^= state[7];
    Ago ^= state[8];
    Agu ^= state[9];
    Aka ^= state[10];
    Ake ^= state[11];
    Aki ^= state[12];
    Ako ^= state[13];
    Aku ^= state[14];
    Ama ^= state[15];
    Ame ^= state[16];
    /*Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];*/

    for (round = 0; round < NROUNDS; round += 2)
    {
        BLOCK
    }

    state[0] = Aba ;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
        /*state[4] = Abu;
        state[5] = Aga;
        state[6] = Age;
        state[7] = Agi;
        state[8] = Ago;
        state[9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku ;
        state[15] = Ama ;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;


    */

}
