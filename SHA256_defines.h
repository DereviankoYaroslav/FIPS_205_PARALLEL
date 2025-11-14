#ifndef SHA256_defines_h
#define SHA256_defines_h

#define ROR32(word, n) (((word) >> ((n) )) | ((word ) << (32 - ((n) ))))
//
#define SHR32(word, n) ((word) >> n)
//
#define s0(word)    (ROR32(word,7) ^ ROR32(word, 18) ^ SHR32(word, 3))
#define s1(word)    (ROR32(word,17) ^ ROR32(word, 19) ^ SHR32(word, 10))
#define S1(word)    (ROR32(word,6) ^ ROR32(word, 11) ^ ROR32(word, 25))
#define S0(word)    (ROR32(word,2) ^ ROR32(word, 13) ^ ROR32(word, 22))

//#define s0_128(word)    (ROR32(word,7) ^ ROR32(word, 18) ^ SHR32(word, 3))

#define ch(e,f,g)       ((e & f) ^ (~e & g))
#define maj(a, b, c)    ((a & b) ^ (a & c) ^ (b & c))

#define n6     _mm_set1_epi64x (6)      
#define n6_     _mm_set1_epi64x (26)    

#define n11     _mm_set1_epi64x (11)      
#define n11_     _mm_set1_epi64x (21)   

#define n25     _mm_set1_epi64x (25)      
#define n25_     _mm_set1_epi64x (7)   


#define n2     _mm_set1_epi64x (2)      
#define n2_     _mm_set1_epi64x (30)   

#define n13     _mm_set1_epi64x (13)      
#define n13_     _mm_set1_epi64x (19)   

#define n22     _mm_set1_epi64x (22)      
#define n22_     _mm_set1_epi64x (10)   

#define n7     _mm_set1_epi64x (7)      
#define n7_     _mm_set1_epi64x (25)    
#define  n19    _mm_set1_epi64x(19)
#define  n19_    _mm_set1_epi64x(13)

#define  n18    _mm_set1_epi64x(18)
#define  n18_    _mm_set1_epi64x(14)

#define  n17    _mm_set1_epi64x(17)
#define  n17_   _mm_set1_epi64x(15)

#define  n3     _mm_set1_epi64x(3)
#define  n10     _mm_set1_epi64x(10)


#define ROTR_128(x, n, n_)       _mm_or_si128 (_mm_srl_epi32 (x, n) , _mm_sll_epi32 (x, n_))
#define ROTR_256(x, n, n_)       _mm256_or_si256 (_mm256_srl_epi32 (x, n) , _mm256_sll_epi32 (x, n_))
#define s1_128(x) _mm_xor_si128 (_mm_xor_si128 (ROTR_128(x, n17, n17_) , ROTR_128(x, n19, n19_)), _mm_srl_epi32(x, n10))
#define s1_256(x) _mm256_xor_si256 (_mm256_xor_si256 (ROTR_256(x, n17, n17_) , ROTR_256(x, n19, n19_)), _mm256_srl_epi32(x, n10))
#define s0_128(x) _mm_xor_si128 (_mm_xor_si128 (ROTR_128(x, n7, n7_) , ROTR_128(x, n18, n18_)) , _mm_srl_epi32(x, n3))
#define s0_256(x) _mm256_xor_si256 (_mm256_xor_si256 (ROTR_256(x, n7, n7_) , ROTR_256(x, n18, n18_)) , _mm256_srl_epi32(x, n3))
//#define S1(word)    (ROR32(word,6) ^ ROR32(word, 11) ^ ROR32(word, 25))
#define S1_128(x) _mm_xor_si128 (_mm_xor_si128 (ROTR_128(x, n6, n6_) , ROTR_128(x, n11, n11_)) , ROTR_128(x, n25, n25_))
#define S1_256(x) _mm256_xor_si256 (_mm256_xor_si256 (ROTR_256(x, n6, n6_) , ROTR_256(x, n11, n11_)) , ROTR_256(x, n25, n25_))
//#define S0(word)    (ROR32(word,2) ^ ROR32(word, 13) ^ ROR32(word, 22))
#define S0_128(x) _mm_xor_si128 (_mm_xor_si128 (ROTR_128(x, n2, n2_) , ROTR_128(x, n13, n13_)) , ROTR_128(x, n22, n22_))
#define S0_256(x) _mm256_xor_si256 (_mm256_xor_si256 (ROTR_256(x, n2, n2_) , ROTR_256(x, n13, n13_)) , ROTR_256(x, n22, n22_))

//#define ch(e,f,g)       ((e & f) ^ (~e & g))
#define ch_128(e,f,g)     _mm_xor_si128 ( _mm_and_si128 (e, f), _mm_andnot_si128 (e, g))
#define ch_256(e,f,g)     _mm256_xor_si256 ( _mm256_and_si256 (e, f), _mm256_andnot_si256 (e, g))

//#define maj(a, b, c)    ((a & b) ^ (a & c) ^ (b & c))
#define maj_128(a, b, c)    _mm_xor_si128 (   \
    _mm_xor_si128 (                           \
        _mm_and_si128 (a, b), _mm_and_si128 (a, c)), \
        _mm_and_si128 (b, c))

#define maj_256(a, b, c)    _mm256_xor_si256 (   \
    _mm256_xor_si256 (                           \
        _mm256_and_si256 (a, b), _mm256_and_si256 (a, c)), \
        _mm256_and_si256 (b, c))

#endif