#ifndef FIPS_205_Test_h
#define FIPS_205_Test_h
int test_AVX_const();
int test_fun_128();
int test_calc_w();
int test_sha512();
test_sha512_with_predcalc();
//int test_AVX_sha256_compress4();
int test_AVX_sha256();
int test_MGF1_AVX_sha256();
int test_HMAC512();
int test_AVX_HMAC();
int test_AVX_sha512_WITH_PREDCALC4();
int test_AVX_sha256_WITH_PREDCALC4();
int test_AVX_sha256_WITH_PREDCALC8();
//////////////////////////////////////
//int test_fun_256();
int test_AVX_sha512();
int test_AVX_HMAC512();
int test_AVX_MGF1_sha512();
int test_AVX_sha512_compress4();
/////////////////////////////////
int test_AVX_F();
int test_AVX_HASH();
int test_AVX_HMsg();
int test_Tl();
int test_AVX_PREDCALC_W_sha();
int test_AVX_PRFmsg();
int test_wots_gensk_and_pk();
int test_FIPS205_AVX_wots_gen_pk();
int test_base_2b();
int test_replace_key();
int test_wots_chain();
//int test_FIPS205_wots_gen_sign();
int test_FIPS205_wots();
int test_FIPS205_xmss();
//int test_FIPS205_HT();
//int test_FIPS205_fors();
int test_FIPS205_fors_and_HT();


int test_2_b();


#endif

