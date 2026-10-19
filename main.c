#include <stdio.h>

#include "SHA256_device.h"

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include "Common.h"
#include "FIPS_205_Params.h"
#include "FIPS_205_Adr.h"
#include "FIPS_205_Test.h"
#include "AVXconst.h"
#include "FIPS_205_JSon.h"

int main()
{
	print_params();
	int res = 0;

	printf("\nCPU SHA-NI (SHA-1/SHA-256) instructions:  %s\n", check_sha256() ? "Available" : "Not available");
	printf("CPU SHA-512 instructions:  %s\n\n", is_sha512_usable() ? "Available" : "Not available");

	SetAVXConst();
#ifdef _JSON_FILE
	res = TestJSon();
	printf("%s:\tTestJSon - %s\n", smodes[FIPS_205_MODE], res == OK ? "OK" : "ERROR"); 
#endif

	res = test_2_b();
	printf("test_2_b? %s\n", res == 0 ? "OK" : "ERROR");

#if FIPS205_N > 16

	res = test_AVX_sha512();
	printf("test_AVX_sha512 %s\n", res == OK ? "OK" : "ERROR");

	res = test_AVX_sha512_compress4();
	printf("test_AVX_sha512_compress4 %s\n", res == OK ? "OK" : "ERROR");

	
#endif
	res = test_addr();
	printf("test_addr %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	res = test_AVX_sha256();
	printf("test_AVX_sha256 %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	res = test_MGF1_AVX_sha256 ();
	printf("test_MGF1_AVX_sha256 %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

#if FIPS205_N == 16
	res = test_AVX_HMAC();
	printf("test_AVX_HMAC %s\n", res == OK ? "OK" : "ERROR");
#endif

	// test_wots_gensk_and_pk
	res = test_wots_gensk_and_pk();
	printf("test_wots_gensk_and_pk %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	res = test_base_2b();
	printf("test_base_2b %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	//res = test_replace_key();
	//printf("test_replace_key %s\n", res == OK ? "OK" : "ERROR");

	res = test_FIPS205_wots();
	printf("test_FIPS205_wots_gen_sign %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	res = test_FIPS205_xmss();
	printf("test_FIPS205_xmss %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	res = test_FIPS205_fors_and_HT();
	printf("test_FIPS205_fors_and_HT %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	res = test_internal_function();
	printf("test_internal_function %s\n", res == OK ? "OK" : "ERROR");
	printf("---------------------------------------------------------------------------------\n\n");

	return res;
}
