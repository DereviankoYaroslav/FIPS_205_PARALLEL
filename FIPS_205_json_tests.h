#ifndef JSON_H
#define JSON_H

#include "FIPS_205_Params.h"
#ifdef _JSON_FILE
#define	KEYGEN "keyGen"
#define	SIGGEN "sigGen"
#define SIGVER "sigVer"
#define	KEYGEN_TYPE 1
#define	SIGGEN_TYPE 2
#define SIGVER_TYPE 3
#define	ALGORITHM "SLH-DSA"

#define KEYGEN_FILE ".\\TestVectors\\SLH-DSA-keyGen-FIPS205\\internalProjection.json"
#define SIGGEN_FILE ".\\TestVectors\\SLH-DSA-sigGen-FIPS205\\internalProjection.json"
#define SIGVER_FILE ".\\TestVectors\\SLH-DSA-sigVer-FIPS205\\internalProjection.json"

typedef struct _TEST
{
	int tc_id;
	int deferred;
	uint8_t* start, * finish;
}TEST, *PTEST;

typedef struct _JSON_TEST_MESSAGE_LENGTH
{
	int min;
	int max;
	int increment;
}JSON_TEST_MESSAGE_LENGTH, *PJSON_TEST_MESSAGE_LENGTH;

typedef struct _JSON_TEST_GROUP
{
	
	int tg_id;
	int parameter_set; // high - K, low L
	int deterministic; // TRUE, FALSE;
	int tests_count;
	char pre_hash[8];
	TEST tests[16];
	JSON_TEST_MESSAGE_LENGTH jtml;
	uint8_t* start, * finish;
}JSON_TEST_GROUP, * PJSON_TEST_GROUP;

typedef struct _JSON
{
	int vs_id;
	int groups_count;
	char algorithm[8];
	int mode;
	char revision[8];
	JSON_TEST_GROUP groups[30];
}JSON, * PJSON;

SUCCESS test_json();

int ReadGroups(PJSON_TEST_GROUP group, uint8_t* begin_cur);
extern char HashName[][16];
//extern const size_t HashNameCount;
#endif
#endif








