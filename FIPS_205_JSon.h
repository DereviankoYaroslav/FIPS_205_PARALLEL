#ifndef JSON_H
#define JSON_H

#include "FIPS_205_Params.h"
#ifdef _JSON_FILE
#define	KEYGEN	"keyGen"
#define	SIGGEN	"sigGen"
#define SIGVER	"sigVer"
#define	KEYGEN_TYPE	1
#define	SIGGEN_TYPE	2
#define SIGVER_TYPE	3
#define	ALGORITHM	"SLH-DSA"

#define KEYGEN_FILE	".\\TestVectors\\SLH-DSA-keyGen-FIPS205\\internalProjection.json" 
#define SIGGEN_FILE	".\\TestVectors\\SLH-DSA-sigGen-FIPS205\\internalProjection.json" 
#define SIGVER_FILE	".\\TestVectors\\SLH-DSA-sigVer-FIPS205\\internalProjection.json" 

typedef struct _TEST
{
	int tcId;
	int deferred;
	uint8_t* start, * finish;
}TEST, *PTEST;

typedef struct _JSON_TEST_MESSAGE_LENGTH
{
	int min, max, increment;
}JSON_TEST_MESSAGE_LENGTH, *PJSON_TEST_MESSAGE_LENGTH;
typedef struct _JSON_TEST_GROUP
{
	
	int tgId;
	int parameterSet; // high - K, low L
	int deterministic; // TRUE, FALSE;
	int tests_count;
	char preHash[8];
	TEST tests[16];
	JSON_TEST_MESSAGE_LENGTH jtml;
	uint8_t* start, * finish;
}JSON_TEST_GROUP, * PJSON_TEST_GROUP;
typedef struct _JSON
{
	int vsId;
	int groups_count;
	char Algorithm[8];
	int Mode;
	char Revision[8];
	
	JSON_TEST_GROUP groups[30];
}JSON, * PJSON;

SUCCESS TestJSon();
//SUCCESS TestJsonFile(PJSON  json_datas, const char* fn);
int ReadGroups(PJSON_TEST_GROUP group, uint8_t* begin_cur);
extern char HashName[][16];
//extern const size_t HashNameCount;
#endif
#endif








