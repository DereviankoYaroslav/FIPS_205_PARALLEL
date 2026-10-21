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

int to_digit(
	char c);

uint8_t* skip_empty_symbols(
	uint8_t* cur);

static uint8_t* find_label(
	uint8_t* cur,
	const uint8_t* end,
	const char* label);

static uint8_t* skip_colon(
	uint8_t* p,
	const uint8_t* end);

uint8_t* read_json_hex(
	uint8_t* dest,
	uint8_t* start,
	const size_t count);

uint8_t* read_json_int(
	int* value_,
	uint8_t * cur,
	const uint8_t * end,
	const char* label);

uint8_t* read_json_bool(
	int* value_,
	uint8_t* cur,
	const uint8_t* end,
	const char* label);

uint8_t* read_json_label(
	uint8_t* cur,
	const uint8_t* end,
	const char* label,
	const uint8_t end_symb);

uint8_t *read_json16_char_count(
	int *size,
	uint8_t* cur,
	const uint8_t* end,
	const char* label);

uint8_t* read_json_message_len(
	const PJSON_TEST_MESSAGE_LENGTH p,
	uint8_t* cur,
	const uint8_t* end);

uint8_t* read_json_char(
	uint8_t *value_,
	uint8_t* cur,
	const uint8_t* end,
	const char* label);

uint8_t *read_json_title(
	const PJSON json_datas,
	uint8_t *src,
	const uint8_t *end);

uint8_t *skip_quot(
	uint8_t* cur);

int read_groups(
	PJSON_TEST_GROUP group,
	uint8_t* begin_cur);

uint8_t *read_json_file(
	size_t * size,
	const char* fn);

int read_json_tests(
	PTEST tests,
	uint8_t* cur_begin,
	const uint8_t* cur_end);

SUCCESS read_json_sig_gen(
	uint8_t* sk,
	uint8_t* sig,
	uint8_t* msg,
	int* msg_len,
	uint8_t *prnd,
	int *is_prnd,
	PTEST test,
	const size_t max_msg);

SUCCESS read_json_group_title(
	PJSON_TEST_GROUP group,
	const int mode);

static void reset_predcalc();

SUCCESS json_sig_gen(
	PJSON_TEST_GROUP groups,
	const int groups_count);

SUCCESS read_json_key_gen(
	uint8_t* sk,
	uint8_t* pk,
	uint8_t* pk_seed,
	uint8_t* sk_seed,
	uint8_t* sk_prf,
	PTEST test);

SUCCESS json_key_gen(
	PJSON_TEST_GROUP groups,
	int groups_count);

SUCCESS read_json_sig_ver(
	uint8_t* pk,
	uint8_t* rnd,
	uint8_t* sig,
	int* sig_len,
	uint8_t* msg,
	int* msg_len,
	int* expected,
	PTEST test,
	const size_t max_msg);

SUCCESS json_sig_ver(
	PJSON_TEST_GROUP groups,
	int groups_count);

SUCCESS test_json_file(
	const char* fn);

SUCCESS test_json();

extern char HashName[][16];
//extern const size_t HashNameCount;
#endif
#endif








