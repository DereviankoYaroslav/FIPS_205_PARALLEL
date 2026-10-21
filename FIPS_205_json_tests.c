#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "FIPS_205_Params.h"
#include "FIPS_205_internal.h"
#include "FIPS_205_json_tests.h"

char smodes[][20] = {
	"SLH-DSA-SHA2-128s",
	"SLH-DSA-SHAKE-128s",
	"SLH-DSA-SHA2-128f",
	"SLH-DSA-SHAKE-128f",

	"SLH-DSA-SHA2-192s",
	"SLH-DSA-SHAKE-192s",
	"SLH-DSA-SHA2-192f",
	"SLH-DSA-SHAKE-192f",

	"SLH-DSA-SHA2-256s",
	"SLH-DSA-SHAKE-256s",
	"SLH-DSA-SHA2-256f",
	"SLH-DSA-SHAKE-256f"
};
size_t smodes_count = sizeof(smodes) / sizeof(smodes[0]);

#ifdef _JSON_FILE
#define MAX_TESTS	((int)(sizeof(((PJSON_TEST_GROUP)0)->tests) / sizeof(TEST)))
static int groups_capacity = 0;
#define DEFAULT_MSG_BITS_MIN	8
#define DEFAULT_MSG_BITS_MAX	(8192 * 8)

int to_digit(
	char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'A' && c <= 'F')
		return  c - 'A' + 10;

	if (c >= 'a' && c <= 'f')
		return  c - 'a' + 10;

	return 0xFF;
}


uint8_t* skip_empty_symbols(
	uint8_t* cur)
{
	if (cur == 0)
		return cur;

	while (*cur == ' ' || *cur == '\t' || *cur == '\r' || *cur == '\n')
		++cur;

	return cur;
}

static uint8_t* find_label(
	uint8_t* cur,
	const uint8_t* end,
	const char* label)
{
	size_t n;

	if (cur == 0 || end == 0 || label == 0)
		return 0;

	n = strlen(label);

	if (n == 0 || (size_t)(end - cur) < n)
		return 0;

	for (; cur + n <= end; ++cur)
	{
		if (*cur == (uint8_t)label[0] && memcmp(cur, label, n) == 0)
			return cur + n;
	}

	return 0;
}

static uint8_t* skip_colon(
	uint8_t* p,
	const uint8_t* end)
{
	if (p == 0)
		return 0;

	p = skip_empty_symbols(p);

	if (p < end && *p == ':')
		++p;

	return skip_empty_symbols(p);
}

uint8_t* read_json_hex(
	uint8_t* dest,
	uint8_t* start,
	const size_t count)
{
	uint8_t *cur = start;
	const size_t size = count;

	if (cur == 0)
		return 0;

	for (size_t i = 0; i < size; ++i)
	{
		int d1 = to_digit(cur[2 * i]);
		int d2 = to_digit(cur[2 * i + 1]);

		if (d1 == 0xFF || d2 == 0xFF)
			return 0;
		dest[i] = (uint8_t)(d1 * 16 + d2);
	}

	return cur + 2 * count + 1;
}

uint8_t* read_json_int(
	int* value_,
	uint8_t * cur,
	const uint8_t * end,
	const char* label)
{
	uint8_t* p;

	if (cur == 0)
		return cur;

	cur = skip_empty_symbols(cur);
	p = find_label(cur, end, label);

	if (p == 0)
		return 0;

	int value = 0, any = 0;
	p = skip_colon(p, end);

	while (p < end && *p >= '0' && *p <= '9')
	{
		value = value * 10 + (*p - '0');
		++p;
		any = 1;
	}

	if (!any)
		return 0;
	*value_ = value;

	return p;
}

uint8_t* read_json_bool(
	int* value_,
	uint8_t* cur,
	const uint8_t* end,
	const char* label)
{
	uint8_t* p;

	if (cur == 0)
		return cur;

	cur = skip_empty_symbols(cur);
	p = find_label(cur, end, label);

	if (p == 0)
		return 0;

	p = skip_colon(p, end);

	if ((size_t)(end - p) >= 4 && strncmp((char*)p, "true", 4) == 0)
	{
		*value_ = 1;
		p += 4;
	}
	else if ((size_t)(end - p) >= 5 && strncmp((char*)p, "false", 5) == 0)
	{
		*value_ = 0;
		p += 5;
	}
	else
		return 0;

	return p;
}

uint8_t* read_json_label(
	uint8_t* cur,
	const uint8_t* end,
	const char* label,
	const uint8_t end_symb)
{
	uint8_t* p;

	if (cur == 0)
		return cur;

	cur = skip_empty_symbols(cur);
	p = find_label(cur, end, label);

	if (p == 0)
		return 0;                       /* this is the line that used to fault */
	while (p < end && *p != end_symb)
		++p;

	return (p < end) ? p : 0;
}

uint8_t *read_json16_char_count(
	int *size,
	uint8_t* cur,
	const uint8_t* end,
	const char* label)
{
	int count;
	uint8_t* start = cur, *finish;

	*size = 0;
	start = read_json_label(start, end, label, '\"');

	if (start == 0)
		return 0;

	finish = start + 1;

	while (finish < end && *finish != '\"')
		++finish;

	if (finish >= end)
		return 0;

	++finish;
	count = (int)(finish - start);
	*size = count - 2;

	return start ;
}

uint8_t* read_json_message_len(
	const PJSON_TEST_MESSAGE_LENGTH p,
	uint8_t* cur,
	const uint8_t* end)
{
	uint8_t* q;

	p->min = DEFAULT_MSG_BITS_MIN;
	p->max = DEFAULT_MSG_BITS_MAX;
	p->increment = 8;

	if (cur == 0)
		return cur;

	q = read_json_label(cur, end, "\"messageLengths\"", '[');

	if (q == 0)
		return cur;

	while (q < end && *q != '{')
		++q;

	if (q >= end)
		return cur;

	++q;
	q = read_json_int(&p->min, q, end, "\"min\"");
	q = read_json_int(&p->max, q, end, "\"max\"");
	q = read_json_int(&p->increment, q, end, "\"increment\"");

	if (q == 0)
	{
		p->min = DEFAULT_MSG_BITS_MIN;
		p->max = DEFAULT_MSG_BITS_MAX;
		p->increment = 8;
		return cur;
	}

	return q;
}

uint8_t* read_json_char(
	uint8_t *value_,
	uint8_t* cur,
	const uint8_t* end,
	const char* label)
{
	uint8_t* p;

	*value_ = 0;

	if (cur == 0)
		return cur;

	cur = skip_empty_symbols(cur);
	p = find_label(cur, end, label);

	if (p == 0)
		return 0;

	while (p < end && *p != '\"')
		++p;

	if (p >= end)
		return 0;

	++p;

	while (p < end && *p != '\"')
		*value_++ = *p++;

	*value_ = 0;

	if (p >= end)
		return 0;

	return p + 1;
}

uint8_t *read_json_title(
	const PJSON json_datas,
	uint8_t *src,
	const uint8_t *end)
{
	uint8_t *cur = src;
	int value;

	if (cur == 0)
		return cur;

	cur = skip_empty_symbols(cur);

	if (*cur == '{')
	{
		char mode[16];
		++cur;
		cur = read_json_int(&value, cur, end, "\"vsId\"");

		if (cur == 0)
			return 0;

		json_datas->vs_id = value;
		cur = read_json_char((uint8_t*)json_datas->algorithm, cur, end, "\"algorithm\"");

		if (cur == 0 || strcmp (json_datas->algorithm,  ALGORITHM))
			return 0;

		mode[0] = 0;
		cur = read_json_char((uint8_t*)mode, cur, end, "\"mode\"");

		if (cur == 0)
			return 0;

		json_datas->mode = -1;

		if (strcmp(mode, KEYGEN) == 0)
		{
			json_datas->mode = KEYGEN_TYPE;
		}
		else
		{
			if (strcmp(mode, SIGGEN) == 0)
				json_datas->mode = SIGGEN_TYPE;
			else if (strcmp(mode, SIGVER) == 0)
				json_datas->mode = SIGVER_TYPE;
		}
		if (json_datas->mode == -1)
			return 0;

		cur = read_json_char((uint8_t*)json_datas->revision, cur, end, "\"revision\"");
		// "FIPS205"
		if (cur == 0 || strcmp(json_datas->revision, "FIPS205"))
			return 0;
	}

	return cur;
}

uint8_t *skip_quot(
	uint8_t* cur)
{
	while (*cur != 0 && *cur != '\"')
	{
		if (*cur == '\\' && cur[1] != 0)
			++cur;

		++cur;
	}
	if (*cur == '\"')
		++cur;

	return cur;
}

int read_groups(
	PJSON_TEST_GROUP group,
	uint8_t* begin_cur)
{
	uint8_t* cur = begin_cur;
	char start_symb = '{', end_symb = '}';
	int count = 0;
	int groups_count = 0;

	while (*cur)
	{
		if (groups_count >= groups_capacity)     /* was unbounded */
			break;

		cur = skip_empty_symbols(cur);

		if (*cur == 0)
			break;

		while (*cur && *cur != start_symb)
			cur++;

		if (*cur == 0)
			break;

		group[groups_count].start = cur;
		count = 1;
		++cur;

		while (*cur != 0)
		{
			if (*cur == '\"')
			{
				++cur;
				cur = skip_quot(cur);
				continue;
			}
			if (*cur == start_symb)
				++count;
			if (*cur == end_symb)
				--count;
			if (*cur == end_symb && count == 0)
				break;
			++cur;
		}
		if (*cur)
		{
			group[groups_count++].finish = cur;
			++cur;
		}
	}

	return groups_count;
}

uint8_t *read_json_file(
	size_t * size,
	const char* fn)
{
	FILE* f;
	long n;
	uint8_t* p;
	size_t got;
	char pathbuf[512];
#ifndef _WIN32
	size_t i, len = strlen(fn);
	if (len + 1 <= sizeof(pathbuf))
	{
		for (i = 0; i <= len; ++i)
			pathbuf[i] = (fn[i] == '\\') ? '/' : fn[i];

		fn = pathbuf;
	}
#else
	(void)pathbuf;
#endif

	*size = 0;
	f = fopen(fn, "rb");

	if (!f)
	{
		printf("JSON: cannot open %s\n", fn);
		return 0;
	}

	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return 0;
	}

	n = ftell(f);
	if (n < 0) {
		fclose(f);
		return 0;
	}

	rewind(f);
	p = (uint8_t*)malloc((size_t)n + 1);

	if (!p) {
		fclose(f);
		return 0;
	}

	got = fread(p, 1, (size_t)n, f);
	fclose(f);
	p[got] = 0;
	*size = got;

	return p;
}

int read_json_tests(
	PTEST tests,
	uint8_t* cur_begin,
	const uint8_t* cur_end)
{
	int count = 0;
	uint8_t* cur;

	cur_begin = read_json_label(cur_begin, cur_end, "\"tests\"", '[');

	if (cur_begin == 0)
		return 0;

	++cur_begin;
	cur = cur_begin;

	while (cur < cur_end && count < MAX_TESTS)
	{
		int depth;

		while (cur < cur_end && *cur != '{')
			++cur;

		if (cur >= cur_end)
			break;

		tests[count].start = cur;
		tests[count].tc_id = 0;
		depth = 0;

		while (cur < cur_end)
		{
			if (*cur == '\"')
			{
				++cur;
				cur = skip_quot(cur);
				continue;
			}
			if (*cur == '{')
				++depth;
			else if (*cur == '}')
			{
				--depth;
				if (depth == 0)
					break;
			}
			++cur;
		}
		if (cur >= cur_end)
			break;

		tests[count].finish = cur;
		read_json_int(&tests[count].tc_id, tests[count].start, tests[count].finish, "\"tcId\"");
		++count;
		++cur;
	}

	return count;
}


SUCCESS read_json_sig_gen(
	uint8_t* sk,
	uint8_t* sig,
	uint8_t* msg,
	int* msg_len,
	uint8_t *prnd,
	int *is_prnd,
	PTEST test,
	const size_t max_msg)
{
	SUCCESS success = ERROR;
	uint8_t* cur = test->start, * cur_end = test->finish;
	uint8_t* p;
	int count;
	*is_prnd = 0;
	*msg_len = 0;

	cur = read_json16_char_count(&count, cur, cur_end, "\"sk\"");

	if (cur && count / 2 == FIPS205_SK_BYTES)
	{
		cur = read_json_hex(sk, cur + 1, count / 2);
		p = read_json16_char_count(&count, test->start, cur_end, "\"additionalRandomness\"");

		if (p != 0 && count / 2 == FIPS205_N)
		{
			if (read_json_hex(prnd, p + 1, count / 2) != 0)
				*is_prnd = 1;
		}

		cur = read_json16_char_count(&count, cur, cur_end, "\"message\"");

		if (cur && count >= 0 && (size_t)(count / 2) * 8 <= max_msg)
		{
			*msg_len = (count / 2) * 8;
			cur = read_json_hex(msg, cur + 1, count / 2);
			cur = read_json16_char_count(&count, cur, cur_end, "\"signature\"");

			if (cur && count / 2 == FIPS205_SIG_BYTES)
			{
				cur = read_json_hex(sig, cur + 1, count / 2);

				if (cur)
					success = OK;
			}
		}
	}

	return success;
}

SUCCESS read_json_group_title(
	PJSON_TEST_GROUP group,
	const int mode)
{
	SUCCESS success = ERROR;
	uint8_t* cur, * end_cur;
	char temp[32];
	int value, j;
	cur = group->start;
	end_cur = group->finish;
	group->parameter_set = -1;
	group->deterministic = 1;
	strcpy(group->pre_hash, "none");

	if (*cur == '{' && *end_cur == '}')
	{
		++cur;
		cur = read_json_int(&value, cur, end_cur, "\"tgId\"");

		if (cur == 0)
			return ERROR;

		group->tg_id = value;
		// "parameterSet"
		cur = read_json_char((uint8_t*)temp, cur, end_cur, "\"parameterSet\"");

		if (cur == 0)
			return ERROR;

		for (j = 0; j < (int)smodes_count; ++j)
		{
			if (strcmp(smodes[j], temp) == 0)
			{
				group->parameter_set = j;
				break;
			}
		}
		if (group->parameter_set < 0)
			return ERROR;

		success = OK;
		temp[0] = 0;

		if (read_json_char((uint8_t*)temp, group->start, end_cur, "\"signatureInterface\"") != 0)
		{
			if (strcmp(temp, "internal") != 0)
				strcpy(group->pre_hash, "skip");
		}

		temp[0] = 0;

		if (read_json_char((uint8_t*)temp, group->start, end_cur, "\"preHash\"") != 0)
		{
			if (strcmp(temp, "none") != 0)
				strcpy(group->pre_hash, "skip");
		}

		if (read_json_bool(&value, group->start, end_cur, "\"deterministic\"") != 0)
			group->deterministic = value;

		if (mode != KEYGEN_TYPE)
			read_json_message_len(&group->jtml, cur, end_cur);
		else
		{
			group->jtml.min = DEFAULT_MSG_BITS_MIN;
			group->jtml.max = DEFAULT_MSG_BITS_MAX;
			group->jtml.increment = 8;
		}

		if (read_json_label(group->start, end_cur, "\"tests\"", '[') == 0)
			success = ERROR;
	}

	return success;
}

static void reset_predcalc()
{
#ifndef SHAKE
	is_predcalc_pk_256 = 0;
#if FIPS205_N != 16
	is_predcalc_pk_512 = 0;
#endif
#endif
}

SUCCESS json_sig_gen(
	PJSON_TEST_GROUP groups,
	const int groups_count)
{
	SUCCESS success = ERROR, overall = ERROR;
	int i, j, executed = 0;
	static uint8_t sk[FIPS205_SK_BYTES], sig[FIPS205_SIG_BYTES], read_sig [FIPS205_SIG_BYTES], rnd [FIPS205_N];
	uint8_t* m;
	int m_len, is_rnd;

	for (i = 0; i < groups_count; ++i)
	{
		if (read_json_group_title(&groups[i], SIGGEN_TYPE) != OK)
			continue;

		if (groups[i].parameter_set != FIPS_205_MODE)
			continue;
		if (strcmp(groups[i].pre_hash, "none") != 0)
			continue;

		m = malloc(groups[i].jtml.max / 8);

		if (m)
		{
			int tests = read_json_tests(groups[i].tests, groups[i].start, groups[i].finish);

			for (j = 0; j < tests; ++j)
			{
				success = read_json_sig_gen(sk, read_sig, m, &m_len, rnd, &is_rnd,
							 &groups[i].tests[j], (size_t)groups[i].jtml.max);

				if (success == OK)
				{
					reset_predcalc();
					memset(sig, 0, FIPS205_SIG_BYTES);

					if (is_rnd)
						FIPS205_sign_internal_new__(sig, m, m_len / 8, sk, rnd);
					else
						FIPS205_sign_internal_new__(sig, m, m_len / 8, sk, sk + 2 * FIPS205_N);

					if (memcmp(read_sig, sig, FIPS205_SIG_BYTES) != 0)
						success = ERROR;

					++executed;
					if (success != OK)
						overall = ERROR;
					else if (executed == 1)
						overall = OK;
				}
				else
					overall = ERROR;

				printf("%s\tSIGGEN\ttest %d %s\n", smodes[FIPS_205_MODE],
				       groups[i].tests[j].tc_id, success == OK ? "OK" : "ERROR");
			}
			free(m);
		}
	}
	return executed ? overall : ERROR;
}

SUCCESS read_json_key_gen(
	uint8_t* sk,
	uint8_t* pk,
	uint8_t* pk_seed,
	uint8_t* sk_seed,
	uint8_t* sk_prf,
	PTEST test)
{
	SUCCESS success = ERROR;
	uint8_t* cur = test->start, * cur_end = test->finish;
	int count;

	cur = read_json16_char_count(&count, cur, cur_end, "\"skSeed\"");

	if (cur && count / 2 == FIPS205_N)
	{
		cur = read_json_hex(sk_seed, cur + 1, count / 2);
		cur = read_json16_char_count(&count, cur, cur_end, "\"skPrf\"");

		if (cur && count / 2 == FIPS205_N)
		{
			cur = read_json_hex(sk_prf, cur + 1, count / 2);
			cur = read_json16_char_count(&count, cur, cur_end, "\"pkSeed\"");

			if (cur && count / 2 == FIPS205_N)
			{
				cur = read_json_hex(pk_seed, cur + 1, count / 2);
				cur = read_json16_char_count(&count, cur, cur_end, "\"sk\"");

				if (cur && count / 2 == FIPS205_SK_BYTES)
				{
					cur = read_json_hex(sk, cur + 1, count / 2);
					cur = read_json16_char_count(&count, cur, cur_end, "\"pk\"");

					if (cur && count / 2 == FIPS205_PK_BYTES)
					{
						cur = read_json_hex(pk, cur + 1, count / 2);

						if (cur)
							success = OK;
					}
				}
			}
		}
	}

	return success;
}

SUCCESS json_key_gen(
	PJSON_TEST_GROUP groups,
	int groups_count)
{
	SUCCESS success = ERROR, overall = ERROR;
	int i, j, executed = 0;
	static uint8_t sk_read[FIPS205_SK_BYTES], pk_read[FIPS205_PK_BYTES];
	uint8_t PKseed[FIPS205_N];
	uint8_t SKseed[FIPS205_N], SKprf[FIPS205_N];

	for (i = 0; i < groups_count; ++i)
	{
		if (read_json_group_title(&groups[i], KEYGEN_TYPE) != OK)
			continue;

		if (groups[i].parameter_set != FIPS_205_MODE)
			continue;

		int tests = read_json_tests(groups[i].tests, groups[i].start, groups[i].finish);

		for (j = 0; j < tests; ++j)
		{
			/* was groups[i].tests - every pass re-read test 0 */
			success = read_json_key_gen(sk_read, pk_read, PKseed, SKseed, SKprf,
						 &groups[i].tests[j]);

			if (success == OK)
			{
				uint8_t PKroot[FIPS205_N];

				reset_predcalc();
				FIPS205_keygen_internal(PKroot, SKseed, SKprf, PKseed);

				/* sk = SK.seed||SK.prf||PK.seed||PK.root, pk = PK.seed||PK.root */
				if (memcmp(sk_read,                     SKseed, FIPS205_N) ||
				    memcmp(sk_read +     FIPS205_N,     SKprf,  FIPS205_N) ||
				    memcmp(sk_read + 2 * FIPS205_N,     PKseed, FIPS205_N) ||
				    memcmp(sk_read + 3 * FIPS205_N,     PKroot, FIPS205_N) ||
				    memcmp(pk_read,                     PKseed, FIPS205_N) ||
				    memcmp(pk_read +     FIPS205_N,     PKroot, FIPS205_N))
					success = ERROR;

				++executed;
				if (success != OK)
					overall = ERROR;
				else if (executed == 1)
					overall = OK;
			}
			else
				overall = ERROR;

			printf("%s\tKEYGEN\ttest %d %s\n", smodes[FIPS_205_MODE],
			       groups[i].tests[j].tc_id, success == OK ? "OK" : "ERROR");
		}
	}

	return executed ? overall : ERROR;
}

SUCCESS read_json_sig_ver(
	uint8_t* pk,
	uint8_t* rnd,
	uint8_t* sig,
	int* sig_len,
	uint8_t* msg,
	int* msg_len,
	int* expected,
	PTEST test,
	const size_t max_msg)
{
	SUCCESS success = ERROR;
	uint8_t* cur = test->start, * cur_end = test->finish;
	uint8_t* p;
	int count;

	*msg_len = 0;
	*sig_len = 0;
	*expected = 0;

	if (read_json_bool(expected, test->start, cur_end, "\"testPassed\"") == 0)
		return ERROR;

	cur = read_json16_char_count(&count, cur, cur_end, "\"pk\"");

	if (cur && count / 2 == FIPS205_PK_BYTES)
	{
		cur = read_json_hex(pk, cur + 1, count / 2);
		p = read_json16_char_count(&count, test->start, cur_end, "\"additionalRandomness\"");

		if (p != 0 && count / 2 == FIPS205_N)
			read_json_hex(rnd, p + 1, count / 2);

		cur = read_json16_char_count(&count, cur, cur_end, "\"message\"");

		if (cur && (size_t)(count / 2) * 8 <= max_msg)
		{
			*msg_len = (count / 2) * 8;
			cur = read_json_hex(msg, cur + 1, count / 2);
			cur = read_json16_char_count(&count, cur, cur_end, "\"signature\"");

			if (cur && count / 2 <= FIPS205_SIG_BYTES + 4)
			{
				*sig_len = count / 2;
				cur = read_json_hex(sig, cur + 1, count / 2);

				if (cur)
					success = OK;
			}
		}
	}

	return success;
}

SUCCESS json_sig_ver(
	PJSON_TEST_GROUP groups,
	int groups_count)
{
	SUCCESS success = ERROR, overall = ERROR;
	int i, j, executed = 0;
	static uint8_t pk[FIPS205_PK_BYTES], sig [FIPS205_SIG_BYTES + 4];
	static uint8_t rnd[FIPS205_N];

	uint8_t* m;
	int m_len, sig_len, expected;

	for (i = 0; i < groups_count; ++i)
	{
		if (read_json_group_title(&groups[i], SIGVER_TYPE) != OK)
			continue;

		if (groups[i].parameter_set != FIPS_205_MODE)
			continue;

		if (strcmp(groups[i].pre_hash, "none") != 0)
			continue;

		m = malloc(groups[i].jtml.max / 8);

		if (m)
		{
			int tests = read_json_tests(groups[i].tests, groups[i].start, groups[i].finish);

			for (j = 0; j < tests; ++j)
			{
				success = read_json_sig_ver(pk, rnd, sig, &sig_len, m, &m_len, &expected,
							 &groups[i].tests[j], (size_t)groups[i].jtml.max);

				if (success == OK)
				{
					SUCCESS res;
					reset_predcalc();
					res = FIPS205_verify_internal_new__(m, m_len / 8, sig,
								      (uint32_t)sig_len, pk);
					success = ((res == OK) == (expected != 0)) ? OK : ERROR;
					++executed;

					if (success != OK)
						overall = ERROR;
					else if (executed == 1)
						overall = OK;
				}
				else
					overall = ERROR;

				printf("%s\tSIGVER\ttest %d %s\n", smodes[FIPS_205_MODE],
				       groups[i].tests[j].tc_id, success == OK ? "OK" : "ERROR");
			}
			free(m);
		}
	}

	return executed ? overall : ERROR;
}

SUCCESS test_json_file(
	const char* fn)
{
	SUCCESS success = ERROR;
	size_t fsize = 0;
	static JSON  datas, * json_datas = &datas;
	PJSON_TEST_GROUP garr;
	uint8_t* p;
	uint8_t* cur;
	uint8_t* cur_max;

	p = read_json_file(&fsize, fn);

	if (p == 0 || fsize == 0)
	{
		free(p);
		return ERROR;
	}

	cur = p;
	cur_max = p + fsize;
	garr = (PJSON_TEST_GROUP)malloc(128 * sizeof(JSON_TEST_GROUP));

	if (garr == 0)
	{
		free(p);
		return ERROR;
	}

	groups_capacity = 128;
	cur = read_json_title(json_datas, cur, cur_max);

	if (cur && cur < cur_max)
	{
		cur = read_json_label(cur, cur_max, "\"testGroups\"", '[');

		if (cur && cur < cur_max)
		{
			int groups_count = read_groups(garr, cur);
			json_datas->groups_count = groups_count;

			if (json_datas->mode == KEYGEN_TYPE)
			{
				success = json_key_gen(garr, groups_count);
			}
			else
			{
				if (json_datas->mode == SIGGEN_TYPE)
				{
					success = json_sig_gen(garr, groups_count);
				}
				else
				{
					if (json_datas->mode == SIGVER_TYPE)
					{
						success = json_sig_ver(garr, groups_count);
					}
				}
			}
		}
	}

	groups_capacity = 0;
	free(garr);
	free(p);

	return success;
}

SUCCESS test_json()
{
	SUCCESS success = OK;

	/* all three files are run even if an earlier one fails */
	if (test_json_file(KEYGEN_FILE) != OK)
		success = ERROR;

	if (test_json_file(SIGGEN_FILE) != OK)
		success = ERROR;

	if (test_json_file(SIGVER_FILE) != OK)
		success = ERROR;

	return success;
}
#endif
