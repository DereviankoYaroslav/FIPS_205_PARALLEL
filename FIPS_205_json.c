#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "FIPS_205_Params.h"

//#include "FIPS_205_API.h"
#include "FIPS_205_internal.h"
#include "FIPS_205_JSon.h"

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

int to_digit(char c)
{

	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return  c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return  c - 'a' + 10;
	return 0xFF;
}


uint8_t* SkipEmptySymbols(uint8_t* cur)
{
	while (*cur == ' ' || *cur == '\r' || *cur == '\n')
		++cur;
	return cur;
}

uint8_t* ReadJsonHex(uint8_t* dest, uint8_t* start, size_t count)
{
	uint8_t *cur = start;
	size_t size = count , i ;
	//uint8_t value;
	for (i = 0; i < size; ++i)
	{
		
		
		int d1 = to_digit(cur[2 * i]);
		int d2 = to_digit(cur[2 * i + 1]);
		dest[i] = (uint8_t)(d1 * 16 + d2);
	}
	return cur + 2 * count + 1;

}
uint8_t* ReadJsonInt(int* value_, uint8_t * cur, char* label)
{
	if (cur == 0)
		return cur;
	cur = SkipEmptySymbols(cur);
	uint8_t* p = strstr(cur, label), *pend/* = strchr (p, ',')*/;

	if (p /*&& pend*/)
	{
		p = p + strlen(label);
		int value = 0;
		while (/*(size_t)p < (size_t)pend*/*p >= '0' && *p <= '9')
		{
			//if (*p >= '0' && *p <= '9')
			{
				value = value * 10 + (*p - '0');
			}
			++p;
		}
		*value_ = value;
		//++pend;
		++p;
		
	}
	//return pend;
	return p;
}

uint8_t* ReadJsonBool(int* value_, uint8_t* cur, char* label)
{
	if (cur == 0)
		return cur;
	cur = SkipEmptySymbols(cur);
	uint8_t* p = strstr(cur, label), * pend = strchr(p, ',');
	if (p && pend)
	{
		p = p + strlen(label);
		int value = 0;
		p = SkipEmptySymbols(p);
		if (strncmp(p, "true,", 5) == 0)
		{
			value = 1;
			p += 5;
		}
		else
		{
			if (strncmp(p, "false,", 6) == 0)
			{
				value = 0;
				p += 6;
			}
			else
				p = 0;
		}
		*value_ = value;
		

	}
	return p;
}

uint8_t* ReadJsonLabel(uint8_t* cur, uint8_t* label, uint8_t end_symb)
{
	if (cur == 0)
		return cur;
	cur = SkipEmptySymbols(cur);
	uint8_t* p = strstr(cur, label),
		* pend = p + strlen(label);
	pend = strchr(pend, end_symb);
	return pend;
}

uint8_t *ReadJson16CharCount(int *size, uint8_t* cur, char* label)
{
	
	int count;
	uint8_t* start = cur, *finish;
	start = ReadJsonLabel(start, label, '\"');
	finish = start + 1;
	while (*finish++ != '\"');
	count = (int)(finish - start);

	
	*size = count - 2;
	return start ;
}

uint8_t* ReadJsonMessageLen(PJSON_TEST_MESSAGE_LENGTH p, uint8_t* cur)
{
	cur = ReadJsonLabel(cur, "\"messageLengths\": ", '[');
	while (*cur != '{')
	{
		++cur;
	}
	++cur;
	cur = ReadJsonInt(&p->min, cur, "\"min\": ");
	cur = ReadJsonInt(&p->max, cur, "\"max\": ");
	cur = ReadJsonInt(&p->increment, cur, "\"increment\": " );
	while (*cur != ']')
	{
		++cur;
	}

	while (*cur != ',')
	{
		++cur;
	}

	return cur++;
}

uint8_t* ReadJsonChar(uint8_t *value_, uint8_t* cur, char* label)
{
	if (cur == 0)
		return cur;
	cur = SkipEmptySymbols(cur);
	uint8_t* p = strstr(cur, label), * pend = strchr(p, ',');
	if (p && pend)
	{
		p = p + strlen(label);
		
		while ((size_t)p < (size_t)pend)
		{

			if (*p == '\"')
				break;
			++p;
		}
		++p;
		while ((size_t)p < (size_t)pend)
		{
			if (*p == '\"')
				break;
			*value_++ = *p++;
		}
		*value_ = 0;
		++pend;


	}
	return pend;
}

uint8_t *ReadJsonTitle(PJSON  json_datas, uint8_t *src) {
	//size_t groups_count;
	uint8_t *cur = src;
	int value;
	if (cur == 0)
		return cur;
	cur = SkipEmptySymbols(cur);
	if (*cur == '{')
	{
		char mode[8];
		++cur;

		cur = ReadJsonInt(&value, cur, "\"vsId\": ");
			json_datas->vsId = value;
		cur = ReadJsonChar(json_datas->Algorithm, cur, "\"algorithm\": ");
		if (strcmp (json_datas->Algorithm,  ALGORITHM))
			return 0;
		cur = ReadJsonChar(mode, cur, "\"mode\": ");
		json_datas->Mode = -1;
		if (strcmp(mode, "keyGen") == 0)
		{
			json_datas->Mode = KEYGEN_TYPE;
		}
		else
		{
			if (strcmp(mode, "sigGen") == 0)
				json_datas->Mode = SIGGEN_TYPE;
			else if (strcmp(mode, "sigVer") == 0)
				json_datas->Mode = SIGVER_TYPE;
		}
		if (json_datas->Mode == -1)
			return 0;

		cur = ReadJsonChar(json_datas->Revision, cur, "\"revision\": ");
		// "FIPS205"
		if (strcmp(json_datas->Revision, "FIPS205"))
			return 0;

	}
	return cur;
}

uint8_t *skip_quot(uint8_t* cur)
{
	while (*cur != 0 && *cur != '\"')
		++cur;
	if (*cur == '\"')
		++cur;
	return cur;
}

int ReadGroups(PJSON_TEST_GROUP group, uint8_t* begin_cur)
{
	char* end_cur = 0;
	char* cur = begin_cur;
	
	char start_symb = '{', end_symb = '}';
	size_t count = 0;
	size_t count_cav = 0;

	int groups_count = 0;


	while (*cur)
	{
		cur = SkipEmptySymbols(cur);
		if (*cur == 0)
			break;
		/*if (*cur == '\"')
		{
			++cur;
			cur = skip_quot(cur);
		}*/
		while (*cur && *cur != start_symb)
			cur++;
		if (*cur == 0)
			break;
		group[groups_count].start = cur;

		
		count = 1;
		
		++cur;
		while (*cur != 0)
		{
			cur = SkipEmptySymbols(cur);
			if (*cur == '\"')
			{
				++cur;
				cur = skip_quot(cur);
			}
			if (*cur == 0)
				break;
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

	
	return groups_count ;
}


uint8_t *ReadJsonFile(size_t * size, const char* fn )
{
	SUCCESS success = ERROR;
	uint8_t* p = 0;
	FILE* f = fopen(fn, "rt");
	if (f)
	{
		fseek(f, 0, SEEK_END);
		size_t fsize = ftell(f);
		fseek(f, 0, SEEK_SET);
		p = malloc(fsize);
		if (p)
		{
			success = OK;
			fread(p, 1, fsize, f);
			fclose(f);
			
		}
		*size = fsize;
	}
	return p;
}

int ReadJsonTests(PTEST tests, uint8_t* cur_begin, uint8_t* cur_end)
{
	int count = 0;
	uint8_t* cur;
	cur_begin = ReadJsonLabel(cur_begin, "\"tests\": ", '[');
	//while (*cur_begin != '[')
	++cur_begin;
	while (*cur_end != ']')
		--cur_end;
	cur = cur_begin;
	while ((size_t)cur < (size_t)cur_end)
	{
		
		while (*cur != '{' && (size_t)cur < (size_t)cur_end)
			++cur;
		if ((size_t)cur >= (size_t)cur_end)
			break;
		tests[count].start = cur;
		cur = ReadJsonInt(&tests[count].tcId, cur, "\"tcId\": ");
		int b_quat = 0;
		while (1)
		{
			++cur;
			cur = SkipEmptySymbols(cur);
			if (*cur == 0 || (size_t)cur >= (size_t)cur_end)
				break;
			
			if (*cur == '\"')
			{
				b_quat ^= 1;
			}
			if (*cur == '}' && !b_quat)
			{
				tests[count].finish = cur;
				break;
			}
		}
		if (*cur == 0)
			break;
		++count;
	}

	return count ;
}


SUCCESS ReadJsonSigGen(uint8_t* sk, uint8_t* sig, uint8_t* msg, int* msg_len, uint8_t *prnd, int *is_prnd, PTEST test, size_t max_msg)
{
	SUCCESS success = ERROR;
	uint8_t* cur = test->start, * cur_end = test->finish;
	int count;
	cur = ReadJson16CharCount(&count, cur, "\"sk\": ");
	if (count / 2 == FIPS205_SK_BYTES)
	{
		cur = ReadJsonHex(sk, cur + 1, count / 2);
		// "additionalRandomness": 
		uint8_t *temp_cur;
		*is_prnd = 0;
		//cur = ReadJson16CharCount(&count, cur, "\"additionalRandomness\": ");
		temp_cur = ReadJsonLabel(cur, "\"additionalRandomness\": ", '\"');
		if (temp_cur != 0 && (temp_cur - cur) < 100)
		{
			cur = ReadJson16CharCount(&count, cur, "\"additionalRandomness\": ");
			if (count / 2 == FIPS205_N)
			{
				cur = ReadJsonHex(prnd, cur + 1, count / 2);
				*is_prnd = 1;
			}
		}
		
		cur = ReadJsonInt(msg_len, cur, "\"messageLength\": ");
		if (*msg_len <= max_msg)
		{
			cur = ReadJson16CharCount(&count, cur, "\"message\": ");
			if (count / 2 == *msg_len / 8)
			{
				cur = ReadJsonHex(msg, cur + 1, count / 2);
				cur = ReadJson16CharCount(&count, cur, "\"signature\": ");
				if (count / 2 == FIPS205_SIG_BYTES)
				{
					cur = ReadJsonHex(sig, cur + 1, count / 2);
					success = OK;
				}


			}
		}
	}
	
	return success;
}

SUCCESS ReadJsonGroupTitle(PJSON_TEST_GROUP group, int mode)
{
	SUCCESS success = ERROR;
	uint8_t* cur, * end_cur;
	cur = group->start;
	end_cur = group->finish;
	char temp[24];
	int value, j;

	if (*cur == '{' && *end_cur == '}')
	{
		++cur;
		--end_cur;

		cur = ReadJsonInt(&value, cur, "\"tgId\": ");
		group->tgId = value;
		// "parameterSet"
		cur = ReadJsonChar(temp, cur, "\"parameterSet\": ");
		if (cur && ((size_t)cur < (size_t)end_cur))
		{
			for (j = 0; j < smodes_count; ++j)
			{
				if (strcmp(smodes[j], temp) == 0)
				{
					group->parameterSet = j;
					break;
				}
			}
			if (j != smodes_count)
			{
				success = OK;
				if (mode != KEYGEN_TYPE)
				{
					cur = ReadJsonMessageLen(&group->jtml, cur);

				}

			}
		}
		if (cur && ((size_t)cur < (size_t)end_cur))
		{
			cur = ReadJsonLabel(cur, "\"tests\": ", '[');
			if (cur && ((size_t)cur < (size_t)end_cur))
				success = OK;
		}
	}
	return success;
}

SUCCESS JsonSigGen(PJSON_TEST_GROUP groups, int groups_count)
{
	SUCCESS success = ERROR;
	int i, j;
	//uint8_t* cur;
	static uint8_t sk[FIPS205_SK_BYTES], sig[FIPS205_SIG_BYTES], read_sig [FIPS205_SIG_BYTES], rnd [FIPS205_N];
	uint8_t* m;
	int m_len, /*sig_len, */is_rnd;
	for (i = 0; i < groups_count; ++i)
	{

		/*if (m)
		{*/
		//cur = groups[i].start;
		/*if (i == 13)
			printf("");*/
		success = ReadJsonGroupTitle(&groups[i], SIGGEN_TYPE);
		if (success == OK)
		{
			
			if (groups[i].parameterSet == FIPS_205_MODE)
			{
				success = ERROR;
				size_t max_msg_value = (size_t)groups[i].jtml.max;
				m = malloc(groups[i].jtml.max / 8);
				if (m)
				{
					//success = OK;
					int tests = ReadJsonTests(groups[i].tests, groups[i].start, groups[i].finish);

					for (j = 0; j < tests; ++j)
					{
						success = ReadJsonSigGen(sk, read_sig, m, &m_len, rnd, &is_rnd, &groups[i].tests[j], max_msg_value);

						if (success == OK)
						{
							if (is_rnd)
								FIPS205_sign_internal(sig, m, m_len / 8, sk, rnd);
							else
							{
								FIPS205_sign_internal(sig, m, m_len / 8, sk, sk + 2 * FIPS205_N);
							}
							
								
						}
						//success |= memcmp(read_sig, sig, FIPS205_SIG_BYTES) != 0;
						for (int k = 0; k < FIPS205_SIG_BYTES; ++k)
						{
							if (read_sig[k] != sig[k])
							{
								printf("k = %d read_sig[k] = %x sig[k] = %x\n", k, read_sig[k], sig[k]);
								success = 1;
								break;
							}
						}
						
						printf("%s\tSIGGEN\ttest %d %s\n", smodes[FIPS_205_MODE], groups[i].tests[j].tcId, success == OK ? "OK" : "ERROR");
					}
					free(m);
				}
				
			}
		}
	}
	return success;

	
}




SUCCESS ReadJsonKeyGen(uint8_t* sk, uint8_t* pk, uint8_t* pkSeed, uint8_t* skSeed, uint8_t* skPrf, PTEST test)
{
	SUCCESS success = ERROR;
	uint8_t* cur = test->start, * cur_end = test->finish;
	int count;
	cur = ReadJson16CharCount(&count, cur, "\"skSeed\": ");
	if (count / 2 == FIPS205_N)
	{
		cur = ReadJsonHex(skSeed, cur + 1, count / 2);
		cur = ReadJson16CharCount(&count, cur, "\"skPrf\": ");
		if (count / 2 == FIPS205_N)
		{
			cur = ReadJsonHex(skPrf, cur + 1, count / 2);
			cur = ReadJson16CharCount(&count, cur, "\"pkSeed\": ");
			if (count / 2 == FIPS205_N)
			{
				cur = ReadJsonHex(pkSeed, cur + 1, count / 2);

				cur = ReadJson16CharCount(&count, cur, "\"sk\": ");
				if (count / 2 == FIPS205_SK_BYTES)
				{
					cur = ReadJsonHex(sk, cur + 1, count / 2);

					cur = ReadJson16CharCount(&count, cur, "\"pk\": ");
					if (count / 2 == FIPS205_PK_BYTES)
					{
						cur = ReadJsonHex(pk, cur + 1, count / 2);
						success = OK;
					}
				}
			}
		}
	}
	
	return success;
	
}
SUCCESS JsonKeyGen(PJSON_TEST_GROUP groups, int groups_count)
{
	SUCCESS success = OK;
	int i, j;
	//uint8_t* cur;
	static uint8_t sk[FIPS205_SK_BYTES], pk[FIPS205_PK_BYTES];
	static uint8_t sk_read[FIPS205_SK_BYTES], pk_read[FIPS205_PK_BYTES];
	uint8_t PKseed[FIPS205_N]/*, PKroot[FIPS205_N]*/;
	uint8_t SKseed[FIPS205_N], SKprf[FIPS205_N];


	for (i = 0; i < groups_count; ++i)
	{
		success = ReadJsonGroupTitle(&groups[i], KEYGEN_TYPE);
		if (groups[i].parameterSet == FIPS_205_MODE)
		{
			int tests = ReadJsonTests(groups[i].tests, groups[i].start, groups[i].finish);

			for (j = 0; j < tests; ++j)
			{
				success = ReadJsonKeyGen(sk_read, pk_read, PKseed, SKseed, SKprf, groups[i].tests);

				if (success == OK)
				{
					uint8_t SKseed[FIPS205_N], SKprf[FIPS205_N],
						PKseed[FIPS205_N], PKroot_read[FIPS205_N], PKroot[FIPS205_N];
					memcpy(SKseed, sk_read, FIPS205_N);
					memcpy(SKprf, sk_read + FIPS205_N, FIPS205_N);
					memcpy(PKseed, sk_read + 2 * FIPS205_N, FIPS205_N);
					memcpy(PKroot_read, sk_read + 3 * FIPS205_N, FIPS205_N);
					//FIPS205_keygen_internal(sk, pk, SKseed, SKprf, PKseed);
					FIPS205_keygen_internal(PKroot, SKseed, SKprf, PKseed);
					success = (memcmp(PKroot, PKroot_read, FIPS205_N) != 0);

					printf("%s\tKEYGEN\ttest %d %s\n", smodes[FIPS_205_MODE], groups[i].tests[j].tcId, success == OK ? "OK" : "ERROR");
				}
			}
		}
		//free(m);
	}
	return success;

}





SUCCESS ReadJsonSigVer(
	uint8_t* sk, uint8_t* pk, uint8_t* rnd,
	uint8_t* sig, char* msg, char* err_msg,
	int* msg_len, PTEST test, size_t max_msg)
{
	SUCCESS success = ERROR;
	uint8_t* cur = test->start, * cur_end = test->finish;
	int count;
	cur = ReadJson16CharCount(&count, cur, "\"sk\": ");
	if (count/2 == FIPS205_SK_BYTES)
	{
		cur = ReadJsonHex(sk, cur + 1, count / 2);
		cur = ReadJson16CharCount(&count, cur, "\"pk\": ");
		if (count/2 == FIPS205_PK_BYTES)
		{
			cur = ReadJsonHex(pk, cur + 1, count / 2);
			// "additionalRandomness": 
			cur = ReadJson16CharCount(&count, cur, "\"additionalRandomness\": ");
			if (count/2 == FIPS205_N)
			{
				cur = ReadJsonHex(rnd, cur + 1, count / 2);
				// "messageLength"
				cur = ReadJsonInt(msg_len, cur, "\"messageLength\": ");
				if (*msg_len <= max_msg )
				{
					cur = ReadJson16CharCount(&count, cur, "\"message\": ");
					if (count / 2 == *msg_len / 8)
					{
						cur = ReadJsonHex(msg, cur + 1, count / 2);
						cur = ReadJson16CharCount(&count, cur, "\"signature\": ");
						if (count / 2 == FIPS205_SIG_BYTES)
						{
							cur = ReadJsonHex(sig, cur + 1, count / 2);
							
							success = OK;
						}

					}
				}
			}
		}
	}
	cur = ReadJsonChar(err_msg, cur, "\"reason\": ");
	return success;
}
					
SUCCESS JsonSigVer(PJSON_TEST_GROUP groups, int groups_count)
{
	SUCCESS success = OK;
	int i, j;
	//uint8_t* cur;
	static uint8_t sk[FIPS205_SK_BYTES], pk[FIPS205_PK_BYTES], sig [FIPS205_SIG_BYTES];
	static uint8_t rnd[FIPS205_N];

	static uint8_t additionalRandomness[FIPS205_N];

	uint8_t* m;
	int m_len/*, sig_len*/;
	//uint8_t* m;
	char* err_msgs[] = {
		"valid signature and message - signature should verify successfully",
		"modified signature - SIGFORS modified",
		"invalid signature - signature is too large",
		"modified signature - SIGHT modified",
		"modified signature - R modified",
		"invalid signature - signature is too small",
		"message altered",
		"modified signature - SIGHT modified"
	}, err_msg [256];
	for (i = 0; i < groups_count; ++i)
	{
		
		/*if (m)
		{*/
			//cur = groups[i].start;
		success = ReadJsonGroupTitle(&groups[i], SIGVER_TYPE);
		if (groups[i].parameterSet == FIPS_205_MODE)
		{
			size_t max_msg_value = (size_t)groups[i].jtml.max;
			m = malloc(groups[i].jtml.max/8);
			if (m)
			{
				int tests = ReadJsonTests(groups[i].tests, groups[i].start, groups[i].finish);
				
				for (j = 0; j < tests; ++j)
				{
					success = ReadJsonSigVer(sk, pk, rnd, sig, m, err_msg, &m_len, &groups[i].tests[j], max_msg_value);
					
					if (success == OK)
						success = FIPS205_verify_internal(m, m_len/8, sig, FIPS205_SIG_BYTES, pk);
					if ((success == ERROR) && strcmp(err_msg, err_msgs[0]))
						success = OK;
					printf("%s\tSIGVER\ttest %d %s\n", smodes[FIPS_205_MODE], groups[i].tests[j].tcId, success == OK ? "OK" : "ERROR");
				}
				free(m);
			}
			//free(m);
		}

	}
	return success;
}

SUCCESS TestJsonFile(/*PJSON  json_datas, */const char* fn)
{
	
	SUCCESS success = ERROR;
	size_t fsize;
	static JSON  datas, * json_datas = &datas;
		
	uint8_t*p =  ReadJsonFile(&fsize, fn);
	uint8_t* cur = p, *cur_max = cur + fsize;
	size_t st_cur = (size_t)cur, st_cur_max = st_cur + fsize;
	if (p)
	{

		//uint8_t temp[32];
		//uint8_t* cur = p;
		cur = ReadJsonTitle(json_datas, cur);
		if (cur && (size_t) cur < st_cur_max)
		{
			cur = ReadJsonLabel(cur, "\"testGroups\": ", '[');
			int groups_count;
			if ((size_t)cur < st_cur_max)
			{
				groups_count = ReadGroups(json_datas->groups, cur);
				json_datas->groups_count = groups_count;
				//int i, j, tests_count;

				

				//int value;
				if (json_datas->Mode == KEYGEN_TYPE)
				{
					success = JsonKeyGen(json_datas->groups, groups_count);
		
				}
				else
				{
					if (json_datas->Mode == SIGGEN_TYPE)
					{
						success = JsonSigGen(json_datas->groups, groups_count);

					}
					else
					{
						if (json_datas->Mode == SIGVER_TYPE)
						{
							
							success = JsonSigVer(json_datas->groups, groups_count);
							
						}
						
					}


				}

			}
			
				
		

		}
		free(p);
		
	}
		
	//success = OK;
	
	return success;
}


SUCCESS TestJSon()
{

	
	SUCCESS success = OK;

	success = TestJsonFile(KEYGEN_FILE);



	if (success == OK)
	{
		success = TestJsonFile(SIGGEN_FILE);

	}


	if (success == OK)
	{
		success = TestJsonFile(SIGVER_FILE);

	}


	return success;

}

#endif
