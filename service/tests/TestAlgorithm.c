/******************************************************************************
     * File: TestAlgorithm.c
     * Description: Тестирование функций для работы с алгоритмом 
	                отрицательного отбора
     * Created: 29 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#include "src\\unity.h"
#include "..\\algorithm.h"

extern uint8_t pat_length, pat_shift, affinity;
extern WorkingMemory *pat_db;

// Проверка на добавление шаблона в базу
void test_BreakIntoPatterns_should_Add()
{
	uint8_t i = pat_length;
	const char *p = pat_db->memory;
	const char *buf = "abcdef123456";
	reset_memory(pat_db);
	break_into_patterns(buf, strlen(buf));
	TEST_ASSERT_EQUAL_STRING_LEN("abcde", p + i * 0, i);
	TEST_ASSERT_EQUAL_STRING_LEN("def12", p + i * 1, i);
	TEST_ASSERT_EQUAL_STRING_LEN("12345", p + i * 2, i);
	TEST_ASSERT_EQUAL_STRING_LEN("456  ", p + i * 3, i);
}

// Проверка, что шаблоны при добавлении не повторяются
void test_BreakIntoPatterns_should_NoRepeat()
{
	uint8_t i = pat_length;
	const char *p = pat_db->memory;
	reset_memory(pat_db);
	const char *buf = "12345f123456";
	break_into_patterns(buf, strlen(buf));
	// Шаблон 12345 не должен появиться второй раз
	TEST_ASSERT_EQUAL_STRING_LEN("12345", p + i * 0, i);
	TEST_ASSERT_EQUAL_STRING_LEN("45f12", p + i * 1, i);
	TEST_ASSERT_EQUAL_STRING_LEN("456  ", p + i * 2, i);
}

// Проверка замены шаблона из базы на текущий шаблон
void test_BreakIntoPatterns_should_Replace()
{
	uint8_t i = pat_length;
	const char *p = pat_db->memory;
	reset_memory(pat_db);
	// Полное заполнение базы
	const char *buf = "abcde1234567890";
	break_into_patterns(buf, strlen(buf));
	TEST_ASSERT_EQUAL_STRING_LEN("abcde", p + i * 0, i);
	TEST_ASSERT_EQUAL_STRING_LEN("de123", p + i * 1, i);
	TEST_ASSERT_EQUAL_STRING_LEN("23456", p + i * 2, i);
	TEST_ASSERT_EQUAL_STRING_LEN("56789", p + i * 3, i);	
	TEST_ASSERT_EQUAL_STRING_LEN("890  ", p + i * 4, i);	
	// Должен быть заменен первый наиболее непохожий элемент
	// "abc" совпадает с "abcde", а "23" c "de123", заменяется "23456"
	// "23   " не совпадает с "abcde"
	buf = "abc23";
	break_into_patterns(buf, strlen(buf));
	TEST_ASSERT_EQUAL_STRING_LEN("23   ", p + i * 0, i);
	TEST_ASSERT_EQUAL_STRING_LEN("de123", p + i * 1, i);
	TEST_ASSERT_EQUAL_STRING_LEN("abc23", p + i * 2, i);
	TEST_ASSERT_EQUAL_STRING_LEN("56789", p + i * 3, i);	
	TEST_ASSERT_EQUAL_STRING_LEN("890  ", p + i * 4, i);	
}

// Проверка на корректность расчёта расстояния Хэмминга
void test_HammingDistance_should_CorrectValue()
{
	TEST_ASSERT_EQUAL_UINT8(0, hamming_distance("12345", "12345"));
	TEST_ASSERT_EQUAL_UINT8(1, hamming_distance("62345", "12345"));
	TEST_ASSERT_EQUAL_UINT8(2, hamming_distance("17845", "12345"));
	TEST_ASSERT_EQUAL_UINT8(3, hamming_distance("12890", "12345"));
	TEST_ASSERT_EQUAL_UINT8(4, hamming_distance("67390", "12345"));
	TEST_ASSERT_EQUAL_UINT8(5, hamming_distance("67890", "12345"));
}

void setUp()
{
	pat_length = 5;
	pat_shift = 3;
	affinity = 3;
	pat_db = create_memory(5, pat_length);
}

void tearDown()
{
	free_memory(pat_db);
}

int main()
{
	UNITY_BEGIN();
	RUN_TEST(test_BreakIntoPatterns_should_Add);
	RUN_TEST(test_BreakIntoPatterns_should_NoRepeat);
	RUN_TEST(test_BreakIntoPatterns_should_Replace);
	RUN_TEST(test_HammingDistance_should_CorrectValue);	
	return UNITY_END();
}
