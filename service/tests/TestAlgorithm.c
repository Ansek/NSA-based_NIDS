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
extern WorkingMemory *det_db;
extern WorkingMemory *stat_db;
extern KDTree *stat_tree;
extern Bool msg_log_enabled;

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

typedef struct MiniStats
{
	VectorType x, y, z; // uint16
} MiniStats;

// Проверка вычислений границ 
void test_GetHRect_should_CorrectValues()
{
	MiniStats stats[5] = 
	{
		1, 9, 40,
		2, 8, 50,
		3, 7, 10,
		4, 6, 20,
		5, 5, 30
	};
	VectorType *hrect = get_hrect((VectorType *)stats, 5, 3);
	VectorType expected[] = {1, 5, 10, 5, 9, 50};
	TEST_ASSERT_EQUAL_UINT16_ARRAY(expected, hrect, 6);
}

// Проверка построения стуктуры дерева
void test_CreateKDNode_CorrectStructure()
{
	MiniStats hrect[2] = 
	{
		0, 6, 8,    // min
		5, 7, 10    // max
	};
	KDNode *node = create_kdnode((VectorType *)hrect, 0, 3, 5);
	// Проверка только крайнего левого поддерева
	TEST_ASSERT_EQUAL_UINT16(2, node->mean);
	TEST_ASSERT_EQUAL_UINT16(6, node->left->mean);
	node = node->left->left;
	TEST_ASSERT_EQUAL_UINT16(9, node->mean);	
	TEST_ASSERT_EQUAL_UINT16(1, node->right->mean);
	TEST_ASSERT_NULL(node->right->left);
	TEST_ASSERT_NULL(node->right->right);
	node = node->left;
	TEST_ASSERT_EQUAL_UINT16(1, node->mean);
	TEST_ASSERT_EQUAL_UINT16(8, node->right->mean);
	TEST_ASSERT_NULL(node->right->left);
	TEST_ASSERT_NULL(node->right->right);
	node = node->left;
	TEST_ASSERT_EQUAL_UINT16(8, node->mean);
	TEST_ASSERT_EQUAL_UINT16(0, node->right->mean);
	TEST_ASSERT_EQUAL_UINT16(0, node->left->mean);
	TEST_ASSERT_NULL(node->right->left);
	TEST_ASSERT_NULL(node->right->right);
	TEST_ASSERT_NULL(node->left->left);
	TEST_ASSERT_NULL(node->left->right);	
}

// Проверка распределения элементов в дереве
void test_CreateKDTree_CorrectValue()
{
	// 2 точки задают внешний куб
	// другие 3 расположены в одном подкубе
	// одна из них расположена между двумя и должна исчезнуть
	MiniStats stats[5] = 
	{
		22,  8, 17,  // должна исчезнуть
		25, 25, 25,  // задает внешний куб
		21,  9, 16,  // задает внутреннее пространство
		 5,  5,  5,  // задает внешний куб
		24,  6, 19   // задает внутреннее пространство
	};
	// Размещение в памяти
	WorkingMemory *wm = create_memory(5, sizeof(MiniStats));
	for (int i = 0; i < 5; i++)
		add_to_memory(wm, (char *)&(stats[i]));
	// Создание дерева
	KDTree *tree = create_kdtree(wm, 5);
	// Запись данных листов в память
	save_kdtree_to_memory(wm, tree);
	// Проверка размера
	TEST_ASSERT_EQUAL_UINT8(4, wm->count);
	// Сравнение
	MiniStats expected[4] = {
		 5,  5,  5,
		21,  6, 16,
		24,  9, 19,
		25, 25, 25
	};
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected, wm->memory, 12);
	free_kdnode(tree->root);
	free(tree);
	free_memory(wm);
}

// Для нескольких тестов со сжатым деревом
KDTree *get_compress_kdtree(WorkingMemory *wm)
{
	MiniStats stats[6] = 
	{
		22,  8, 17,
		25, 25, 25,
		21,  9, 16, // В разных областях,
		21, 11, 16,	// но близкие друг к другу
		 5,  5,  5,
		24,  6, 19
	};
	// Размещение в памяти	
	for (int i = 0; i < 6; i++)
		add_to_memory(wm, (char *)&(stats[i]));
	// Создание дерева
	KDTree *tree = create_kdtree(wm, 5);
	// Сжатие дерева
	compress_kdtree(tree);
	return tree;
}

// Проверка корректности структуры после сжатия
void test_CompressKDTree_CorrectStructure()
{
	WorkingMemory *wm = create_memory(6, sizeof(MiniStats));
	KDTree *tree = get_compress_kdtree(wm);
	// Запись данных листов в память
	save_kdtree_to_memory(wm, tree);
	// Проверка размера
	TEST_ASSERT_EQUAL_UINT8(4, wm->count);
	// Сравнение
	MiniStats expected[4] = {
		 5,  5,  5,
		21,  6, 16,
		24, 11, 19,
		25, 25, 25
	};
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected, wm->memory, 12);
	free_kdnode(tree->root);
	free(tree);
	free_memory(wm);
}

// Проверка сохранности данных при упаковке и распаковке
void test_PackAndUnpackDetectors_DataIntegrity()
{
	// Подготовка данных
	TimeData td;
	td.days = 123;
	td.hours = 4;
	td.minutes = 5;
	MiniStats stats[5] = 
	{
		22,  8, 17,
		25, 25, 25,
		21,  9, 16,
		 5,  5,  5,
		24,  6, 19
	};
	// Размещение в памяти
	for (int i = 0; i < 5; i++)
		add_to_memory(stat_db, (char *)&(stats[i]));
	for (int i = 0; i < 3; i++)
		add_to_memory(det_db, "12345");
	// Упаковка данных
	size_t size;
	const char *data = pack_detectors(&td, &size);
	// Очистка памяти
	ZeroMemory(stat_db->memory, stat_db->max_count * stat_db->size);
	ZeroMemory(det_db->memory, det_db->max_count * det_db->size);
	// Распаковка данных
	TimeData td2;
	unpack_detectors(data, &td2);
	// Сравнение данных
	MiniStats expected[4] = {
		 5,  5,  5,
		21,  6, 16,
		24,  9, 19,
		25, 25, 25
	};
	TEST_ASSERT_EQUAL_MEMORY(&td, &td2, sizeof(TimeData));
	TEST_ASSERT_EQUAL_UINT32(63, size);
	TEST_ASSERT_EQUAL_UINT32(5, stat_db->count);
	TEST_ASSERT_EQUAL_UINT32(3, det_db->count);
	TEST_ASSERT_EQUAL_UINT8(sizeof(MiniStats), stat_db->size);
	TEST_ASSERT_EQUAL_UINT8(pat_length, det_db->size);
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected, stat_db->memory, 12);
	char *p = det_db->memory;
	for (int i = 0; i < 3; i++)
	{
		TEST_ASSERT_EQUAL_STRING_LEN("12345", p, det_db->size);
		p += det_db->size;
	}
}

// Проверка поиска аномалии в данных пакета
void test_CheckPackage_AnomalyDetection()
{
	reset_memory(det_db);
	add_to_memory(det_db, "abcde");
	add_to_memory(det_db, "01234");
	add_to_memory(det_db, "56789");
	PackAnomaly *pa = NULL;
	pa = check_package("06780", 5);
	TEST_ASSERT_NOT_NULL(pa);
	TEST_ASSERT_EQUAL_STRING_LEN("56789", pa->detector, det_db->size);
	pa = check_package("a0c0e", 5);
	TEST_ASSERT_NOT_NULL(pa);
	TEST_ASSERT_EQUAL_STRING_LEN("abcde", pa->detector, det_db->size);
	pa = check_package("01234", 5);
	TEST_ASSERT_NOT_NULL(pa);
	TEST_ASSERT_EQUAL_STRING_LEN("01234", pa->detector, det_db->size);
}

// Проверка поиска аномалии статистики вне пространства дерева
void test_CheckStatistics_AnomalyDetectionOutSpace()
{
	WorkingMemory *wm = create_memory(6, sizeof(MiniStats));
	stat_tree = get_compress_kdtree(wm);
	// Добавляемы данные
	MiniStats stats[8] = 
	{
		 1,  1,   1,
		 1,  15, 15,
		15,   1, 15,
		15,  15,  1,
		15,  15, 30,
		15,  30, 15,
		30,  15, 15,
		30,  30, 30
	};
	// Сравнение данных
	MiniStats expected[2] = {
		 5,  5,  5,
		25, 25, 25
	};
	for (int i = 0; i < 8; i++)
	{
		StatAnomaly *sa = check_statistics((VectorType *)(stats + i));
		TEST_ASSERT_NOT_NULL(sa);
		TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected, sa->hrect, 6);
		if (i < 4)
			TEST_ASSERT_EQUAL_UINT16(1, *sa->value);
		else
			TEST_ASSERT_EQUAL_UINT16(30, *sa->value);
		if (i < 2 || 5 < i)
			TEST_ASSERT_EQUAL_UINT8(0, sa->i);
		else if (i == 2 || 5 == i)
			TEST_ASSERT_EQUAL_UINT8(1, sa->i);
		else
			TEST_ASSERT_EQUAL_UINT8(2, sa->i);		
	}
	free_kdnode(stat_tree->root);
	free(stat_tree);
}

// Проверка поиска аномалии статистики в пространстве дерева
void test_CheckStatistics_AnomalyDetectionInSpace()
{
	WorkingMemory *wm = create_memory(6, sizeof(MiniStats));
	stat_tree = get_compress_kdtree(wm);
	// Добавляемы данные
	MiniStats stats[3] = 
	{
		15,  5, 15,
		22, 17, 17,
		22,  5, 10
	};
	// Сравнение данных
	MiniStats expected_1[2] = {
		 5,  5,  5,
		 5,  5,  5
	};
	MiniStats expected_2[2] = {
		21,  6,  16,
		24,  11, 19
	};
	MiniStats expected_3[2] = {
		25, 25, 25,
		25, 25, 25
	};
	StatAnomaly *sa = check_statistics((VectorType *)(stats));
	TEST_ASSERT_NOT_NULL(sa);
	TEST_ASSERT_NULL(sa->hrect);
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected_1, sa->left_range, 6);
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected_2, sa->right_range, 6);
	TEST_ASSERT_EQUAL_UINT16(15, *sa->value);
	TEST_ASSERT_EQUAL_UINT8(0, sa->i);
	sa = check_statistics((VectorType *)(stats + 1));
	TEST_ASSERT_NOT_NULL(sa);
	TEST_ASSERT_NULL(sa->hrect);
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected_2, sa->left_range, 6);
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected_3, sa->right_range, 6);
	TEST_ASSERT_EQUAL_UINT16(17, *sa->value);
	TEST_ASSERT_EQUAL_UINT8(1, sa->i);
	sa = check_statistics((VectorType *)(stats + 2));
	TEST_ASSERT_NOT_NULL(sa);
	TEST_ASSERT_NULL(sa->hrect);
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected_1, sa->left_range, 6);
	TEST_ASSERT_EQUAL_UINT16_ARRAY(&expected_2, sa->right_range, 6);
	TEST_ASSERT_EQUAL_UINT16(10, *sa->value);
	TEST_ASSERT_EQUAL_UINT8(2, sa->i);
}

void setUp()
{
	pat_length = 5;
	pat_shift = 3;
	affinity = 3;
	msg_log_enabled = 0;
	pat_db = create_memory(5, pat_length);
	det_db = create_memory(5, pat_length);
	stat_db = create_memory(5, sizeof(MiniStats));
}

void tearDown()
{
	free_memory(pat_db);
	free_memory(det_db);
	free_memory(stat_db);
}

int main()
{
	UNITY_BEGIN();
	RUN_TEST(test_BreakIntoPatterns_should_Add);
	RUN_TEST(test_BreakIntoPatterns_should_NoRepeat);
	RUN_TEST(test_BreakIntoPatterns_should_Replace);
	RUN_TEST(test_HammingDistance_should_CorrectValue);
	RUN_TEST(test_GetHRect_should_CorrectValues);
	RUN_TEST(test_CreateKDNode_CorrectStructure);
	RUN_TEST(test_CreateKDTree_CorrectValue);
	RUN_TEST(test_CompressKDTree_CorrectStructure);
	RUN_TEST(test_PackAndUnpackDetectors_DataIntegrity);
	RUN_TEST(test_CheckPackage_AnomalyDetection);
	RUN_TEST(test_CheckStatistics_AnomalyDetectionOutSpace);
	RUN_TEST(test_CheckStatistics_AnomalyDetectionInSpace);
	return UNITY_END();
}
