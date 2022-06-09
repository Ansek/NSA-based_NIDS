/******************************************************************************
     * File: algorithm.h
     * Description: Функции для алгоритма отрицательного отбора.
     * Created: 28 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __ALGORITHM_H__
#define __ALGORITHM_H__

#include "filemanager.h"

#define VectorType uint16_t

// Набор переменных для работы с памятью
typedef struct WorkingMemory
{
	uint32_t count;     // Текущее количество элементов
	uint32_t max_count; // Максимальное количество элементов
	uint8_t size;       // Сколько памяти занимает один элемент
	char *memory;       // Указатель на начало памяти
	char *cursor;       // Указатель на свободную память
	HANDLE mutex;       // Мьютекс для разграничения доступа
} WorkingMemory;                 

// Статистика поведения сети
typedef struct NBStats
{   
	VectorType tcp_count;         // Общее количество пакетов TCP
	VectorType udp_count;         // Общее количество пакетов UDP
	VectorType icmp_count;        // Общее количество пакетов ICMP
	VectorType ip_count;          // Общее количество пакетов других протоколов
	VectorType syn_count;         // Кол-во полуоткрытых соединений TCP 
	VectorType ask_sa_count;      // Кол-во открытых соединений TCP(ASK,SYN+ASK)
	VectorType fin_count;         // Кол-во закрытых соединений TCP
	VectorType rst_count;         // Кол-во сброшенных соединений TCP
	VectorType al_tcp_port_count; // Кол-во обращений к разрешенным портам TCP
	VectorType un_tcp_port_count; // Кол-во обращений к неразрешенным портам TCP
	VectorType al_udp_port_count; // Кол-во обращений к разрешенным портам UDP
	VectorType un_udp_port_count; // Кол-во обращений к неразрешенным портам UDP
} NBStats;

// Узел k-мерного дерева
typedef struct KDNode
{
	VectorType mean;   // Среднее значение i-мерности узла
	uint8_t i;       // Мерность данного значения
	Bool is_leaf;    // Флаг, что узел является листом
	struct KDNode *left;  // Указатель на левый узел дерева (<= mean)
	struct KDNode *right; // Указатель на правый узел дерева (> mean)
} KDNode;

// Информация о k-мерном дереве
typedef struct KDTree
{
	uint8_t k;          // Мерность дерева
	uint32_t depth;     // Максимальная глубина (0 - корень)
	VectorType *hrect;  // Гиперпрямоугольник по которому строилось дерево
	KDNode *root;       // Корень дерева
} KDTree;

/**
@brief Инициализирует параметры алгоритма
@brief stud_time Для записи времени обучения
*/
void init_algorithm(TimeData *stud_time);

/**
@brief Освобождение ресурсов
*/
void free_algorithm();

/**
@brief Выделяет новую рабочую память
@param max_count Максимальное количество элементов
@param size Размер одного элемента
@return Указатель на рабочую память
*/
WorkingMemory *create_memory(uint32_t max_count, uint8_t size);

/**
@brief Сбрасывает внутренние указатели в начало
@param wm Указатель на рабочую память
*/
void reset_memory(WorkingMemory *wm);

/**
@brief Освобождение ресурсов рабочей памяти
@param wm Указатель на рабочую память
*/
void free_memory(WorkingMemory *wm);

/**
@brief Освобождение ресурсов рабочей памяти
@param wm Указатель на рабочую память
@param wm Данные которые надо записать
@return TRUE - запись добавлена
*/
Bool add_to_memory(WorkingMemory *wm, const char *data);

/**
@brief Освобождение ресурсов рабочей памяти
@param wm Указатель на рабочую память
@param wm Указатель на место записи
@param wm Данные которые надо записать
@return TRUE - запись добавлена
*/
Bool write_to_memory(WorkingMemory *wm, char *cursor, const char *data);

/**
@brief Разделяет строку на шаблоны нормальной активности
@param buf Буфер данных для разделения
@param len Длина строки
@param len Длина строки
*/
void break_into_patterns(const char *buf, uint32_t len);

/**
@brief Метрика различия строк. Расстояние по Хэммингу
@param s1 Первая строка
@param s2 Вторая строка
@return Чем выше значение, тем сильнее строки отличаются. Max == pat_length
*/
uint8_t hamming_distance(const char *s1, const char *s2);

/**
@brief Записывает в det_db случайную строку,
@brief которая не похожа на строки из pat_db
@return TRUE - удалось сгенерировать детектор
*/
Bool generate_detector();

/**
@brief Получает краевые значения гиперпрямоугольника
@param vectors Набор векторов, расположенных друг за другом
@param len Количество элементов
@param k Мерность пространства
@return Граничные векторы гиперпрямоугольника
*/
VectorType *get_hrect(const VectorType *vectors, uint32_t len, uint8_t k);

/**
@brief Создает правые и левые элементы дерева
@param hrect Массив на стуктуру с границами гиперпрямоугольника
@param i Текущая мерность пространства
@param k Общая мерность пространства
@param depth Какой глубины строить дерево
@return Корневой узел дерева
*/
KDNode *create_kdnode(VectorType *hrect, uint8_t i, uint8_t k, uint32_t depth);

/**
@brief Добавляет один вектор в k-мерное дерево
@param tree Дерево, в которое надо добавить вектор
@param vector Один вектор размерностью k
*/
void add_in_kdtree(KDTree *tree, const VectorType *vector);

/**
@brief Строит k-мерное дерево по заданному гиперпрямоугольнику и заполняет его
@param wm Память, из которой считываются данные
@param depth Какой глубины строить дерево
@return Информацию о дереве и его корень
*/
KDTree *create_kdtree(const WorkingMemory *wm, uint32_t depth);

/**
@brief Заполняет текущее дерево и сбрасывает память
@param tree Дерево которое заполняется
@param wm Память, из которой берутся данные
*/
void move_memory_to_kdtree(KDTree *tree, WorkingMemory *wm);

/**
@brief Заполняет память данными из дерева
@param wm Память, в которую записывают
@param tree Дерево с данными
*/
void save_kdtree_to_memory(WorkingMemory *wm, const KDTree *tree);

/**
@brief Освобождение ресурсов всех узлов
@param node Узел k-мерного дерева
*/
void free_kdnode(KDNode *node);

/**
@brief Сжатие, путем объединених непустых ветвей
@brief и удаление узлов с пустыми листьями
@param tree K-мерное дерево которое надо сжать
*/
void compress_kdtree(KDTree *tree);

/**
@brief Возвращает статистику доступную для записи
@return Указатель на статистику
*/
NBStats *get_statistics();

/**
@brief Запаковыет данные детекторов для сохранения в файл
@param td Время, затраченное на обучение детекторов
@param size Размер сформированных данных
@return Данные для записи
*/
const char *pack_detectors(TimeData *td, size_t *size);

/**
@brief Распаковывает данные о детекторах
@param data Данные для чтения
@param data Для получение данных о времени обучения
*/
void unpack_detectors(const char *data, TimeData *stud_time);

#endif