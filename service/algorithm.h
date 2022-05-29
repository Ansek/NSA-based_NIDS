/******************************************************************************
     * File: algorithm.h
     * Description: Функции для алгоритма отрицательного отбора.
     * Created: 28 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __ALGORITHM_H__
#define __ALGORITHM_H__

#include "filemanager.h"

// Набор переменных для работы с памятью
typedef struct WorkingMemory
{
	uint32_t count;              // Текущее количество элементов
	uint32_t max_count;          // Максимальное количество элементов
	char *memory;                // Указатель на начало памяти
	char *cursor;                // Указатель на свободную память
	HANDLE mutex;                // Мьютекс для разграничения доступа
} WorkingMemory;                 

// Статистика поведения сети
typedef struct NBStats
{
	uint16_t tcp_count;          // Общее количество пакетов TCP
	uint16_t udp_count;          // Общее количество пакетов UDP
	uint16_t icmp_count;         // Общее количество пакетов ICMP
	uint16_t ip_count;           // Общее количество пакетов других протоколов
	uint16_t syn_count;          // Кол-во полуоткрытых соединений TCP 
	uint16_t ask_sa_count;       // Кол-во открытых соединений TCP(ASK,SYN+ASK)
	uint16_t fin_count;          // Кол-во закрытых соединений TCP
	uint16_t rst_count;          // Кол-во сброшенных соединений TCP
	uint16_t al_tcp_port_count;  // Кол-во обращений к разрешенным портам TCP
	uint16_t un_tcp_port_count;  // Кол-во обращений к неразрешенным портам TCP
	uint16_t al_udp_port_count;  // Кол-во обращений к разрешенным портам UDP
	uint16_t un_udp_port_count;  // Кол-во обращений к неразрешенным портам UDP
} NBStats;

/**
@brief Инициализирует параметры алгоритма
*/
void init_algorithm();

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
@brief Возвращает статистику доступную для записи
@return Указатель на статистику
*/
NBStats *get_statistics();

#endif