/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __ANALYZER_H__
#define __ANALYZER_H__

#include "settings.h"

#include <windows.h>

#define PACKAGE_BUFFER_SIZE 	65535	// Размер буфера пакета

// Заголовок IP-пакета
typedef struct IPHeader
{
	unsigned char	ver_len;	// Версия и длина заголовка
	unsigned char	tos;		// Тип сервиса
	unsigned short	length;		// Длина всего пакета
	unsigned short	id;			// Идентификатор пакета
	unsigned short	offset;		// Флаги и смещения
	unsigned char	ttl;		// Время жизни пакета
	unsigned char	protocol;	// Используемый протокол
	unsigned short	xsum;		// Контрольная сумма
	unsigned long	src;		// IP-адрес отправителя
	unsigned long	dest;		// IP-адрес получателя
} IPHeader;

// Данные для адаптера
typedef struct AdapterData
{
	char *addr; 						// Сетевой адрес
	char buffer[PACKAGE_BUFFER_SIZE]; 	// Для хранения данных пакета
} AdapterData;

// Данные для анализатора
typedef struct AnalyzerData
{
	unsigned short id;			// Идентификатор анализатора
	size_t pack_count; 			// Количество непроверенных пакетов	
	size_t r_cursor;			// Курсор для чтения данных
	size_t w_cursor;			// Курсор для записи данных
	size_t e_cursor;			// Курсор для фиксирования конца текущего пакета
	Bool lock; 					// Флаг, что анализатор занят другим потоком
	HANDLE mutex;				// Мьютекс для корректного изменения данных 
	char *buffer;				// Ссылка на буфер данных
} AnalyzerData;

// Кольцевой список анализаторов
typedef struct AnalyzerList
{
	AnalyzerData data;			// Данные для анализатора
	HANDLE hThread;				// Ссылка на поток
	struct AnalyzerList *next;	// Следующий анализатор
} AnalyzerList;

/**
@brief Запускает процесс проверки пакетов
*/
void run_analyzer();

/**
@brief Добавляет пакет в очередь на анализ
@param data Данные о пакете
*/
void analyze_package(AdapterData *data);

// Получение имени протокола
/**
@brief Добавляет пакет в очередь на анализ
@param protocol Идентификатор протокола
@return Название протокола
*/
char *get_protocol_name(const unsigned char protocol);

#endif