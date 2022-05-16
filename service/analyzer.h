/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __ANALYZER_H__
#define __ANALYZER_H__

#include "filemanager.h"

#include <windows.h>
#include <time.h>

#define PACKAGE_DATA_SIZE sizeof(void *) * 2  // Размер PackageData без буфера 
#define PACKAGE_BUFFER_SIZE            65535  // Размер буфера пакета

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
	FID fid;							// Идентификатор на файл
	char buffer[PACKAGE_BUFFER_SIZE]; 	// Для хранения данных пакета
} AdapterData;

// Тип данных для перемещения по буферу AnalyzerData
typedef struct PackageData
{
	AdapterData *adapter;		// Ссылка на информацию об адаптере
	struct PackageData *next; 	// Следующий адрес в буфере
	IPHeader header;			// Заголовок пакета
	char data;					// Начало данных пакета
} PackageData;

// Данные для анализатора
typedef struct AnalyzerData
{
	unsigned short id;			// Идентификатор анализатора
	PackageData *r_package;		// Указатель для чтения пакетов
	PackageData *w_package;		// Указатель для записи пакетов
	size_t pack_count; 			// Количество непроверенных пакетов	
	Bool lock; 					// Флаг, что анализатор занят другим потоком
	Bool read;					// Флаг, что выполняется чтение
	HANDLE mutex;				// Мьютекс для ожидания чтения при записи
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

/**
@brief Получение имени протокола
@param protocol Идентификатор протокола
@return Название протокола
*/
char *get_protocol_name(const unsigned char protocol);

#endif