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

// Данные для анализатора
typedef struct AnalyzerData
{
	unsigned short id;			// Идентификатор анализатора
	unsigned short pack_count; 	// Количество непроверенных пакетов	
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
@param pack Ссылка на пакет
*/
void analyze_package(char *pack);

#endif