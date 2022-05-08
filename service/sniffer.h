/******************************************************************************
     * File: sniffer.h
     * Description: Анализатор сетевого трафика.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdio.h>
#include <winsock2.h>

#include "analyzer.h"

#define SIO_RCVALL 0x98000001 		// Для приёма всех пакетов из сети
#define HOST_NAME_SIZE 		128		// Размер имени хоста

// Данные для адаптера
typedef struct AdapterData
{
	char *addr; 						// Сетевой адрес
	char buffer[PACKAGE_BUFFER_SIZE]; 	// Для хранения данных пакета
} AdapterData;

// Список сведений для адаптера
typedef struct AdapterList
{
	AdapterData data;			// Данные для адаптера
	HANDLE hThread;				// Ссылка на поток
	struct AdapterList *next;	// Следующий адаптер
} AdapterList;

/**
@brief Запускает процесс анализа трафика
*/
void run_sniffer();

#endif