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