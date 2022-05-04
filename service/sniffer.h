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

#include "settings.h"

#define SIO_RCVALL 0x98000001 		// Для приёма всех пакетов из сети
#define HOST_NAME_SIZE 		128		// Размер имени хоста
#define PACKET_BUFFER_SIZE 	65535	// Размер буфера пакета

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

/**
@brief Запускает процесс анализа трафика
*/
void run_sniffer();

#endif