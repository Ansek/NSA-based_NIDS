/******************************************************************************
     * File: sniffer.c
     * Description: Анализатор сетевого трафика.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "sniffer.h"

char packet_buffer[PACKET_BUFFER_SIZE];

// Вспомогательная, для получение имени протокола
char *get_protocol_name(const unsigned char protocol);

void run_sniffer()
{
	// Получение параметров
	while (is_reading_settings_section("Sniffer"))
	{
		char *name = read_setting_name();
		if (strcmp(name, "adapters") == 0)
			while (is_reading_setting_value())
				printf("adapter - %s\n", read_setting_s());		
	}
	// Инициализация сокетов
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2,2), &wsadata);
	// Создаение сокета
	SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	// Получение информации о хосте
	char host_name[HOST_NAME_SIZE];
	gethostname(host_name, HOST_NAME_SIZE);
	HOSTENT *host = gethostbyname(host_name);
	SOCKADDR_IN sa;
	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	printf("Adapter address: %s\n\n", 
		inet_ntoa(*((struct in_addr*)host->h_addr_list[1]))); 
	sa.sin_addr.s_addr = ((struct in_addr*)host->h_addr_list[1])->s_addr;
	// Привязка локального адреса к сокету
	bind(s, (SOCKADDR *)&sa, sizeof(SOCKADDR));
	// Включение режима promiscuous
	unsigned long flag = TRUE;
	ioctlsocket(s, SIO_RCVALL, &flag);
	
	// Просмотр всех пакетов
	while (TRUE)
	{
		int count = recv(s, packet_buffer, PACKET_BUFFER_SIZE, 0);
		if (count >= sizeof(IPHeader))
		{
			IN_ADDR addr;
			// Если пакет пришёл
			IPHeader  *packet = (IPHeader *)packet_buffer;
			// Вывод протокола
			printf("%s: ", get_protocol_name(packet->protocol));
			// Вывод отправителя 
			addr.s_addr = packet->src;
			printf("%s to ", inet_ntoa(addr));
			// Вывод получателя 
			addr.s_addr = packet->dest;
			printf("%s", inet_ntoa(addr));
			// Вывод размера
			unsigned short size = (packet->length << 8) + (packet->length >> 8);
			printf(" Size: %d\n", size);
			// Вывод содержимого после заголовка пакета
			printf("Data: \n");
			for (int i = sizeof(IPHeader); i < size; i++)
				printf("%c", packet_buffer[i]);
			printf("\n\n");
		}
	}
}

char *get_protocol_name(const unsigned char protocol)
{
	char *s = "Unknown protocol";
	switch (protocol)
	{
		case IPPROTO_IP:
			s = "IP";
			break;
		case IPPROTO_ICMP:
			s = "ICMP";
			break;
		case IPPROTO_IGMP:
			s = "IGMP";
			break;
		case IPPROTO_GGP:
			s = "GGP";
			break;
		case IPPROTO_TCP:
			s = "TCP";
			break;
		case IPPROTO_PUP:
			s = "PUP";
			break;
		case IPPROTO_UDP:
			s = "UDP";
			break;
		case IPPROTO_IDP:
			s = "IDP";
			break;
		case IPPROTO_IPV6:
			s = "IPV6";
			break;
		case IPPROTO_ND:
			s = "ND";
			break;
		case IPPROTO_ICLFXBM:
			s = "ICLFXBM";
			break;
		case IPPROTO_ICMPV6:
			s = "ICMPV6";
			break;			
	}	
	return s;
}