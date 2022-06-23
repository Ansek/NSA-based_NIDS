/******************************************************************************
     * File: sniffer.c
     * Description: Анализатор сетевого трафика.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "sniffer.h"

char package_buffer[PACKAGE_BUFFER_SIZE];
AdapterList *beg_alist = NULL;  // Ссылки на список адаптеров
AdapterList *end_alist = NULL;
 
/**
@brief Подключение к адаптеру для прослушивания
@param addr - Адрес адаптера
*/
void connection_to_adapter(const char *addr);

/**
@brief Поток для анализа трафика
*/
DWORD WINAPI sn_thread(LPVOID ptr);

void run_sniffer()
{
	// Инициализация сокетов
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != NO_ERROR)
		print_msglog("WinSock initialization failed!\n");
	
	PList *tcp_port = create_plist();
	PList *udp_port = create_plist();
	
	// Получение параметров
	while (is_reading_settings_section("Sniffer"))
	{
		const char *name = read_setting_name();
		if (strcmp(name, "adapters") == 0)
			while (is_reading_setting_value())
				connection_to_adapter(read_setting_s());
		else if (strcmp(name, "allowed_tcp_ports") == 0)
			while (is_reading_setting_value())
				add_in_plist(tcp_port, htons(read_setting_u()));
		else if (strcmp(name, "allowed_udp_ports") == 0)
			while (is_reading_setting_value())
				add_in_plist(udp_port, htons(read_setting_u()));
		else
			print_not_used(name);
	}

	// Инициализация анализаторов
	run_analyzer(tcp_port, udp_port);
}

void connection_to_adapter(const char *addr)
{
	// Создание отдельного потока
	AdapterList *alist = (AdapterList *)malloc(sizeof(AdapterList));
	alist->data.addr = addr;
	alist->data.fid = add_log_file(addr);
	alist->hThread	= CreateThread(NULL, 0, sn_thread, &alist->data, 0, NULL);
	if (alist->hThread == NULL)
		print_errlog("Failed to create thread!\n");
	alist->next = NULL;
	// Добавление его в список
	if (beg_alist == NULL)
		beg_alist = alist;
	else
		end_alist->next = alist;
	end_alist = alist;
}

DWORD WINAPI sn_thread(LPVOID ptr)
{
	AdapterData *data = (AdapterData *)ptr;
	// Создание сокета
	SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (s == INVALID_SOCKET) {
		print_errlogf("Error creating socket: %s\n", WSAGetLastError());
		WSACleanup();
		exit(5);
	}
	// Подключение сокета к адаптеру
	SOCKADDR_IN sa;
	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(data->addr);
	bind(s, (SOCKADDR *)&sa, sizeof(SOCKADDR));
	
	// Включение режима promiscuous
	unsigned long flag = TRUE;
	ioctlsocket(s, SIO_RCVALL, &flag);
	
	print_msglogf("Listening on adapter with address %s.\n", data->addr);
	// Просмотр всех пакетов
	while (TRUE)
	{
		int count = recv(s, data->buffer, PACKAGE_BUFFER_SIZE, 0);
		if (count >= sizeof(IPHeader))
		{
			analyze_package(data);
		}
	}
}

const char *get_protocol_name(const uint8_t protocol)
{
	char *s = "Unknown protocol";
	switch (protocol)
	{
		case IPPROTO_IP:
			s = "IP";
			break;
		case IPPROTO_IGMP:
			s = "IGMP";
			break;
		case IPPROTO_GGP:
			s = "GGP";
			break;
		case IPPROTO_PUP:
			s = "PUP";
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