/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#include "analyzer.h"

NBStats *stats  = NULL;     // Для сбора статистики  поведения сети
PList *tcp_ports = NULL;    // Список разрешенных TCP портов
PList *udp_ports = NULL;    // Список разрешенных UDP портов
PList *min_det_save = NULL; // Минуты между сохранением детекторов
AnalyzerList *alist = NULL; // Ссылка на циклический список анализаторов
SynTCPList *beg_synlist = NULL; // Список полуоткрытых соединений 
SynTCPList *end_synlist = NULL;
Bool is_stats_changed = FALSE;  // Были ли изменения в статистике
uint16_t alist_count; // Количество анализаторов в списке
HANDLE list_mutex;    // Мьютекс для работы со списком
HANDLE lock_mutex;    // Мьютекс для контроля блокировок
HANDLE stat_mutex;    // Мьютекс для работы со статистикой
TimeData stud_time;   // Для хранения времени обучения

// Параметры из файла конфигурации
uint8_t  work_mode;   // Режим работы анализаторов 
uint16_t max_alist_count;    // Максимальное количество анализаторов
uint16_t stat_col_period;    // Период сбора статистики в секундах
uint16_t det_gen_period;     // Период генерации детектора в секундах
size_t analyzer_buffer_size; // Максимальный размер буфера анализатора

/**
@brief Создает анализатор в новом потоке
@param unlock Должен ли анализтор быть разблокирован
@return - Указатель на список
*/
AnalyzerList *create_analyzer(Bool unlock);

/**
@brief Получает свободный анализатор
@param length - Размер пространства, которое нужно занять
*/
AnalyzerData *get_free_analyzer(size_t length);

/**
@brief Анализирует пакет протокола TCP
@param pd - Данные пакета
*/
void analyze_tcp(PackageData *pd);
 
/**
@brief Анализирует пакет протокола UDP
@param pd - Данные пакета
*/
void analyze_udp(PackageData *pd);

/**
@brief Анализирует пакет протокола ICMP
@param pd - Данные пакета
*/
void analyze_icmp(PackageData *pd);

/**
@brief Анализирует пакет без связи с протоколом
@param pd - Данные пакета
*/
void analyze_ip(PackageData *pd);

/**
@brief Проверяет содержимое пакета
@param info Информация о пакете
*/
void analyze_data(PackageInfo *info);

/**
@brief Разбор нужных элементов IP заголовка
@param pd - Данные пакета
@return Структура с основным содержимым для вывода
*/
PackageInfo get_ip_info(PackageData *pd);

/**
@brief Блокировка анализатора
@param data - Данные анализатора
@return TRUE - если заблокирован данным потоком
*/
Bool lock_analyzer(AnalyzerData *data);

/**
@brief Разблокировка анализатора
@param data - Данные анализатора
*/
void unlock_analyzer(AnalyzerData *data);

/**
@brief Добавляет адрес в список полуоткрытых соединения
@param src - Адрес отправителя
*/
void add_syn_tcp_list(uint32_t src);

/**
@brief Удаляет адрес из списка полуоткрытых соединения
@param src - Адрес отправителя
@return TRUE - был ли такой элемент в списке
*/
Bool remove_syn_tcp_list(uint32_t src);

/**
@brief Поток для проверки пакетов
*/
DWORD WINAPI an_thread(LPVOID ptr);

/**
@brief Поток для периодичного сохранения детекторов
*/
DWORD WINAPI sd_thread(LPVOID ptr);

/**
@brief Поток для периодичной генерации детекторов
*/
DWORD WINAPI gd_thread(LPVOID ptr);

/**
@brief Поток для фиксации данных статистики
*/
DWORD WINAPI stats_thread(LPVOID ptr);

void run_analyzer(PList *tcp_ps, PList *udp_ps)
{
	tcp_ports = tcp_ps;
	udp_ports = udp_ps;
	min_det_save = create_plist(); 
	
	uint16_t min_alist_count;
	list_mutex = CreateMutex(NULL, FALSE, NULL);
	lock_mutex = CreateMutex(NULL, FALSE, NULL);

	// Получение параметров
	while (is_reading_settings_section("Analyzer"))
	{
		const char *name = read_setting_name();
		if (strcmp(name, "work_mode") == 0)
			work_mode = read_setting_u();
		else if (strcmp(name, "min_analyzer_count") == 0)
			min_alist_count = read_setting_u();
		else if (strcmp(name, "max_analyzer_count") == 0)
			max_alist_count = read_setting_u();
		else if (strcmp(name, "max_packet_in_analyzer") == 0)
			analyzer_buffer_size = read_setting_u() *
				(PACKAGE_DATA_SIZE + PACKAGE_BUFFER_SIZE);
		else if (strcmp(name, "detector_save_periods") == 0)
			while (is_reading_setting_value())
				add_in_plist(min_det_save, read_setting_u());
		else if (strcmp(name, "statistics_collection_period") == 0)
			stat_col_period = read_setting_u();
		else if (strcmp(name, "detector_generation_period") == 0)		
			det_gen_period = read_setting_u();
		else
			print_not_used(name);
	}

	// Инициализация параметров алгоритм отрицательного отбора
	init_algorithm(&stud_time);
	stats = get_statistics();

	// Создание потока для сохранения детекторов
	HANDLE hThread = CreateThread(NULL, 0, sd_thread, NULL, 0, NULL);
	if (hThread == NULL)
	{
		print_msglog("Thread to save detectors not created!");
		exit(6);
	}

	// Создание потока для сохранения статистики
	hThread = CreateThread(NULL, 0, gd_thread, NULL, 0, NULL);
	if (hThread == NULL)
	{
		print_msglog("Thread to save statistics not created!");
		exit(7);
	}
	
	// Создание потока для генерации детекторов
	hThread = CreateThread(NULL, 0, stats_thread, NULL, 0, NULL);
	if (hThread == NULL)
	{
		print_msglog("Thread to save statistics not created!");
		exit(8);
	}
	
	// Создание требуемого количества анализаторов
	for (int i = 0; i  < min_alist_count; i++)
		create_analyzer(FALSE);
}

void analyze_package(AdapterData *data)
{
	IPHeader *package = (IPHeader *)data->buffer;
	uint16_t len = (package->length << 8) + (package->length >> 8);
	size_t size = len + PACKAGE_DATA_SIZE;
	AnalyzerData *adata = get_free_analyzer(size);
	// Копирование информации в буфер анализатора
	WaitForSingleObject(adata->mutex, INFINITE);
	adata->w_package->adapter = data;
	adata->w_package->next = (PackageData *)((char *)adata->w_package + size);
	memcpy(&adata->w_package->header, data->buffer, len);
	adata->w_package = adata->w_package->next;
	adata->pack_count++;
	ReleaseMutex(adata->mutex);
	unlock_analyzer(adata);
}

AnalyzerList *create_analyzer(Bool lock)
{
	AnalyzerList *al = NULL;
	WaitForSingleObject(list_mutex, INFINITE);
	if (alist_count < max_alist_count)
	{
		// Создание отдельного потока
		al = (AnalyzerList *)malloc(sizeof(AnalyzerList));
		alist_count++;
		al->data.id = alist_count;
		al->data.pack_count = 0;
		al->data.read = FALSE;
		al->data.lock = lock;
		al->data.mutex = CreateMutex(NULL, FALSE, NULL);
		al->data.buffer = (char *)malloc(analyzer_buffer_size);
		al->data.r_package = (PackageData *)(PackageData *)al->data.buffer;
		al->data.w_package = (PackageData *)(PackageData *)al->data.buffer;
		al->data.r_package->adapter = NULL; // Как признак отсутствия пакета
		al->hThread	= CreateThread(NULL, 0, an_thread, &al->data, 0, NULL);
		if (al->hThread == NULL)
			print_errlog("Failed to create thread!\n");
		// Добавление его в циклический список
		if (alist == NULL)
		{
			alist = al;
			alist->next = al;
		}
		else
		{
			al->next = alist->next;
			alist->next = al;
			alist = alist->next;
		}
	}
	else
	{
		print_errlogf("The maximum number of analyzers has been reached [%u]",
			max_alist_count);
	}
	ReleaseMutex(list_mutex);
	return al;
}

AnalyzerData *get_free_analyzer(size_t length)
{
	AnalyzerList *p = alist;
	AnalyzerList *al = NULL;
	uint16_t filled_count = 0;
	do
	{	
		char *buffer_top = (p->data.buffer + analyzer_buffer_size);
		// Проверяем, что анализатор не заблокирован другим потоком
		if (lock_analyzer(&p->data))
		{	
			char *r_cursor = (char *)p->data.r_package;
			char *w_cursor = (char *)p->data.w_package;
			// Ищем свободное место
			if (r_cursor < w_cursor)
			{
				// После указателя записи
				if (length <= (buffer_top - w_cursor))
					al = p;
				// Перед указателем чтения
				else if (length <= r_cursor - p->data.buffer)
				{
					al = p;
					// Поиск последнего пакета
					PackageData *pd = al->data.r_package;
					while (pd->next != al->data.w_package)
						pd = pd->next;
					// Сброс записи на начало буфера
					al->data.w_package = (PackageData *)al->data.buffer; 
					pd->next = al->data.w_package;
				}
					
			}
			else if (r_cursor > w_cursor)
			{
				// Между указателями
				if (length <= r_cursor - w_cursor)
					al = p;
			}
			else 
			{
				// Если указывает на обработанный пакет
				if (p->data.r_package->adapter == NULL)
					al = p;
			}
		}
		// Создаем новый анализатор, если не получилось найти свободный	
		if (al == NULL)
		{
			filled_count++;
			unlock_analyzer(&p->data);
			if (p->next == alist)
			{
				al = create_analyzer(TRUE);
				// Если нельзя больше создавать анализаторы из-за ограничения
				// и все анализаторы полностью заполненные
				if (al == NULL && filled_count == alist_count)
				{
					print_msglog("Search analyzer to reset.\n");
					do
					{
						if (lock_analyzer(&p->data))
						{
							// Проверка доступности сброса
							char *next = (char *)p->data.r_package->next;
							if (length <= buffer_top - next)
							{
								al = p;
								// Сброс записи на начало буфера
								al->data.w_package = al->data.r_package->next;
								WaitForSingleObject(al->data.mutex, INFINITE);
								if (al->data.read)
									al->data.pack_count = 1;
								else
									al->data.pack_count = 0;
								ReleaseMutex(al->data.mutex);
								print_msglogf("Analyzer #%u has been reset.\n", 
									al->data.id);
							}
							else
								unlock_analyzer(&p->data);
						}
						p = p->next;
					}
					while (al == NULL);
				}
			}
		}
		p = p->next;
	}
	while (al == NULL);
	return &al->data;
}

void analyze_tcp(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	info.data  = (char *)&pd->header;
	// Получаем заголовок протокола
	TCPHeader *tcp = (TCPHeader *)(info.data + info.shift);
	info.shift += (tcp->length & 0xF0) >> 2;
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	stats->tcp_count++;
	// флаги
	if (tcp->flags == SYN_FTCP && stats->syn_count < 65535)
	{
		stats->syn_count++;
		add_syn_tcp_list(pd->header.src);
	}
	else if (tcp->flags == ACK_FTCP && stats->ask_sa_count < 65535)
	{
		if (remove_syn_tcp_list(pd->header.src))
			stats->ask_sa_count++;
	}
	else if (tcp->flags == FIN_FTCP && stats->fin_count < 65535)
		stats->fin_count++;
	else if (tcp->flags == RST_FTCP && stats->rst_count < 65535)
		stats->rst_count++;
	// порты
	if (contain_in_plist(tcp_ports, tcp->dst_port))
	{
		if (stats->al_tcp_port_count < 65535)
			stats->al_tcp_port_count++;
	}
	else
	{
		if (stats->un_tcp_port_count < 65535)
			stats->un_tcp_port_count++;
	}	
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);	
	// Определяем флаги
	char flags[7] = "UAPRSF";
	for (int i = 0; i < 6; i++)
		if ((tcp->flags & 0x20 >> i) == 0)
			flags[i] = '_';
	// Переход к данным
	info.data += info.shift;
	// Анализ содержимого пакета
	analyze_data(&info);
	// Вывод в файл
	log_package(&info, get_format(TCP),
		info.time_buff, flags,
		info.src_buff, ntohs(tcp->src_port),
		info.dst_buff, ntohs(tcp->dst_port),
		info.size);
}

void analyze_udp(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	info.data = (char *)&pd->header;
	// Получаем заголовок протокола
	UDPHeader *udp = (UDPHeader *)(info.data + info.shift);
	info.shift += sizeof(UDPHeader);
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	stats->udp_count++;
	// порты
	if (contain_in_plist(udp_ports, udp->dst_port))
	{
		if (stats->al_udp_port_count < 65535)
			stats->al_udp_port_count++;
	}
	else
	{
		if (stats->un_udp_port_count < 65535)
			stats->un_udp_port_count++;
	}	
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);
	// Переход к данным
	info.data += info.shift;
	// Анализ содержимого пакета
	analyze_data(&info);
	// Вывод в файл
	log_package(&info, get_format(UDP), info.time_buff,
		info.src_buff, ntohs(udp->src_port),
		info.dst_buff, ntohs(udp->dst_port),
		info.size);
}

void analyze_icmp(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	info.data = (char *)&pd->header;
	// Получаем заголовок протокола
	ICMPHeader *icmp = (ICMPHeader *)(info.data + info.shift);
	info.shift += sizeof(ICMPHeader);
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	stats->icmp_count++;
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);	
	// Переход к данным
	info.data += info.shift;
	// Анализ содержимого пакета
	analyze_data(&info);
	// Вывод в файл
	log_package(&info, get_format(ICMP),
		info.time_buff, icmp->type, icmp->code,
		info.src_buff, info.dst_buff, info.size);
}

void analyze_ip(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	info.data = (char *)(&pd->header);
	info.data += info.shift;
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	stats->ip_count++;
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);
	// Переход к данным
	info.data += info.shift;
	// Анализ содержимого пакета
	analyze_data(&info);
	// Вывод в файл
	log_package(&info, get_format(IP),
		info.time_buff, get_protocol_name(pd->header.protocol),
		info.src_buff, info.dst_buff, info.size);
}

void analyze_data(PackageInfo *info)
{
	uint16_t len = info->size - info->shift;
	if (len > 0)
		break_into_patterns(info->data, len);
}

PackageInfo get_ip_info(PackageData *pd)
{
	PackageInfo info;
	// Запись идентификатор на файл
	info.fid = pd->adapter->fid;
	// Получение текущего времени
	get_localtime(info.time_buff);
	// Получение адресов
	IN_ADDR in_addr;
	in_addr.s_addr = pd->header.src;
	strcpy(info.src_buff, inet_ntoa(in_addr));
	in_addr.s_addr = pd->header.dst;
	strcpy(info.dst_buff, inet_ntoa(in_addr));
	// Определение размера
	info.size = ntohs(pd->header.length);
	// Определение смещения
	info.shift = sizeof(IPHeader);
	return info;
}

Bool lock_analyzer(AnalyzerData *data)
{
	Bool l = FALSE;
	WaitForSingleObject(lock_mutex, INFINITE);
	// Проверяем, что анализатор свободен
	if (!data->lock)
	{
		data->lock = TRUE;
		l = TRUE;
	}
	ReleaseMutex(lock_mutex);
	return l;
}

void unlock_analyzer(AnalyzerData *data)
{
	WaitForSingleObject(lock_mutex, INFINITE);
	data->lock = FALSE;
	ReleaseMutex(lock_mutex);
}

void add_syn_tcp_list(uint32_t src)
{
	SynTCPList *p = beg_synlist;
	// Попытка найти в списке
	while (p != NULL)
		if (p->src == src)
		{
			if (p->count < 65535)
				p->count++;
			break;
		}			
		else
			p = p->next;

	if (p == NULL)
	{
		p = (SynTCPList *)malloc(sizeof(SynTCPList));
		p->src = src;
		p->count = 1;
		p->next = NULL;
		// Добавление его в список
		if (beg_synlist == NULL)
		{
			beg_synlist = p;
			end_synlist = p;
		}
		else
		{
			end_synlist->next = p;
			end_synlist = p;
		}
	}
}

Bool remove_syn_tcp_list(uint32_t src)
{
	Bool res = FALSE;
	SynTCPList *p = beg_synlist;
	if (p != NULL)
	{
		SynTCPList *pred = NULL; 
		// Поиск нужного адреса
		while (p != NULL && p->src != src)
		{
			pred = p;
			p = p->next;
		}
		if (p != NULL && p->count > 0)
		{
			p->count--;
			res = TRUE;
			if (p->count == 0)
			{
				if (pred == NULL)
					beg_synlist = beg_synlist->next;
				else
					pred->next = p->next;
				free(p);
				p = NULL;
			}
		}
	}
}

DWORD WINAPI an_thread(LPVOID ptr)
{
	AnalyzerData *data = (AnalyzerData *)ptr;
	print_msglogf("Analyzer #%u launched\n", data->id);
	while (TRUE)
	{
		if (data->pack_count && work_mode > 0)
		{
			data->read = TRUE;
			PackageData *pd = data->r_package;
			// Определение типа протокола для уточнения анализа
			if (work_mode == WMODE_STUD)
			{
				if (pd->header.protocol == IPPROTO_TCP)
					analyze_tcp(pd);
				else if (pd->header.protocol == IPPROTO_UDP)
					analyze_udp(pd);
				else if (pd->header.protocol == IPPROTO_ICMP)
					analyze_icmp(pd);
				else
					analyze_ip(pd);
			}
			// Отмечаем, что пакет проверен
			pd->adapter = NULL; 
			data->r_package = pd->next;
			WaitForSingleObject(data->mutex, INFINITE);
			data->pack_count--;
			data->read = FALSE;
			ReleaseMutex(data->mutex);
		}
	}
}

DWORD WINAPI sd_thread(LPVOID ptr)
{
	PNode *p = min_det_save->beg;
	while (p != NULL)
	{
		// Засыпание на определенное количество минут
		Sleep(p->value * 60000); // До 24 дней
		work_mode = WMODE_PASS;
		add_time(&stud_time, p->value); // Увеличение на минуту
		// Сохранение данных
		size_t size;
		const char *data = pack_detectors(&stud_time, &size);
		save_detectors(&stud_time, data, size);
		// Переход к следующему элементу и освобождение памяти
		PNode *temp = p;
		p = p->next;
		free(temp);
		temp = NULL;
		work_mode = WMODE_STUD;
	}
}

DWORD WINAPI stats_thread(LPVOID ptr)
{
	while (TRUE)
	{
		Sleep(stat_col_period * 1000);
		// Запись текущей статистики в лог
		if (is_stats_changed)
		{
			// Получение времени
			char time_buff[9];
			get_localtime(time_buff);
			// Запись статистики
			log_stats(get_format(STATS), time_buff, 
				stats->tcp_count, stats->udp_count,
				stats->icmp_count, stats->ip_count,
				stats->syn_count, stats->ask_sa_count,
				stats->fin_count, stats->rst_count,
				stats->al_tcp_port_count, stats->un_tcp_port_count,
				stats->al_udp_port_count, stats->un_udp_port_count);
			// Добавление новой статистики, для сохранения предыдущей
			stats = get_statistics();
			is_stats_changed = FALSE;
		}
	}
}

DWORD WINAPI gd_thread(LPVOID ptr)
{
	do
	{
		Sleep(det_gen_period * 1000);
	}
	while (generate_detector());
}