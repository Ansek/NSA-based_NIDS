/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#include "analyzer.h"

AnalyzerList *alist = NULL;			// Ссылка на циклический список анализаторов
SavePeriodsList* beg_splist = NULL; // Минуты между сохранением детекторов
SavePeriodsList* end_splist = NULL; 
NBStatisticsList* beg_nbslist = NULL; // Список статистик поведения сети
NBStatisticsList* end_nbslist = NULL;
unsigned short alist_count;			// Количество анализаторов в списке
unsigned short max_alist_count;		// Максимальное количество анализаторов
unsigned short adapter_data_size;	// Размер данных адаптера без буфера
unsigned short stat_col_period;		// Период сбора статистики в секундах
size_t analyzer_buffer_size;		// Максимальный размер буфера анализатора
FID fid_stat;                       // Хранит идентификатор на файл статистики
Bool is_stats_changed = FALSE;		// Были ли изменения в статистике
HANDLE list_mutex;					// Мьютекс для работы со списком
HANDLE lock_mutex;					// Мьютекс для контроля блокировок
HANDLE stat_mutex;                  // Мьютекс для работы со статистикой

const char *db_detectors_dirname = NULL; // Путь к файлам детекторов

// Шаблон для вывода информации о TCP
const char* tcp_log_format = "\
%s. TCP(%s): %s:%d to %s:%d Size: %d\n\
Data: \"";
// Шаблон для вывода информации о UDP
const char* udp_log_format = "\
%s. UDP: %s:%d to %s:%d Size: %d\n\
Data: \"";
// Шаблон для вывода информации о ICMP
const char* icmp_log_format = "\
%s. ICMP(%d, %d): %s to %s Size: %d\n\
Data: \"";
// Шаблон для вывода информации о пакете по умолчанию
const char* ip_log_format = "\
%s. %s: %s to %s Size: %d\n\
Data: \"";
// Шаблон для вывода информации о статистике
const char* stat_log_format = "\
%s\n\
tc=%d;\t\tuc=%d;\t\tic=%d;\t\tipc=%d;\n\
sc=%d;\t\tac=%d;\t\tfc=%d;\t\trc=%d;\n\
atc=%d;\t\tutc=%d;\t\tauc=%d;\t\tuuc=%d;\n\n";

// Вспомогательные функции
// Создает анализатор в новом потоке
AnalyzerList *create_analyzer(Bool unlock);
// Получает свободный анализатор
AnalyzerData *get_free_analyzer(size_t length);
// Анализирует пакет протокола TCP
void analyze_tcp(PackageData *pd);
// Анализирует пакет протокола UDP
void analyze_udp(PackageData *pd);
// Анализирует пакет протокола ICMP
void analyze_icmp(PackageData *pd);
// Анализирует пакет без связи с протоколом
void analyze_ip(PackageData *pd);
// Разбор нужных элементов IP заголовка
PackageInfo get_ip_info(PackageData *pd);
// Блокировка анализатора
// @return TRUE - если заблокирован данным потоком
Bool lock_analyzer(AnalyzerData *data);
// Разблокировка анализатора
void unlock_analyzer(AnalyzerData *data);
// Добавляет промежуток в минутах между сохранением детекторов
void add_save_period(int period);
// Прибавляет минуты к td
void add_time(TimeData *td, int minutes);
// Записывает в буфер текущее время
void get_localtime(char* buff);
// Создает новую статистику в списке
void create_statistics();
// Поток для проверки пакетов
DWORD WINAPI an_thread(LPVOID ptr);
// Поток для переодичного сохранения детекторов
DWORD WINAPI sd_thread(LPVOID ptr);
// Поток для фиксации данных статистики
DWORD WINAPI nbs_thread(LPVOID ptr);

void run_analyzer()
{
	unsigned short min_alist_count;
	list_mutex = CreateMutex(NULL, FALSE, NULL);
	lock_mutex = CreateMutex(NULL, FALSE, NULL);
		
	// Получение параметров
	while (is_reading_settings_section("Analyzer"))
	{
		char *name = read_setting_name();
		if (strcmp(name, "min_analyzer_count") == 0)
			min_alist_count = read_setting_i();
		else if (strcmp(name, "max_analyzer_count") == 0)
			max_alist_count = read_setting_i();
		else if (strcmp(name, "max_packet_in_analyzer") == 0)
			analyzer_buffer_size = read_setting_i() *
				(PACKAGE_DATA_SIZE + PACKAGE_BUFFER_SIZE);
		else if (strcmp(name, "db_detectors_dirname") == 0)
			db_detectors_dirname = read_setting_s();
		else if (strcmp(name, "detector_save_periods") == 0)
			while (is_reading_setting_value())
				add_save_period(read_setting_i());
		else if (strcmp(name, "stat_col_period") == 0)
			stat_col_period = read_setting_i();
		else
			print_not_used(name);
	}
	
	// Создание потока для сохранения детекторов
	HANDLE hThread = CreateThread(NULL, 0, sd_thread, NULL, 0, NULL);
	if (hThread == NULL)
	{
		print_msglog("Thread to save detectors not created!");
		exit(6);
	}
	
	// Создание потока для сохранения статистики
	hThread = CreateThread(NULL, 0, nbs_thread, NULL, 0, NULL);
	if (hThread == NULL)
	{
		print_msglog("Thread to save statistics not created!");
		exit(7);
	}
	
	// Создание требуемого количества анализаторов
	for (int i = 0; i  < min_alist_count; i++)
		create_analyzer(FALSE);
}

void analyze_package(AdapterData *data)
{
	IPHeader *package = (IPHeader *)data->buffer;
	unsigned short len = (package->length << 8) + (package->length >> 8);
	size_t size = len + PACKAGE_DATA_SIZE;
	AnalyzerData *adata = get_free_analyzer(size);
	// Копирование информации в буфер анализатора
	WaitForSingleObject(adata->mutex, INFINITE);
	adata->w_package->adapter = data;
	adata->w_package->next = (PackageData *)((char *)adata->w_package + size);
	memcpy(&(adata->w_package->header), data->buffer, len);
	adata->w_package = adata->w_package->next;
	adata->pack_count++;
	ReleaseMutex(adata->mutex);
	unlock_analyzer(adata);
}

void set_fid_stat(FID fid)
{
	fid_stat = fid;
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
		al->hThread	= CreateThread(NULL, 0, an_thread, &(al->data), 0, NULL);
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
		print_errlogf("The maximum number of analyzers has been reached [%d]",
			max_alist_count);
	}
	ReleaseMutex(list_mutex);
	return al;
}

AnalyzerData *get_free_analyzer(size_t length)
{
	AnalyzerList *p = alist;
	AnalyzerList *al = NULL;
	unsigned short filled_count = 0;
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
				// и все анализаторы полностью заполненые
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
								print_msglogf("Analyzer #%d has been reset.\n", 
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
	return &(al->data);
}

void analyze_tcp(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	char *data = (char *)&(pd->header);
	// Получаем заголовок протокола
	TCPHeader *tcp = (TCPHeader *)(data + info.shift);
	info.shift += (tcp->length & 0xF0) >> 2;
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	NBStatistics *stat = &end_nbslist->stat;
	stat->tcp_count++;
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);	
	// Определяем флаги
	char flags[7] = "UAPRSF";
	for (int i = 0; i < 6; i++)
		if ((tcp->flags & 0x20 >> i) == 0)
			flags[i] = '_';
	// Переход к данным
	data += info.shift;
	// Вывод в файл
	fprint_package(pd->adapter->fid, data, &info, tcp_log_format,
		info.time_buff, flags,
		info.src_buff, ntohs(tcp->src_port),
		info.dst_buff, ntohs(tcp->dst_port),
		info.size);
}

void analyze_udp(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	char *data = (char *)&(pd->header);
	// Получаем заголовок протокола
	UDPHeader *udp = (UDPHeader *)(data + info.shift);
	info.shift += sizeof(UDPHeader);
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	NBStatistics *stat = &end_nbslist->stat;
	stat->udp_count++;
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);	
	// Переход к данным
	data += info.shift;
	// Вывод в файл
	fprint_package(pd->adapter->fid, data, &info, udp_log_format,
		info.time_buff,
		info.src_buff, ntohs(udp->src_port),
		info.dst_buff, ntohs(udp->dst_port),
		info.size);
}

void analyze_icmp(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	char *data = (char *)&(pd->header);
	// Получаем заголовок протокола
	ICMPHeader *icmp = (ICMPHeader *)(data + info.shift);
	info.shift += sizeof(ICMPHeader);
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	NBStatistics *stat = &end_nbslist->stat;
	stat->icmp_count++;
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);	
	// Переход к данным
	data += info.shift;
	// Вывод в файл
	fprint_package(pd->adapter->fid, data, &info, icmp_log_format,
		info.time_buff, icmp->type, icmp->code,
		info.src_buff, info.dst_buff, info.size);
}

void analyze_ip(PackageData *pd)
{
	PackageInfo info = get_ip_info(pd);
	char *data = (char *)(&pd->header);
	data += info.shift;
	// Сбор статистики
	WaitForSingleObject(stat_mutex, INFINITE);
	NBStatistics *stat = &end_nbslist->stat;
	stat->ip_count++;
	is_stats_changed = TRUE;
	ReleaseMutex(stat_mutex);
	// Вывод в файл
	fprint_package(pd->adapter->fid, data, &info, icmp_log_format,
		info.time_buff, get_protocol_name(pd->header.protocol),
		info.src_buff, info.dst_buff, info.size);
}

PackageInfo get_ip_info(PackageData *pd)
{
	PackageInfo info;
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

void add_save_period(int period)
{
	SavePeriodsList *splist;
	splist = (SavePeriodsList *)malloc(sizeof(SavePeriodsList));
	splist->period = period;
	splist->next = NULL;
	// Добавление его в список
	if (beg_splist == NULL)
	{
		beg_splist = splist;
		end_splist = splist;
	}
	else
	{
		end_splist->next = splist;
		end_splist = splist;
	}
}

void add_time(TimeData *td, int minutes)
{
	// Получение минут
	td->minutes += minutes % 60;
	if (td->minutes > 59)
	{
		td->hours++;
		td->minutes -= 60;
	}
	minutes /= 60;
	// Получение часов
	td->hours += minutes % 24;
	if (td->hours > 23)
	{
		td->days++;
		td->hours -= 24;
	}
	minutes /= 24;
	// Получение дней
	td->days += minutes;
}

void get_localtime(char* buff)
{
	// Получение текущего времени
	time_t tt;
	struct tm *ti;
	time(&tt);
	ti = localtime(&tt);
	// Запись в буффер
	sprintf(buff, "%02d:%02d:%02d", ti->tm_hour, ti->tm_min, ti->tm_sec);
}

void create_statistics()
{
	NBStatisticsList *nbslist;
	nbslist = (NBStatisticsList *)malloc(sizeof(NBStatisticsList));
	ZeroMemory(&nbslist->stat, sizeof(NBStatistics));
	nbslist->next = NULL;
	// Добавление его в список
	WaitForSingleObject(stat_mutex, INFINITE);
	if (beg_nbslist == NULL)
	{
		beg_nbslist = nbslist;
		end_nbslist = nbslist;
	}
	else
	{
		end_nbslist->next = nbslist;
		end_nbslist = nbslist;
	}
	is_stats_changed = FALSE;
	ReleaseMutex(stat_mutex);	
}

DWORD WINAPI an_thread(LPVOID ptr)
{
	AnalyzerData* data = (AnalyzerData *)ptr;	
	print_msglogf("Analyzer #%d launched\n", data->id);
	while (TRUE)
	{
		if (data->pack_count)
		{
			data->read = TRUE;
			PackageData *pd = data->r_package;
			// Определение типа протокола для уточнения анализа
			if (pd->header.protocol == IPPROTO_TCP)
				analyze_tcp(pd);
			else if (pd->header.protocol == IPPROTO_UDP)
				analyze_udp(pd);
			else if (pd->header.protocol == IPPROTO_ICMP)
				analyze_icmp(pd);
			else
				analyze_ip(pd);
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
	TimeData td;
	td.days = 0;
	td.hours = 0;
	td.minutes = 0;
	while (beg_splist != NULL)
	{
		// Засыпание на определенное количество минут
		Sleep(beg_splist->period * 60000); // До 24 дней 
		add_time(&td, beg_splist->period); // Увеличение на минуту
		// Формирование имени файлов логов
		if (db_detectors_dirname == NULL)
			db_detectors_dirname = "DB//";
		char filename[FILE_NAME_SIZE];
		sprintf(filename, "%sdetectors [%d d. %d h. %d m.].db", 
			db_detectors_dirname, td.days, td.hours, td.minutes);
		// Сохранение файла
		FILE *f = create_file(filename);
		fprintf(f, "%d m.", beg_splist->period);
		fclose(f);
		// Переход к следующему элементу и освобождение памяти
		SavePeriodsList* temp = beg_splist;
		beg_splist = beg_splist->next;
		free(temp);
		temp = NULL;
	}
}

DWORD WINAPI nbs_thread(LPVOID ptr)
{
	while (TRUE)
	{
		// Запись текущей статистики в лог
		if (is_stats_changed)
		{
			// Получение времени
			char time_buff[9];
			get_localtime(time_buff); 
			// Запись статистики
			NBStatistics *stat = &end_nbslist->stat;
			fprint_f(fid_stat, stat_log_format, time_buff,
				stat->tcp_count, stat->udp_count, stat->icmp_count, stat->ip_count,
				stat->syn_count, stat->ask_sa_count, stat->fin_count, stat->rst_count,
				stat->al_tcp_port_count, stat->un_tcp_port_count,
				stat->al_udp_port_count, stat->un_udp_port_count);
		}
		// Добавление новой статистики, для сохранения предыдущей
		create_statistics();
		Sleep(stat_col_period * 1000);
	}
}