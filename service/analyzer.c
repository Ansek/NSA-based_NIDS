/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#include "analyzer.h"

AnalyzerList *alist = NULL;			// Ссылка на циклический список анализаторов
unsigned short alist_count;			// Количество анализаторов в списке
unsigned short max_alist_count;		// Максимальное количество анализаторов
unsigned short adapter_data_size;	// Размер данных адаптера без буфера
size_t analyzer_buffer_size;		// Максимальный размер буфера анализатора
HANDLE list_mutex;					// Мьютекс для работы со списком
HANDLE lock_mutex;					// Мьютекс для контроля блокировок
HANDLE print_mutex;					// Мьютекс для контроля вывода текста

// Вспомогательные функции
// Создает анализатор в новом потоке
AnalyzerList *create_analyzer(Bool unlock);
// Получает свободный анализатор
AnalyzerList *get_free_analyzer(unsigned short length);
// Блокировка анализатора
// @return TRUE - если заблокирован данным потоком
Bool lock_analyzer(AnalyzerList *al);
// Разблокировка анализатора
void unlock_analyzer(AnalyzerList *al);
// Увеличение параметра количества обрабатываемых пакетов
void inc_pack_count(AnalyzerData *data);
// Уменьшение параметра количества обрабатываемых пакетов
void dec_pack_count(AnalyzerData *data);
// Поток для проверки пакетов
DWORD WINAPI an_thread(LPVOID ptr);

void run_analyzer()
{
	unsigned short min_alist_count;
	list_mutex = CreateMutex(NULL, FALSE, NULL);
	lock_mutex = CreateMutex(NULL, FALSE, NULL);
	print_mutex = CreateMutex(NULL, FALSE, NULL);
	
	// Получение параметров
	while (is_reading_settings_section("Analyzer"))
	{
		char *name = read_setting_name();
		if (strcmp(name, "min_analyzer_count") == 0)
			min_alist_count = read_setting_i();
		else if (strcmp(name, "max_analyzer_count") == 0)
			max_alist_count = read_setting_i();
		else if (strcmp(name, "max_packet_in_analyzer") == 0)
		{
			analyzer_buffer_size = read_setting_i() * sizeof(AdapterData);
			adapter_data_size = sizeof(AdapterData) - PACKAGE_BUFFER_SIZE - 1;
		}
		else
			print_not_used(name);
	}
	
	// Создание требуемого количества анализаторов
	for (int i = 0; i  < min_alist_count; i++)
		create_analyzer(FALSE);
}

void analyze_package(AdapterData *data)
{
	IPHeader *package = (IPHeader *)data->buffer;
	unsigned short len = (package->length << 8) + (package->length >> 8);
	size_t size = len + adapter_data_size;
	AnalyzerList *al = get_free_analyzer(size);
	// Копирование информации в анализатор
	memcpy((al->data.buffer + al->data.w_cursor), data, size);
	al->data.w_cursor += size;
	inc_pack_count(&al->data);
	unlock_analyzer(al);
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
		al->data.r_cursor = 0;
		al->data.w_cursor = 0;
		al->data.e_cursor = 0;
		al->data.lock = lock;
		al->data.mutex = CreateMutex(NULL, FALSE, NULL);
		al->data.buffer = (char *)malloc(analyzer_buffer_size);
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
		}
	}
	else
	{
		print_errlogf("The maximum number of analyzer analyzers has been reached [%d]!\n",
			max_alist_count);
	}
	ReleaseMutex(list_mutex);
	return al;
}

AnalyzerList *get_free_analyzer(unsigned short length)
{
	AnalyzerList *p = alist;
	AnalyzerList *al = NULL;
	unsigned short filled_count = 0;
	do
	{	
		// Проверяем, что анализатор не заблокирован другим потоком
		if (lock_analyzer(p))
		{
			// Смотрим размер свободного места после курсора записи
			if (length < analyzer_buffer_size - p->data.w_cursor)
			{
				al = p;
			}
			// и перед курсором чтения
			// (При блокировке курсор чтения не должен опускаться)
			else if (length < p->data.r_cursor)
			{
				al = p;
				al->data.w_cursor = 0; // Сброс курсора записи в начало
			}
			else
			{
				filled_count++;
				unlock_analyzer(p);
			}
		}
		// Создаем новый анализатор, если не получилось найти свободный	
		if (p->next == alist && al == NULL)
		{
			al = create_analyzer(TRUE);
			// Если нельзя больше создавать анализаторы из-за ограничения
			// и все анализаторы полностью заполненые
			if (al == NULL && filled_count == alist_count)
			{
				print_msglog("Search analyzer to reset.\n");
				do
				{
					if (lock_analyzer(p))
					{
						// Проверка доступности сброса
						if (length < analyzer_buffer_size - p->data.e_cursor)
						{
							al = p;
							al->data.w_cursor = 0; // Сброс курсора записи в начало
							print_msglogf("Analyzer #%d has been reset.\n", al->data.id);
						}
						else
							unlock_analyzer(p);
					}
					p = p->next;
				}
				while (al == NULL);
			}
		}
		p = p->next;
	}
	while (al == NULL);
	return al;
}

// Блокировка анализатора
Bool lock_analyzer(AnalyzerList *al)
{
	Bool l = FALSE;
	WaitForSingleObject(lock_mutex, INFINITE);
	// Проверяем, что анализатор свободен
	if (!al->data.lock)
	{
		al->data.lock = TRUE;
		l = TRUE;
	}
	ReleaseMutex(lock_mutex);
	return l;
}

// Разблокировка анализатора
void unlock_analyzer(AnalyzerList *al)
{
	WaitForSingleObject(lock_mutex, INFINITE);
	al->data.lock = FALSE;
	ReleaseMutex(lock_mutex);
}

void inc_pack_count(AnalyzerData *data)
{
	WaitForSingleObject(data->mutex, INFINITE);
	data->pack_count++;
	ReleaseMutex(data->mutex);
}

void dec_pack_count(AnalyzerData *data)
{
	WaitForSingleObject(data->mutex, INFINITE);
	data->pack_count--;
	ReleaseMutex(data->mutex);
}

const char* package_info = "\
Analyzer #%d\n\
Adapter %s\n\
%s: %s to %s Size: %d\n\
Data:\n";

DWORD WINAPI an_thread(LPVOID ptr)
{
	AnalyzerData* data = (AnalyzerData *)ptr;	
	print_msglogf("Analyzer #%d launched\n", data->id);
	while (TRUE)
	{
		if (data->pack_count)
		{
			char *adapter_addr, *package_data;
			// Разбор данных о пакете
			package_data = data->buffer + data->r_cursor;
			memcpy(&adapter_addr, package_data, sizeof(char *));
			package_data += sizeof(char *);
			IPHeader *package = (IPHeader *)package_data;
		
			IN_ADDR src_addr, dest_addr;
			src_addr.s_addr = package->src;
			dest_addr.s_addr = package->dest;
			unsigned short size = (package->length << 8) + (package->length >> 8);
			
			WaitForSingleObject(print_mutex, INFINITE);
			print_msglogf(package_info, data->id, adapter_addr, 
				get_protocol_name(package->protocol),
				inet_ntoa(src_addr), inet_ntoa(dest_addr), 
				size);
			if (get_msg_log_enabled())
				for (int i = sizeof(IPHeader); i < size; i++)
					print_msglogc(package_data[i]);
			print_msglog("\n\n");	
			ReleaseMutex(print_mutex);

			dec_pack_count(data);
		}
	}
}
