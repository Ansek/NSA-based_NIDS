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
unsigned short alist_count;			// Количество анализаторов в списке
unsigned short max_alist_count;		// Максимальное количество анализаторов
unsigned short adapter_data_size;	// Размер данных адаптера без буфера
size_t analyzer_buffer_size;		// Максимальный размер буфера анализатора
HANDLE list_mutex;					// Мьютекс для работы со списком
HANDLE lock_mutex;					// Мьютекс для контроля блокировок

const char *db_detectors_dirname = NULL; // Путь к файлам детекторов

// Вспомогательные функции
// Создает анализатор в новом потоке
AnalyzerList *create_analyzer(Bool unlock);
// Получает свободный анализатор
AnalyzerData *get_free_analyzer(size_t length);
// Блокировка анализатора
// @return TRUE - если заблокирован данным потоком
Bool lock_analyzer(AnalyzerData *data);
// Разблокировка анализатора
void unlock_analyzer(AnalyzerData *data);
// Добавляет промежуток в минутах между сохранением детекторов
void add_save_period(int period);
// Прибавляет минуты к td
void add_time(TimeData *td, int minutes);
// Поток для проверки пакетов
DWORD WINAPI an_thread(LPVOID ptr);
// Поток для переодичного сохранения детекторов
DWORD WINAPI sd_thread(LPVOID ptr);

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
		else
			print_not_used(name);
	}
	
	// Создание требуемого количества анализаторов
	for (int i = 0; i  < min_alist_count; i++)
		create_analyzer(FALSE);
	
	// Создание потока для сохранения детекторов
	HANDLE hThread = CreateThread(NULL, 0, sd_thread, NULL, 0, NULL);
	if (hThread == NULL)
		print_msglog("Thread to save detectors not created!");
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
	// Создание отдельного потока
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

const char* package_info = "\
%02d:%02d:%02d. %s: %s to %s Size: %d\n\
Data: \"";

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
			// Получение текущего времени
			time_t tt;
			struct tm *ti;
			time(&tt);
			ti = localtime(&tt);
			// Заполние данных
			IN_ADDR in_addr;
			char src_buff[16];
			char dest_buff[16];
			unsigned short size;
			unsigned short shift = sizeof(IPHeader);
			size = (pd->header.length << 8) + (pd->header.length >> 8);
			in_addr.s_addr = pd->header.src;
			strcpy(src_buff, inet_ntoa(in_addr));
			in_addr.s_addr = pd->header.dest;
			strcpy(dest_buff, inet_ntoa(in_addr));
			// Вывод в файл
			lock_file();	
			fprint_f(pd->adapter->fid, package_info,
				ti->tm_hour, ti->tm_min, ti->tm_sec,
				get_protocol_name(pd->header.protocol),
				src_buff, dest_buff, size);
			fprint_n(pd->adapter->fid, &(pd->data), size - shift);
			fprint_s(pd->adapter->fid, "\"\n\n");
			unlock_file();		
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