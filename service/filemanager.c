/******************************************************************************
     * File: filemanager.c
     * Description: Менеджер сохранения промежуточных результатов в файлы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "filemanager.h"

FileList *beg_flist = NULL; // Ссылки на список файлов
FileList *end_flist = NULL;
FID stats_fid = 0;
HANDLE pack_mutex;   // Для контроля вывода данных о пакетах
HANDLE stats_mutex;  // Для контроля вывода данных о поведении сети
HANDLE print_mutex;  // Мьютекс для контроля вывода текста
Bool msg_log_enabled = 1;  // Флаг вывода сообщений пользователю
Bool err_log_enabled = 1;  // Флаг вывода ошибок пользователю

// Параметры из файла конфигурации
short time_sleep;  // Время перерыва между сохранениями данных
const char *adapter_log_dirname = "LOG//"; // Каталог для хранения логов адаптера
const char *db_detectors_dirname = "DB//"; // Путь к файлам детекторов
const char *db_detectors_file = "detectors.db"; // Файл для загрузки детекторов

// Шаблон для вывода информации о TCP
const char *tcp_log_format = "\
%s. TCP(%s): %s:%u to %s:%u Size: %u\n\
Data: \"";
// Шаблон для вывода информации о UDP
const char *udp_log_format = "\
%s. UDP: %s:%u to %s:%u Size: %u\n\
Data: \"";
// Шаблон для вывода информации о ICMP
const char *icmp_log_format = "\
%s. ICMP(%u, %u): %s to %s Size: %u\n\
Data: \"";
// Шаблон для вывода информации о пакете по умолчанию
const char *ip_log_format = "\
%s. %s: %s to %s Size: %u\n\
Data: \"";
// Шаблон для вывода информации о статистике
const char *stats_log_format = "\
%s\n\
tc=%u;\t\tuc=%u;\t\tic=%u;\t\tipc=%u;\n\
sc=%u;\t\tac=%u;\t\tfc=%u;\t\trc=%u;\n\
atc=%u;\t\tutc=%u;\t\tauc=%u;\t\tuuc=%u;\n\n";
// Шаблон для вывода сообщения об аномальном пакете
const char *report_pa_format = "\
\n!!!\n\
%s\n\
Anomalous package!\n\
Source: %s\n\
Destination: %s\n\
Pattern:  \"";
// Шаблон для вывода сообщения об аномальной статистике
const char *report_sa_format = "\
\n!!!\n\
%s\n\
Anomalous value!\n\
%s: %u";

const char stats_levels[][43] =
{
	"Total number of TCP packets",
	"Total number of UDP packets",
	"Total number of ICMP packets",
	"Total number of packets of other protocols",
	"Number of half-open TCP connections",
	"Number of open TCP connections",
	"Number of closed TCP connections",
	"Number of dropped TCP connections",
	"Number of accesses to allowed TCP ports",
	"Number of accesses to unresolved TCP ports",
	"Number of accesses to allowed UDP ports",
	"Number of accesses to unresolved UDP ports"
};

// Вспомогательные функции
// Получение файла по идентификатору
FileList *get_file(FID id);
// Создает файл
FILE *create_file_m(const char *filename, const char *mode);

// Поток для периодичного сохранения в файлы
DWORD WINAPI fm_thread(LPVOID ptr);

void run_filemanager()
{
	pack_mutex  = CreateMutex(NULL, FALSE, NULL);
	stats_mutex = CreateMutex(NULL, FALSE, NULL);
	print_mutex = CreateMutex(NULL, FALSE, NULL);
		
	// Получение настроек
	while (is_reading_settings_section("FileManager"))
	{
		const char *name = read_setting_name();
		if (strcmp(name, "adapter_log_dirname") == 0)
			adapter_log_dirname = read_setting_s();
		else if (strcmp(name, "db_detectors_dirname") == 0)
			db_detectors_dirname = read_setting_s();
		else if (strcmp(name, "db_detectors_file") == 0)
			db_detectors_file = read_setting_s();
		else if (strcmp(name, "time_sleep") == 0)
			time_sleep = read_setting_u();
		else
			print_not_used(name);
	}
	
	// Добавление файла лога статистики
	stats_fid = add_log_file("statistics");
	
	// Создание потока
	HANDLE hThread = CreateThread(NULL, 0, fm_thread, NULL, 0, NULL);
	if (hThread != NULL)
		print_msglog("File manager started!");
}

FID add_log_file(const char *name)
{
	// Получение имени файла
	char filename[FILE_NAME_SIZE];
	sprintf(filename, "%s%s.log", adapter_log_dirname, name);
	// Открытие файла на добавление
	FILE *file = create_file_m(filename, "a");
	return add_to_flist(file);
}

FILE *create_file(const char *filename)
{
	FILE *file = create_file_m(filename, "w");
	return file;
}

FID add_to_flist(FILE *file)
{
	// Добавление нового файла в список
	FileList *flist = (FileList *)malloc(sizeof(FileList));
	flist->file = file;
	flist->next = NULL;
	if (beg_flist == NULL)
	{
		flist->id = 0;
		beg_flist = flist;
		end_flist = flist;
	}
	else
	{
		flist->id = end_flist->id + 1;
		end_flist->next = flist;
		end_flist = flist;
	}
	return flist->id;
}

void log_package(PackageInfo *info, const char *format, ...)
{
	WaitForSingleObject(pack_mutex, INFINITE);
	FileList *flist = get_file(info->fid);
	va_list ap;
	va_start(ap, format);
	vfprintf(flist->file, format, ap);
	va_end(ap);
	fwrite(info->data, info->size - info->shift, 1, flist->file);
	fputs("\"\n\n", flist->file);
	ReleaseMutex(pack_mutex);
}

void log_stats(const char *format, ...)
{
	WaitForSingleObject(stats_mutex, INFINITE);
	// Запись статистики
	FileList *flist = get_file(stats_fid);
	va_list ap;
	va_start(ap, format);
	vfprintf(flist->file, format, ap);
	va_end(ap);	
	ReleaseMutex(stats_mutex);
}

void save_detectors(TimeData *td, const char *buff, size_t size)
{
	// Формирование имени файлов логов
	char filename[FILE_NAME_SIZE];
	sprintf(filename, "%sdetectors [%u d. %u h. %u m.].db", 
		db_detectors_dirname, td->days, td->hours, td->minutes);
	// Сохранение файла
	FILE *f = create_file(filename);
	fwrite(buff, size, 1, f);
	fclose(f);
}

char *load_detectors()
{
	char *buf = NULL;
	char filename[FILE_NAME_SIZE];
	sprintf(filename, "%s%s", db_detectors_dirname, db_detectors_file);
	FILE *file = fopen(filename, "r");
	if (file != NULL)
	{
		fseek(file, 0, SEEK_END);
		long size = ftell(file);
		fseek(file, 0, SEEK_SET);
		if (size > 0)
		{
			buf = (char *)malloc(size);
			fread(buf, size, 1, file);
			fclose(file);
		}
	}
	return buf;
}

void add_time(TimeData *td, uint32_t minutes)
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

void get_localtime(char *buff)
{
	// Получение текущего времени
	time_t tt;
	struct tm *ti;
	time(&tt);
	ti = localtime(&tt);
	// Запись в буффер
	sprintf(buff, "%02d:%02d:%02d", ti->tm_hour, ti->tm_min, ti->tm_sec);
}

const char* get_format(Format format)
{
	const char *res;
	switch (format)
	{
		case IP:
			res = ip_log_format; break;
		case TCP:
			res = tcp_log_format; break;
		case UDP:
			res = udp_log_format; break;
		case ICMP:
			res = icmp_log_format; break;
		case STATS:
			res = stats_log_format; break;
		default:     
			res = "Unknown format!";
	}
	return res;
}

FileList *get_file(FID id)
{
	FileList *p = beg_flist;
	while(p != NULL && p->id != id)
		p = p->next;
	return p;	
}

FILE *create_file_m(const char *filename, const char *mode)
{
	FILE *file = fopen(filename, mode);
	// Создание директории по необходимости
	if (file == NULL)
	{
		// Попытка создать недостающую директорию
		const char *end = filename;	
		while (*end != '\0')
		{
			if (*end == '\\')
			{
				// Попытка создать директорию
				short size = end - filename + 1;
				char *dir = (char *)malloc(size);
				strncpy(dir, filename, size);
				dir[size - 1] = '\0';
				mkdir(dir);
				free(dir);
				// Повторная помытка создания файла
				file = fopen(filename, mode);
				if (file != NULL)
					break;
			}
			end++;
		}
	}
	if (file == NULL)
	{
		print_errlogf("Failed to create file \"%s\"", filename);
		exit(2);
	};
	return file;
}

DWORD WINAPI fm_thread(LPVOID ptr)
{
	while (TRUE)
	{
		FileList *p = beg_flist;
		// Запись данных из буфера в файл
		while(p != NULL)
		{
			fflush(p->file);
			p = p->next;
		}
		// Засыпание на заданный период
		Sleep(time_sleep);
	}
}

void print_msglog(const char *text)
{
	if (msg_log_enabled)
	{
		puts(text);
	}
}

void print_msglogf(const char *text, ...)
{
	if (msg_log_enabled)
	{
		va_list ap;
		va_start(ap, text);
		vprintf(text, ap);
		va_end(ap);
	}	
}

void print_errlog(const char *text)
{
	if (err_log_enabled)
	{
		printf("Error: %s!\n", text);
	}
}

void print_errlogf(const char *text, ...)
{
	if (err_log_enabled)
	{
		va_list ap;
		va_start(ap, text);
		WaitForSingleObject(print_mutex, INFINITE);
		printf("Error: ");
		vprintf(text, ap);
		puts("!");
		ReleaseMutex(print_mutex);
		va_end(ap);
	}	
}

void report_pa(const PackAnomaly *pa, const PackageInfo *info)
{
	WaitForSingleObject(print_mutex, INFINITE);
	char time_buff[9];
	get_localtime(time_buff);
	printf(report_pa_format, time_buff, info->src_buff, info->dst_buff);
	fwrite(pa->pattern, pa->len, 1, stdout);
	printf("\"\nDetector: \"");
	fwrite(pa->detector, pa->len, 1, stdout);
	puts("\"\n!!!\n");
	ReleaseMutex(print_mutex);
}

void report_sa(const StatAnomaly *sa)
{
	WaitForSingleObject(print_mutex, INFINITE);
	char time_buff[9];
	get_localtime(time_buff);
	printf(report_sa_format, time_buff, stats_levels[sa->i], sa->value[0]);
	if (sa->hrect != NULL)
		printf("Space valid range: [%u, %u]",
			sa->hrect[sa->i], sa->hrect[sa->i + sa->k]);
	if (sa->left_range != NULL)
		printf("Left valid range: [%u, %u]",
			sa->left_range[sa->i], sa->left_range[sa->i + sa->k]);
	if (sa->left_range != NULL)
		printf("Rigit valid range: [%u, %u]",
			sa->right_range[sa->i], sa->right_range[sa->i + sa->k]);
	puts("\n!!!\n");
	ReleaseMutex(print_mutex);
}
