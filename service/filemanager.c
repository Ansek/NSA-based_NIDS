/******************************************************************************
     * File: filemanager.c
     * Description: Менеджер сохранения промежуточных результатов в файлы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "filemanager.h"

FilesList *beg_flist = NULL;	// Ссылки на список файлов
FilesList *end_flist = NULL;
HANDLE print_mutex;				// Мьютекс для контроля вывода текста
	
Bool msg_log_enabled;			// Флаг вывода сообщений пользователю
Bool err_log_enabled;			// Флаг вывода ошибок пользователю
short time_sleep;				// Время перерыва между сохранениями данных

// Вспомогательные функции
// Получение файла по идентификатору
FilesList *get_file(FID id);
// Создает файл
FILE *create_file_m(const char* filename, const char* mode);
// Поток для переодичного сохранения в файлы
DWORD WINAPI fm_thread(LPVOID ptr);

void run_filemanager()
{
	print_mutex = CreateMutex(NULL, FALSE, NULL);
		
	// Получение настроек
	while (is_reading_settings_section("FileManager"))
	{
		char *name = read_setting_name();
		if (strcmp(name, "msg_log_enabled") == 0)
			msg_log_enabled = read_setting_i();
		else if (strcmp(name, "err_log_enabled") == 0)
			err_log_enabled = read_setting_i();
		else if (strcmp(name, "time_sleep") == 0)
			time_sleep = read_setting_i();
		else
			print_not_used(name);
	}
	// Создание потока
	HANDLE hThread = CreateThread(NULL, 0, fm_thread, NULL, 0, NULL);
	if (hThread != NULL)
		print_msglog("File manager started!");
}

FID open_file(const char *filename)
{
	FILE *file = create_file_m(filename, "a");
	return add_to_flist(file);
}

FILE *create_file(const char* filename)
{
	FILE *file = create_file_m(filename, "w");
	return file;
}

FID add_to_flist(FILE *file)
{
	// Добавление нового файла в список
	FilesList *flist = (FilesList *)malloc(sizeof(FilesList));
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

void fprint_s(FID id, const char *text)
{
	FilesList *flist = get_file(id);
	fputs(text, flist->file);
}

void fprint_n(FID id, const char *text, size_t size)
{
	FilesList *flist = get_file(id);
	fwrite(text, size, 1, flist->file);
}

void fprint_f(FID id, const char *text, ...)
{
	FilesList *flist = get_file(id);
	va_list ap;
	va_start(ap, text);
	vfprintf(flist->file, text, ap);
	va_end(ap);
}


void print_msglog(const char* text)
{
	if (msg_log_enabled)
	{
		puts(text);
	}
}

void print_msglogc(const char symbol)
{
	putchar(symbol);
}

void print_msglogf(const char* text, ...)
{
	if (msg_log_enabled)
	{
		va_list ap;
		va_start(ap, text);
		vprintf(text, ap);
		va_end(ap);
	}	
}

void print_errlog(const char* text)
{
	if (err_log_enabled)
	{
		printf("Error: %s!\n", text);
	}
}

void print_errlogf(const char* text, ...)
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

Bool get_msg_log_enabled()
{
	return msg_log_enabled;
}

void lock_file()
{
	WaitForSingleObject(print_mutex, INFINITE);
}

void unlock_file()
{
	ReleaseMutex(print_mutex);
}

FilesList *get_file(FID id)
{
	FilesList *p = beg_flist;
	while(p != NULL && p->id != id)
		p = p->next;
	return p;	
}

FILE *create_file_m(const char* filename, const char* mode)
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
		FilesList *p = beg_flist;
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