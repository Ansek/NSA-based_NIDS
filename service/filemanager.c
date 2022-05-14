/******************************************************************************
     * File: filemanager.c
     * Description: Менеджер сохранения промежуточных результатов в файлы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "filemanager.h"

FilesList *beg_flist = NULL;	// Ссылки на список файлов
FilesList *end_flist = NULL;	
Bool msg_log_enabled;			// Флаг вывода сообщений пользователю
Bool err_log_enabled;			// Флаг вывода ошибок пользователю
short time_sleep;				// Время перерыва между сохранениями данных

// Вспомогательные функции
// Получение файла по идентификатору
FilesList *get_file(short id);
// Поток для переодичного сохранения в файлы
DWORD WINAPI fm_thread(LPVOID ptr);

void run_filemanager()
{
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
		print_msglog("File manager started!\n");
}

short reg_file(char* name)
{
	// Добавление нового файла в список
	FilesList *flist = (FilesList *)malloc(sizeof(FilesList));
	flist->name = name;
	flist->b_fragment = NULL;
	flist->e_fragment = NULL;
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

void add_fragment(short id, char* text)
{
	FilesList *flist = get_file(id);
	if (flist != NULL)
	{
		// Добавление нового фрагмента для записи в список
		Fragment *fr = (Fragment *)malloc(sizeof(Fragment));
		fr->text = text;
		fr->next = NULL;
		if (flist->b_fragment == NULL)
		{
			flist->b_fragment = fr;
			flist->e_fragment = fr;
		}
		else
		{
			flist->e_fragment->next = fr;
			flist->e_fragment = fr;
		}
	}
	else
	{
		print_errlog("Trying to add a fragment to an unrelated file");
		exit(2);
	}
}

FilesList *get_file(short id)
{
	FilesList *p = beg_flist;
	while(p != NULL && p->id != id)
		p = p->next;
	return p;	
}

DWORD WINAPI fm_thread(LPVOID ptr)
{
	// Проверка наличия фрагментов для записи
	while (TRUE)
	{
		// Поиск файла
		FilesList *p = beg_flist;
		while(p != NULL && p->b_fragment != NULL)
		{
			// Запись содержимого в файл
			Fragment *fr = p->b_fragment;
			FILE *file;
			if ((file = fopen(p->name, "a")) != NULL)
			{
				// Вывод и освобождение ресурсов
				while (fr != NULL)
				{
					fputs(fr->text, file);
					Fragment *temp = fr;
					fr = fr->next;
					free(temp->text);
					free(temp);
					temp = NULL;
				}
				fclose(file);
				// Очистка списка
				p->b_fragment = NULL;
				p->e_fragment = NULL;
			}
			else
			{
				print_errlogf("Failed to create file \"%s\"", p->name);
				exit(2);
			};
			p = p->next;
		}
		// Засыпание на заданный период
		Sleep(time_sleep);
	}
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
		puts("Error: ");
		vprintf(text, ap);
		puts("!\n");
		va_end(ap);
	}	
}

Bool get_msg_log_enabled()
{
	return msg_log_enabled;
}