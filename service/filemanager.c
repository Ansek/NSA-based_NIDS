/******************************************************************************
     * File: filemanager.c
     * Description: Менеджер сохранения промежуточных результатов в файлы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "filemanager.h"

FilesList *beg_flist = NULL;		// Ссылки на список файлов
FilesList *end_flist = NULL;	
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
		if (strcmp(name, "time_sleep") == 0)
			time_sleep = read_setting_i();
		else
			print_not_used(name);
	}
	// Создание потока
	HANDLE hThread = CreateThread(NULL, 0, fm_thread, NULL, 0, NULL);
	if (hThread != NULL)
		printf("File manager started!\n");
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
		printf("Trying to add a fragment to an unrelated file!\n");
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
				printf("Failed to create file \"%s\"!\n", p->name);
				exit(2);
			};
			p = p->next;
		}
		// Засыпание на заданный период
		Sleep(time_sleep);
	}
}