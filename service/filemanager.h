/******************************************************************************
     * File: filemanager.h
     * Description: Менеджер сохранения промежуточных результатов в файлы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __FILEMANAGER_H__
#define __FILEMANAGER_H__

#include <windows.h>

#include "settings.h"

// Фрагмент текста, который надо сохранить
typedef struct Fragment
{
	char *text;					// Содержимое текста
	struct Fragment *next;		// Ссылка на следующий фрагмент
} Fragment;

// Файл в который надо сохранить фрагменты
typedef struct FilesList
{
	short id;					// Идентификатор файла	
	char *name;					// Имя файла
	Fragment *b_fragment;		// Ссылка на первый фрагмент
	Fragment *e_fragment;		// Ссылка на последний фрагмент
	struct FilesList *next;		// Ссылка на следующий файл
} FilesList;

/**
@brief Запускает менеджер по сохранению файлов
*/
void run_filemanager();

/**
@brief Регистрирует новый файл для записи
@param filename Имя файла
@return Идентификатор на очередь 
*/
short reg_file(char* filename);

/**
@brief Добавление фрагмента для сохранения в файл
@param id Имя файла
@param text Содержимое текста
*/
void add_fragment(short id, char* text);

#endif