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

/**
@brief Выводит текст сообщения пользователю
@param text - Текст сообщения
*/
void print_msglog(const char* text);

/**
@brief Вывод одного символа 
@param symbol - Код символа
*/
void print_msglogc(const char symbol);

/**
@brief Выводит форматированный текст сообщения пользователю
@param text - Текст сообщения
*/
void print_msglogf(const char* text, ...);

/**
@brief Выводит текст ошибки пользователю
@param text - Текст ошибки
*/
void print_errlog(const char* text);

/**
@brief Выводит форматированный текст ошибки пользователю
@param text - Текст ошибки
*/
void print_errlogf(const char* text, ...);

/**
@brief Возращает флаг доступности вывода сообщений пользователю
@param symbol - Код символа
*/
Bool get_msg_log_enabled();

#endif