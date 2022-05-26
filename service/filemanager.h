/******************************************************************************
     * File: filemanager.h
     * Description: Менеджер сохранения промежуточных результатов в файлы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __FILEMANAGER_H__
#define __FILEMANAGER_H__

#include <windows.h>
#include <dir.h>

#include "settings.h"

#define FILE_NAME_SIZE 256
#define FID unsigned char

// Файл в который надо сохранить фрагменты
typedef struct FilesList
{
	FID id;						// Идентификатор файла	
	FILE *file;					// Идентификатор потока файла
	struct FilesList *next;		// Ссылка на следующий файл
} FilesList;

// Хранение информации о пакете для вывода в лог
typedef struct PackageInfo
{
	char time_buff[9];          // Время начала анализа
	char src_buff[16];          // Адрес отправителя
	char dst_buff[16];          // Адрес получателя
	unsigned short size;        // Размер пакета
	unsigned short shift;       // Смещение до данных
} PackageInfo;

/**
@brief Запускает менеджер по сохранению файлов
*/
void run_filemanager();

/**
@brief Открывает файл
@param filename Имя файла
@return Идентификатор для доступа к файлу
*/
FID open_file(const char *filename);

/**
@brief Создает новый файл с заданным именем
@param text - Текст ошибки
*/
FILE *create_file(const char* filename);

/**
@brief Добавляет файл в список
@param file Ссылка на файл
@return Идентификатор для доступа к файлу
*/
FID add_to_flist(FILE *file);

/**
@brief Записывает строку в файл
@param id Идентификатор для доступа к файлу
@param text Текст для записи
*/
void fprint_s(FID id, const char *text);

/**
@brief Записывает строку определенного размера в файл
@param id Идентификатор для доступа к файлу
@param text Текст для записи
@param size Размер данных
*/
void fprint_n(FID id, const char *text, size_t size);

/**
@brief Записывает форматированную строку в файл
@param id Идентификатор для доступа к файлу
@param text Текст для записи
*/
void fprint_f(FID id, const char* text, ...);

/**
@brief Записывает информацию о пакете в файл
@param id Идентификатор для доступа к файлу
@param data Начало данных пакета
@param pi Информация о пакете
@param text Текст для записи
*/
void fprint_package(FID id, const char *data, PackageInfo *info, const char *text, ...);

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

/**
@brief Блокирование потока для записи в файла
*/
void lock_file();

/**
@brief Блокирование потока для записи в файла
*/
void unlock_file();

#endif