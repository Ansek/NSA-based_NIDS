/******************************************************************************
     * File: filemanager.h
     * Description: Менеджер сохранения промежуточных результатов в файлы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __FILEMANAGER_H__
#define __FILEMANAGER_H__

#include <dir.h>
#include <time.h>

#include "settings.h"

#define FILE_NAME_SIZE 256
#define FID uint8_t

typedef enum Format 
{
	IP, TCP, UDP, ICMP, STATS
} Format;

// Файл в который надо сохранить фрагменты
typedef struct FileList
{
	FID id;             // Идентификатор для доступа
	FILE *file;         // Указатель на файл
	struct FileList *next; // Ссылка на следующий файл
} FileList;

// Хранение информации о пакете для вывода в лог
typedef struct PackageInfo
{
	FID fid;            // Идентификатор на файл
	char time_buff[9];  // Время начала анализа
	char src_buff[16];  // Адрес отправителя
	char dst_buff[16];  // Адрес получателя
	uint16_t size;      // Размер пакета
	uint16_t shift;     // Смещение до данных
	const char *data;   // Указатель на начало данных
} PackageInfo;

// Для фиксирования времени обучения
typedef struct TimeData
{
	size_t days;      // Дни
	uint8_t hours;    // Часы
	uint8_t minutes;  // Минуты
} TimeData;

/**
@brief Запускает менеджер по сохранению файлов
*/
void run_filemanager();

/**
@brief Добавляет файл логов в список 
@param name Имя файла лога
@return Идентификатор для доступа к файлу
*/
FID add_log_file(const char *name);

/**
@brief Создает новый файл с заданным именем
@param text - Текст ошибки
*/
FILE *create_file(const char *filename);

/**
@brief Добавляет файл в список
@param file Ссылка на файл
@return Идентификатор для доступа к файлу
*/
FID add_to_flist(FILE *file);

/**
@brief Записывает информацию о пакете в файл
@param info Дополнительная информация для записи
@param data Начало данных пакета
@param format Форматированные данные
*/
void log_package(PackageInfo *info, const char *format, ...);

/**
@brief Записывает статистику в файл
@param format Форматированные данные
*/
void log_stats(const char *format, ...);

/**
@brief Сохранение базы детекторов
@param td Время затраченное на обучение
@param buff Данные для записи в файл
@param size Размер данных
*/
void save_detectors(TimeData *td, const char *buff, size_t size);

/**
@brief Загрузка базы детекторов
@return Содержимое базы 
*/
char *load_detectors();

/**
@brief Прибавляет минут к счётчик времени обучения
@param td Структура для хранения времени
@param minutes На сколько минут надо увеличить
*/
void add_time(TimeData *td, uint32_t minutes);

/**
@brief Записывает в буфер текущее время
@param buff Буферкуда надо записать
*/
void get_localtime(char *buff);

/**
@brief Возвращает шаблон для записи в файл
@param format Идентификатор шаблона
@return Указатель на шаблон
*/
const char* get_format(Format format);

/**
@brief Выводит текст сообщения пользователю
@param text - Текст сообщения
*/
void print_msglog(const char *text);

/**
@brief Выводит форматированный текст сообщения пользователю
@param text - Текст сообщения
*/
void print_msglogf(const char *text, ...);

/**
@brief Выводит текст ошибки пользователю
@param text - Текст ошибки
*/
void print_errlog(const char *text);

/**
@brief Выводит форматированный текст ошибки пользователю
@param text - Текст ошибки
*/
void print_errlogf(const char *text, ...);

#endif