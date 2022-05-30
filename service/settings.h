/******************************************************************************
     * File: settings.h
     * Description: Извлечение данных из файла конфигурации.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __SETTINGS_H__
#define __SETTINGS_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define FILE_NAME "config.ini"   // Имя файла настроек
#define SETTINGS_BUFFER_SIZE 64  // Размер буфера для извлечения текста

#define Bool char
#define FALSE 0
#define TRUE 1

// Узел для хранения целочисленных параметров
typedef struct PNode
{
	uint16_t value;      // Данные
	struct PNode *next;  // Следующее значение
} PNode;

// Список для хранения целочисленных параметров
typedef struct PList
{
	PNode* beg;    // Указатель на начало списка
	PNode* end;    // Указатель на конец списка 
	HANDLE mutex;  // Для разграничения доступа
} PList;

/**
@brief Проверяет, требуется ли читать секцию дальше? 
@param section Название секции
@return TRUE - в секции еще остались настройки
*/
Bool is_reading_settings_section(const char *section);

/**
@brief Проверяет, имеет ли параметр еще значения
@return TRUE - найдено еще значение
*/
Bool is_reading_setting_value();

/**
@brief Считывает название параметра настройки
@return Название параметра
*/
const char *read_setting_name();

/**
@brief Считывает положительное целочисленное значение параметра
@return Значение параметра
*/
uint32_t read_setting_u();

/**
@brief Считывает строковое значение параметра
@return Значение параметра
*/
const char *read_setting_s();

/**
@brief Выводит сообщение, что параметр не используется
@brief и осуществляет переход к следующей строке
@param name Имя параметра
*/
void print_not_used(const char *name);

/**
@brief Создает список для хранения целочисленных значений
@return Новый список
*/
PList *create_plist();

/**
@brief Добавляет значение в список
@param pl Список, в который надо добавить
@param value Добавляемое значение
*/
void add_in_plist(PList *pl, uint16_t value);

/**
@brief Проверяет, содержится ли данное значение в списке
@param pl Список, в котором надо искать
@param value Проверяемое значение
@return TRUE - содержится
*/
Bool contain_in_plist(PList *pl,uint16_t value);

#endif 