/******************************************************************************
     * File: settings.h
     * Description: Извлечение данных из файла конфигурации.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __SETTINGS_H__
#define __SETTINGS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_NAME "config.ini"		// Имя файла настроек
#define SETTINGS_BUFFER_SIZE 64		// Размеор буфера для извленичия текста

//typedef enum { FALSE, TRUE } Bool;
#define Bool char
#define FALSE 0
#define TRUE 1

/**
@brief Проверяет, требуется ли читать секцию дальше? 
@param section Название секции
@return TRUE - в секции еще остались настройки
*/
Bool is_reading_settings_section(char *section);

/**
@brief Считывает название параметра настройки
@return Название параметра
*/
char *read_setting_name();

/**
@brief Считывает целочисленное значение параметра
@return Значение параметра
*/
int read_setting_i();

/**
@brief Считывает вещественного значение параметра
@return Значение параметра
*/
float read_setting_f();

/**
@brief Считывает строковое значение параметра
@return Значение параметра
*/
char *read_setting_s();

#endif 