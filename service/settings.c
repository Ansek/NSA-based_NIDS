/******************************************************************************
     * File: settings.c
     * Description: Извлечение данных из файла конфигурации.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "settings.h"

char settings_buffer[SETTINGS_BUFFER_SIZE];	// Буфер для извленичия текста
FILE *settings;  						    // Объект файла настроек
Bool is_reading_value;	// Для оповещения о нескольких значений параметра

// Вспомогательная, для проверки на новый параметр
Bool check_available()
{
	if (!feof(settings))
	{
		char c = getc(settings);
		// Игнорирование строки комментария
		while (c != EOF && c == ';')
		{
			//Cчитывание до новой строки
			do {
				c = getc(settings);
			} while (c != EOF && c != '\n');
			c = getc(settings);
		}
		// Если нет новой секции или пустой строки
		if (c != EOF && c != '[' && c != ' ' && c != '\n' && c != '\r')
		{
			ungetc(c, settings);
			return TRUE;
		}
	}
	return FALSE;
}

Bool is_reading_settings_section(char *section)
{
	Bool is_available = FALSE;
	// Файл настроек уже просматривается
	if (settings != NULL)
	{
		// Проверка, что параметр есть
		is_available = check_available();
		if (!is_available)
		{
			fclose(settings);
			settings = NULL;
		}			
	}
	else 
	{
		char c;
		char *p = NULL;
		settings = fopen(FILE_NAME, "r");
		// Поиск нужной секции
		do {
			// Поиск названия раздела
			do {
				c = getc(settings);
			} while (c != EOF && c != '[');
			if (c != EOF)
			{
				// Сравнение названия
				p = section;
				do {
					c = getc(settings);
					if (*p == c)
						p++;
					else
						break;
				} while (c != EOF);
				// Если нашли нужную секцию
				if (c != EOF && c == ']')
				{
					//Cчитывание до новой строки
					do {
						c = getc(settings);
					} while (c != EOF && c != '\n');
					// Проверка, что параметр есть
					is_available = check_available();
					if (is_available)
						break;
				}
			}
		} while (c != EOF);
	}
	return is_available;
}

Bool is_reading_setting_value()
{
	return is_reading_value;
}

// Вспомогательная, для проверки наличия значения параметра
void check_setting_value()
{
	char c = getc(settings);
	if (c != '\n' && c != EOF)
		is_reading_value = TRUE;
	ungetc(c, settings);
}

char *read_setting_name()
{
	int i = 0;
	// Считывание имени до разделителя "="
	for (; i < SETTINGS_BUFFER_SIZE; i++)
	{
		settings_buffer[i] = getc(settings);
		if (settings_buffer[i] == EOF)
			i = SETTINGS_BUFFER_SIZE;
		else if (settings_buffer[i] == '=')
		{
			check_setting_value();
			break;
		}
	}
	// Контроль на правильность считывания имени
	if (i == SETTINGS_BUFFER_SIZE)
	{
		fprintf(stderr, "Проблема с определением параметра: {%s}\n",
			settings_buffer[i]);
        exit(1);
	}
	else
	{
		settings_buffer[i] = '\0';
	}
	return settings_buffer;
}

// Вспомогательная, для проверок после считывания значения
void check_setting()
{
	char c;
	is_reading_value = FALSE;
	//Cчитывание до новой строки
	do {
		c = getc(settings);
		// Если обнаружен разделитель
		if (c == ',')
		{
			check_setting_value();
			break;
		}
	} while (c != EOF && c != '\n');	
}

int read_setting_i()
{
	int i;
	fscanf(settings, "%d", &i);
	check_setting();
	return i;
}

float read_setting_f()
{
	float f;
	fscanf(settings, "%f", &f);
	check_setting();
	return f;
}

char *read_setting_s()
{
	int i = 0;
	char c;
	//Cчитывание до новой строки
	while(i < SETTINGS_BUFFER_SIZE - 1)
	{
		c = getc(settings);
		// Пропуск двойных кавычек
		if (c == '"')
			continue;
		// Если обнаружен разделитель
		if (c == ',')
		{
			check_setting_value();
			break;
		}
		//Если конец строки
		if (c == EOF || c == '\n')
		{
			is_reading_value = FALSE;
			break;
		}
		settings_buffer[i] = c;
		i++;
	}
	settings_buffer[i] = '\0';
	// Копирование параметра в новый массив
	if (i > 0)
	{
		char *res = (char *)malloc(i);
		strcpy(res, settings_buffer);
		return res;
	}
	else
	{
		printf("There is no parameter after the delimiter!\n");
		exit(1);
	}
} 