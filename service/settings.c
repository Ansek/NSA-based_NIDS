/******************************************************************************
     * File: settings.c
     * Description: Извлечение данных из файла конфигурации.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "settings.h"

char settings_buffer[SETTINGS_BUFFER_SIZE];	// Буфер для извленичия текста
FILE *settings;  						    // Объект файла настроек

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
			break;
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

int read_setting_i()
{
	char c;
	int i;
	fscanf(settings, "%d", &i);
	//Cчитывание до новой строки
	do {
		c = getc(settings);
	} while (c != EOF && c != '\n');
	return i;
}

float read_setting_f()
{
	char c;
	float f;
	fscanf(settings, "%f", &f);
	//Cчитывание до новой строки
	do {
		c = getc(settings);
	} while (c != EOF && c != '\n');
	return f;
}

char *read_setting_s()
{
	if (fgets(settings_buffer, SETTINGS_BUFFER_SIZE, settings) != NULL)
	{
		// Удаление символа новой строки
		int i = strlen(settings_buffer);
		settings_buffer[i - 1] = '\0'; 
		return settings_buffer;
	}
	return "";
} 