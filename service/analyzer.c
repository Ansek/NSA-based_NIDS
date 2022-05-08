/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#include "analyzer.h"

AnalyzerList *alist = NULL;		// Ссылка на циклический список анализаторов
unsigned short alist_count;			 // Количество анализаторов в списке
unsigned short max_alist_count;		 // Максимальное количество анализаторов
unsigned short analyzer_buffer_size; // Максимальный размер буфера анализатора

// Вспомогательные функции
// Создает анализатор в новом потоке
void create_analyzer();
// Поток для проверки пакетов
DWORD WINAPI an_thread(LPVOID ptr);

void run_analyzer()
{
	unsigned short min_alist_count;
	
	// Получение параметров
	while (is_reading_settings_section("Analyzer"))
	{
		char *name = read_setting_name();
		if (strcmp(name, "min_analyzer_count") == 0)
			min_alist_count = read_setting_i();
		else if (strcmp(name, "max_analyzer_count") == 0)
			max_alist_count = read_setting_i();
		else if (strcmp(name, "max_packet_in_analyzer") == 0)
			analyzer_buffer_size = read_setting_i() * PACKAGE_BUFFER_SIZE;
		else
			print_not_used(name);
	}
	
	// Создание требуемого количества анализаторов
	for (int i = 0; i  < min_alist_count; i++)
		create_analyzer();
}

void analyze_package(char *pack)
{
	// TODO: реализовать
}

void create_analyzer()
{
	if (alist_count < max_alist_count)
	{
		// Создание отдельного потока
		AnalyzerList *al = (AnalyzerList *)malloc(sizeof(AnalyzerList));
		alist_count++;
		al->data.id = alist_count;
		al->data.pack_count = 0;
		al->data.buffer = (char *)malloc(analyzer_buffer_size);
		al->hThread	= CreateThread(NULL, 0, an_thread, &(al->data), 0, NULL);
		if (al->hThread == NULL)
			printf("Failed to create thread!\n");
		// Добавление его в циклический список
		if (alist == NULL)
		{
			alist = al;
			alist->next = al;
		}
		else
		{
			al->next = alist->next;
			alist->next = al;
		}
	}
	else
	{
		printf("The maximum number of analyzer analyzers has been reached [%d]!\n",
			max_alist_count);
	}
}

DWORD WINAPI an_thread(LPVOID ptr)
{
	AnalyzerData* data = (AnalyzerData*)ptr;	
	printf("Analyzer #%d launched\n", data->id);
}

