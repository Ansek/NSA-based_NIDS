/******************************************************************************
     * File: main.c
     * Description: Объединение остальных модулей системы.
     * Created: 3 апреля 2021
     * Author: Секунов Александр

******************************************************************************/

#include "main.h"

int main()
{
	// Тестирование логгера
	run_filemanager();
	Sleep(1000);
	short id = reg_file("Log\\test.log");
	add_fragment(id, "Test Data 1\nIndicator 1\nIndicator 2\n\n");
	add_fragment(id, "Test Data 2\nIndicator 1\nIndicator 2\n\n");
	add_fragment(id, "Test Data 3\nIndicator 1\nIndicator 2\n\n");

	// Тестирование получения пакетов
	run_sniffer();	

	return 0;
}