/******************************************************************************
     * File: algorithm.c
     * Description: Функции для алгоритма отрицательного отбора.
     * Created: 28 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#include "algorithm.h"

WorkingMemory *det_db  = NULL;   // Набор детекторов для анализа пакета
WorkingMemory *pat_db  = NULL;   // Набор шаблонов нормальной активности 
WorkingMemory *stat_db = NULL;   // Набор шаблонов для анализа поведения сети

// Параметры из файла конфигурации
uint8_t pat_length    = 6;  // Длина шаблона пакета
uint8_t pat_shift     = 1;  // Шаг сдвига шаблона пакета
uint8_t affinity      = 4;  // Если равно и выше, то строки различны

/**
@brief Проверка шаблона на уникальность и добавление в базу
@param pat Строка шаблона
*/
void parse_pattern(const char *pat);

/**
@brief Добавление шаблона в базу
@param pat Строка шаблона
*/
void add_pattern(const char *pat);

/**
@brief Текущий шаблон заменяет другой из базы
@param pat Строка шаблона
*/
void replace_pattern(const char *pat);

/**
@brief Фиксация результатов и сброс статистики
*/
void commit_and_reset_statistics();

void init_algorithm()
{
	uint32_t max_dd_count = 0;  // Кол-во детекторов для анализа пакета
	uint32_t max_pd_count = 0;  // Кол-во шаблонов нормальной активности 
	uint32_t max_sd_count = 0;  // Кол-во шаблонов для анализа поведения сети
	
	// Получение параметров
	while (is_reading_settings_section("Algorithm"))
	{
		char *name = read_setting_name();
		if (strcmp(name, "detector_count") == 0)
			max_dd_count = read_setting_i();
		else if (strcmp(name, "pattern_count") == 0)
			max_pd_count = read_setting_i();
		else if (strcmp(name, "statistic_count") == 0)
			max_sd_count = read_setting_i();
		else if (strcmp(name, "pattern_length") == 0)
			pat_length = read_setting_i();
		else if (strcmp(name, "pattern_shift") == 0)
			pat_shift = read_setting_i();
		else if (strcmp(name, "affinity") == 0)
			affinity = read_setting_i();
		else
			print_not_used(name);
	}
	
	det_db  = create_memory(max_dd_count, pat_length);   
	pat_db  = create_memory(max_pd_count, pat_length);
	stat_db = create_memory(max_sd_count, sizeof(NBStats));
	ZeroMemory(stat_db->memory, stat_db->max_count * sizeof(NBStats));
}

void free_algorithm()
{
	free_memory(det_db);
	free_memory(pat_db);
	free_memory(stat_db);
}

WorkingMemory *create_memory(uint32_t max_count, uint8_t size)
{
	WorkingMemory *wm = (WorkingMemory *)malloc(sizeof(WorkingMemory));
	wm->max_count = max_count;
	wm->memory = (uint8_t *)malloc(max_count * size);
	wm->mutex = CreateMutex(NULL, FALSE, NULL); 
	reset_memory(wm);
}

void reset_memory(WorkingMemory *wm)
{
	wm->count = 0;
	wm->cursor = wm->memory;
}

void free_memory(WorkingMemory *wm)
{
	CloseHandle(wm->mutex);
	free(wm->memory);
}

Bool add_to_memory(WorkingMemory *wm, const char *data)
{
	Bool res = FALSE;
	if (data != NULL)
	{
		WaitForSingleObject(wm->mutex, INFINITE);
		if (wm->count < wm->max_count)
		{
			memcpy(wm->cursor, data, pat_length);
			wm->cursor += pat_length;
			wm->count++;
		}
		ReleaseMutex(wm->mutex);
		res = FALSE;
	}
	return res;
}

Bool write_to_memory(WorkingMemory *wm, char *cursor, const char *data)
{
	Bool res = FALSE;
	if (cursor != NULL && data != NULL)
	{
		WaitForSingleObject(wm->mutex, INFINITE);
		memcpy(cursor, data, pat_length);
		ReleaseMutex(wm->mutex);
		res = FALSE;
	}	
	return res;	
}

void break_into_patterns(const char *buf, uint32_t len)
{
	if (len > 0)
	{
		const char *max_buf = buf + len;
		while (buf < max_buf)
		{
			if (buf + pat_length > max_buf)
			{
				// Выравнивание до длины шаблона
				char *temp = (char *)malloc(pat_length);
				uint8_t size = max_buf - buf;
				memcpy(temp, buf, size);
				for (uint8_t i = size; i < pat_length; i++)
					temp[i] = ' ';
				parse_pattern(temp);
				free(temp);
			}
			else
				parse_pattern(buf);
			buf += pat_shift;
		}
	}	
}

uint8_t hamming_distance(const char *s1, const char *s2)
{
	uint8_t d = 0;
	for (uint8_t i = 0; i < pat_length; i++)
		if (s1[i] != s2[i])
			d++;
	return d;
}

NBStats *get_statistics()
{
	NBStats *res;
	WaitForSingleObject(stat_db->mutex, INFINITE);
	// Если полностью заполнили
	if (stat_db->count == stat_db->max_count)
		commit_and_reset_statistics();
	// Возврат текущей области
	res = (NBStats *)stat_db->cursor;
	stat_db->count++;
	stat_db->cursor += sizeof(NBStats);
	ReleaseMutex(stat_db->mutex);
	return res;
}

void parse_pattern(const char *pat)
{
	if (pat_db->count < pat_db->max_count)
		add_pattern(pat);
	else
		replace_pattern(pat);
}

void add_pattern(const char *pat)
{
	const char *p = pat_db->memory;
	// Сравнение с другими шаблонами
	for (uint32_t i = 0; i < pat_db->count; i++)
	{
		// Если строки похожи
		if (hamming_distance(p, pat) < affinity)
		{
			pat = NULL;
			break;
		}
		p += pat_length;
	}
	// Добавление в базу
	add_to_memory(pat_db, pat);
}

void replace_pattern(const char *pat)
{  
	// Поиск непохожего шаблона для замены
	char *p = pat_db->memory;
	char *max_p = NULL;
	uint8_t max_d = 1;
	for (uint32_t i = 0; i < pat_db->count; i++)
	{
		uint8_t d = hamming_distance(p, pat);
		// Если строки не похожи
		if (d > affinity && d > max_d)
		{
			max_p = p;
			max_d = d;
		}
		// Если достигли возможного максимума
		if (max_d == pat_length)
			break;
		p += pat_length;
	}
	// Произведение замены
	if (!write_to_memory(pat_db, max_p, pat))
		print_errlog("Failed to replace pattern!");
}

void commit_and_reset_statistics()
{
	printf("Memory has been reset\n");
	ZeroMemory(stat_db->memory, stat_db->max_count * sizeof(NBStats));
	reset_memory(stat_db);
}