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
@brief Генерирует число с помощью операций XOR и логического сдвига
@return Псевдослучайное число
*/
uint32_t xorshift128();

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
@brief Заменяет детектор на новое сгенерированное случайное значение
@param det куда записывается результат
@return TRUE - удалось заменить детектор
*/
Bool replace_detector(char *det);

/**
@brief Записывает в det_db случайную строку,
@brief которая не похожа на строки из pat_db
*/
void generate_detector();

/**
@brief Добавляет векторы из памяти в k-мерное дерево
@param tree K-мерное дерево
@param wm Считываемая память
*/
void add_from_memore(KDTree *tree, const WorkingMemory *wm);

/**
@brief Заполняет память данными из узла k-мерного дерева
@param wm Память, в которую записывают
@param node Узел с данными
@param k Мерность пространства
*/
void save_kdnode_to_memory(WorkingMemory *wm, const KDNode *node, uint8_t k);

/**
@brief Сжатие, путем объединених непустых ветвей
@brief и удаление узлов с пустыми листьями
@param node Узел с данными
@param k Мерность пространства
@return Граничные вектора листа или NULL, если лист пуст
*/
VectorType *compress_kdnode(KDNode *node, uint8_t k);

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
		const char *name = read_setting_name();
		if (strcmp(name, "detector_count") == 0)
			max_dd_count = read_setting_u();
		else if (strcmp(name, "pattern_count") == 0)
			max_pd_count = read_setting_u();
		else if (strcmp(name, "statistic_count") == 0)
			max_sd_count = read_setting_u();
		else if (strcmp(name, "pattern_length") == 0)
			pat_length = read_setting_u();
		else if (strcmp(name, "pattern_shift") == 0)
			pat_shift = read_setting_u();
		else if (strcmp(name, "affinity") == 0)
			affinity = read_setting_u();
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
	wm->size = size;
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
			memcpy(wm->cursor, data, wm->size);
			wm->cursor += wm->size;
			wm->count++;
		}
		ReleaseMutex(wm->mutex);
		res = TRUE;
	}
	return res;
}

Bool write_to_memory(WorkingMemory *wm, char *cursor, const char *data)
{
	Bool res = FALSE;
	if (cursor != NULL && data != NULL)
	{
		WaitForSingleObject(wm->mutex, INFINITE);
		memcpy(cursor, data, wm->size);
		ReleaseMutex(wm->mutex);
		res = TRUE;
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

VectorType *get_hrect(const VectorType *vecs, uint32_t len, uint8_t k)
{
	// В первой половие хранится минимум, во второй максимум 
	VectorType *min_hrect = (VectorType *)malloc(2 * k * sizeof(VectorType));
	VectorType *max_hrect = min_hrect + k;
	// Вычисление границ
	for (uint8_t i = 0; i < k; i++)
	{
		min_hrect[i] = UINT16_MAX;
		max_hrect[i] = 0;
		const VectorType *p = vecs;
		for (uint32_t j = 0; j < len; j++)
		{
			if (p[i] < min_hrect[i])
				min_hrect[i] = p[i];
			if (p[i] > max_hrect[i])
				max_hrect[i] = p[i];
			p += k;
		}		
	}	
	return min_hrect;
}

KDNode *create_kdnode(VectorType *hrect, uint8_t i, uint8_t k, uint32_t depth)
{
	// Заполнение нового узла
	KDNode *node = (KDNode *)malloc(sizeof(KDNode));
	// Определение возможности разделить пространство пополам
	VectorType min, max;
	uint8_t save = i;
	do 
	{
		node->i = i;
		
		min = hrect[i];
		max = hrect[k + i];
		i++;
		if (i == k)
			i = 0;

		// Если зациклись
		if (save == i)
		{
			return NULL;
		}
	}
	while (max - min == 0); // Переход к другой мерности
		 
	// Вычисление среднего значения
	node->mean = (min + max) >> 1;  // (a+b)/2
	// Если не достигли нужной глубины
	if (depth > 0)
	{
		depth--;
		// Построение левой стороны дерева (<= mean)
		hrect[node->i + k] = node->mean;      // max
		node->left = create_kdnode(hrect, i, k, depth);
		hrect[node->i + k] = max;
		// Построение правой стороны дерева (> mean)
		hrect[node->i] = node->mean + 1;      // min
		node->right = create_kdnode(hrect, i, k, depth);
		hrect[node->i] = min;
	}
	else
	{
		node->left = NULL;
		node->right = NULL;
	}
	// Отметка листов (тогда указатели будут хранить min и max значения)
	node->is_leaf = node->left == NULL && node->right == NULL;
	return node;
}

void add_in_kdtree(KDTree *tree, const VectorType *vector)
{
	KDNode *p = tree->root;
	uint8_t k = tree->k;
	// Поиск листа
	while (!p->is_leaf)
		if (vector[p->i] > p->mean)
			p = p->right;
		else
			p = p->left;
	// Если лист не содержит значений
	if (p->left == NULL)
	{
		VectorType *data = (VectorType *)malloc(2 * k * sizeof(VectorType));
		memcpy(data, vector, k * sizeof(VectorType));      // min
		memcpy(data + k, vector, k * sizeof(VectorType));  // max
		// Сохранение ссылок в свободных узлах дерева
		p->left = (KDNode *)data;
		p->right = (KDNode *)(data + k);
	}
	else
	{
		// Распаковка данных
		VectorType *min = (VectorType *)p->left;
		VectorType *max = (VectorType *)p->right;
		// Сравнение данных
		for (int i = 0; i < k; i++)
		{
			if (vector[i] < min[i])
				min[i] = vector[i];
			if (vector[i] > max[i])
				max[i] = vector[i];
		}		
	}
}

KDTree *create_kdtree(const WorkingMemory *wm, uint32_t depth)
{
	KDTree *tree = (KDTree *)malloc(sizeof(KDTree));
	tree->k = wm->size / sizeof(VectorType);
	tree->depth = depth;
	// Получение граничных значений для построения дерева
	tree->hrect = get_hrect((VectorType *)wm->memory, wm->count, tree->k);
	tree->root = create_kdnode(tree->hrect, 0, tree->k, depth);
	// Заполнение информацией о точках
	add_from_memore(tree, wm);
	return tree;
}

void move_memory_to_kdtree(KDTree *tree, WorkingMemory *wm)
{
	// Получение граничных значений для построения дерева
	VectorType *hrect = get_hrect((VectorType *)wm->memory,wm->count,tree->k);
	uint16_t i = 0;
	Bool resize = FALSE;
	// Проверка минимальных значений
	for (; i < tree->k; i++)
		if (hrect[i] < tree->hrect[i])
		{
			resize = TRUE;
			break;
		}	
	// Проверка максимальных значений
	if (!resize)
		for (; i < 2 * tree->k; i++)
			if (hrect[i] > tree->hrect[i])
			{
				resize = TRUE;
				break;
			}
	// Если надо перераспределить элементы
	if (resize)
	{
		// Создание временного дерева
		KDTree *temp_tree = (KDTree *)malloc(sizeof(KDTree));
		temp_tree->k = tree->k;
		temp_tree->root = create_kdnode(hrect, 0, tree->k, tree->depth);
		add_from_memore(temp_tree, wm);  // Добавление новых данных		
		save_kdtree_to_memory(wm, tree); // Получение данных из старого дерева
		add_from_memore(temp_tree, wm);  // Дополнение старыми данными
		// Очистка старого дерева
		free_kdnode(tree->root);
		free(tree->hrect);
		// Копирование данных в старое дерево
		tree->root = temp_tree->root;
		tree->hrect = hrect;
		free(temp_tree);
	}
	else
	{
		// Просто дополняем
		add_from_memore(tree, wm);
	}
	reset_memory(wm);
}

void save_kdtree_to_memory(WorkingMemory *wm, const KDTree *tree)
{
	reset_memory(wm);
	save_kdnode_to_memory(wm, tree->root, tree->k);
}

void free_kdnode(KDNode *node)
{
	if (node->is_leaf)
	{
		free(node->left);
		free(node->right);
		node->left = NULL;
		node->right = NULL;
	}
	else
	{
		if (node->left != NULL)
			free_kdnode(node->left);
		if (node->right != NULL)
			free_kdnode(node->right);
	}
	free(node);
	node = NULL;
}

void compress_kdtree(KDTree *tree)
{
	compress_kdnode(tree->root, tree->k);
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

uint32_t xorshift128()
{
	// Инициализация любыми значениями
	static uint32_t x = 1795, y = 12345, z = 9876, w = 1243;
	// Реализация генерации
	uint32_t t = x^(x << 11);
	x = y; y = z; z = w;
	w = (w^(w >> 19))^(t^(t >> 8));
	return w;
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
	// Сравнение с детекторами
	if (pat != NULL)
	{
		// Проверка, что детекторы не реагируют на данный шаблон
		char *det = det_db->memory;
		for (uint32_t j = 0; j < det_db->count; j++)
			if (hamming_distance(det, pat) < affinity)
			{
				if (!replace_detector(det))
				{
					ZeroMemory(det, pat_length); // Обнуление значения
					print_errlog("Failed to update detector!");
				}
			}
			else
				det += pat_length;
	}
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

Bool replace_detector(char *det)
{
	char *temp = det;
	uint8_t attempt = 0;
	do
	{
		uint8_t i = 0;
		det = temp;
		// Заполнение детектора случайными значениями
		for (; i < pat_length; i += sizeof(uint32_t))
		{
			uint32_t xs128 = xorshift128();
			memcpy(det, &xs128, sizeof(uint32_t));
			det += sizeof(uint32_t);
		}
		if (i < pat_length)
		{
			i = pat_length - i;
			uint32_t xs128 = xorshift128();
			memcpy(det, &xs128, i);
			det += i;
		}
		// Приведение числа к диапазону при 70%
		for (i = 0; i < pat_length; i++)
		{
			uint8_t p = time(NULL);
			if (p < 0.7 * UINT8_MAX)
				det[i] = det[i] % 94 + 32;
		}
		// Проверка, что детектор не похож на шаблоны нормального поведения
		char *pat = pat_db->memory;
		for (uint32_t j = 0; j < pat_db->count; j++)
			if (hamming_distance(det, pat) < affinity)
			{
				temp = NULL;
				break;				
			}
			else
				pat += pat_length;
		attempt++;
	}
	while(det != NULL && attempt < UINT8_MAX);
	return det != NULL;
}

void generate_detector()
{
	// Если место имеется
	if (det_db->count < det_db->max_count)
	{
		// Временное хранилище для детектора
		char *det = (char *)malloc(pat_length);
		// Добавление, если есть место и детектор уникален
		if (det_db->count < det_db->max_count && replace_detector(det))
			add_to_memory(det_db, det);
		free(det);
	}
}

void add_from_memore(KDTree *tree, const WorkingMemory *wm)
{
	const VectorType *p = (VectorType *)wm->memory;
	for (uint32_t i = 0; i < wm->count; i++)
	{
		add_in_kdtree(tree, p);
		p += tree->k;
	}
}

void save_kdnode_to_memory(WorkingMemory *wm, const KDNode *node, uint8_t k)
{
	if (node != NULL)
	{
		if (node->is_leaf)
		{
			// В узлах листьев запакованы нужные вектора
			if (node->left != NULL)
			{
				char *min = (char *)node->left;
				char *max = (char *)node->right;
				add_to_memory(wm, min);
				if (memcmp(min, max, wm->size) != 0)
					add_to_memory(wm, max);
			}
		}
		else
		{
			save_kdnode_to_memory(wm, node->left, k);
			save_kdnode_to_memory(wm, node->right, k);
		}
	}
}

VectorType *compress_kdnode(KDNode *node, uint8_t k)
{	
	// Отправка запакованных векторов для листьев
	if (node->is_leaf)
		return (VectorType *)node->left;
	// Получение результатов с двух узлов
	VectorType *left_hrect, *right_hrect;
	left_hrect = compress_kdnode(node->left, k);
	right_hrect = compress_kdnode(node->right, k);
	// Очистка пустых узлов
	if (left_hrect == NULL)
		node->left = NULL;
	if (right_hrect == NULL)
		node->right = NULL;
	// Если оба пустые, то "объединяем", удалив узел
	if (node->left == node->right)
	{
		free(node);
		node = NULL;
	}
	// Проверяем, что не равны указателям и имеют одну размерность
	else if ((KDNode *)left_hrect != node->left
		&& (KDNode *)right_hrect != node->right
		&& node->left->i == node->right->i)
	{
		VectorType l_max = *(left_hrect + k + node->left->i);
		VectorType r_min = *(right_hrect + node->right->i);
		VectorType dist;
		if (r_min > l_max)
			dist = r_min - l_max;
		else
			dist = l_max - r_min;
		if (dist < 4)
		{
			uint8_t i = 0;
			// Сравнение min
			for (; i < k; i++)
				if (right_hrect[i] < left_hrect[i])
					left_hrect[i] = right_hrect[i];
			// Сравнение max
			for (; i < 2 * k; i++)
				if (right_hrect[i] > left_hrect[i])
					left_hrect[i] = right_hrect[i];		
			// Освобождение ресурсов
			free(right_hrect);
			free(node->left);
			free(node->right);
			// Упаковка результатов
			node->left = (KDNode *)left_hrect;
			node->right = (KDNode *)(left_hrect + k);
			// Отметка как лист
			node->is_leaf = TRUE;
			return left_hrect;	
		}
	}
	return (VectorType *)node;
}

void commit_and_reset_statistics()
{
	print_msglog("Memory has been reset");
	ZeroMemory(stat_db->memory, stat_db->max_count * sizeof(NBStats));
	reset_memory(stat_db);
}