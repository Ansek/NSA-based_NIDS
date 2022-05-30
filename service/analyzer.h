/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __ANALYZER_H__
#define __ANALYZER_H__

#include "algorithm.h"

#define PACKAGE_DATA_SIZE sizeof(void *) * 2  // Размер PackageData без буфера 
#define PACKAGE_BUFFER_SIZE            65535  // Размер буфера пакета
#define PARAM_NBSTATISTICS_COUNT 12 // Количество параметров статистики
#define NUL_FTCP 0x00  // Нет флагов
#define FIN_FTCP 0x01  // Завершение соединение
#define SYN_FTCP 0x02  // Запрос соединения
#define RST_FTCP 0x04  // Отказ в соединении
#define PSH_FTCP 0x08  // Срочная передача пакета
#define ACK_FTCP 0x10  // Есть номер подтверждения
#define URG_FTCP 0x20  // Есть указатель важности

// Заголовок IP-пакета
typedef struct IPHeader
{
	uint8_t  ver_len;  // Версия и длина заголовка
	uint8_t  tos;      // Тип сервиса
	uint16_t length;   // Длина всего пакета (поменять байты местами)
	uint16_t id;       // Идентификатор пакета
	uint16_t offset;   // Флаги и смещения
	uint8_t  ttl;      // Время жизни пакета
	uint8_t  protocol; // Используемый протокол
	uint16_t xsum;     // Контрольная сумма
	uint32_t src;      // IP-адрес отправителя
	uint32_t dst;      // IP-адрес получателя
} IPHeader;

// Заголовок TCP протокола
typedef struct TCPHeader
{
	uint16_t src_port; // Порт отправителя
	uint16_t dst_port; // Порт получателя
	uint32_t seq_num;  // Порядковый номер
	uint32_t ask_num;  // Номер подтверждения
	uint8_t  length;   // Длина заголовка (первые 4 бита * 4 байта)
	uint8_t  flags;    // Флаги
	uint16_t win_size; // Размер окна
	uint16_t xsum;     // Контрольная сумма
	uint16_t urg;      // Указатель срочности
} TCPHeader;

// Заголовок UDP протокола
typedef struct UDPHeader
{
	uint16_t src_port; // Порт отправителя
	uint16_t dst_port; // Порт получателя
	uint16_t length;   // Длина дейтаграммы
	uint16_t xsum;     // Контрольная сумма
} UDPHeader;

// Заголовок ICMP протокола
typedef struct ICMPHeader
{
	uint8_t  type;     // 0 - ответ, 8 - запрос
	uint8_t  code;     // Код ошибки
	uint16_t xsum;     // Контрольная сумма
	uint16_t field1;   // Поля зависят от значений 
	uint16_t field2;   // type и code
} ICMPHeader;

// Список полуоткрытых соединений
typedef struct SynTCPList
{
	uint32_t  src;     // Адрес отправителя
	uint16_t count;    // Количество для данного адреса
	struct SynTCPList *next;  // Следующее соединение
} SynTCPList;

// Данные для адаптера
typedef struct AdapterData
{
	const char *addr;  // Сетевой адрес
	FID fid;           // Идентификатор на файл
	char buffer[PACKAGE_BUFFER_SIZE];  // Для хранения данных пакета
} AdapterData;

// Тип данных для перемещения по буферу AnalyzerData
typedef struct PackageData
{
	AdapterData *adapter;     // Ссылка на информацию об адаптере
	struct PackageData *next; // Следующий адрес в буфере
	IPHeader header;          // Заголовок пакета
} PackageData;

// Данные для анализатора
typedef struct AnalyzerData
{
	uint16_t id;             // Идентификатор анализатора
	PackageData *r_package;  // Указатель для чтения пакетов
	PackageData *w_package;  // Указатель для записи пакетов
	size_t pack_count;       // Количество непроверенных пакетов
	Bool lock;               // Флаг, что анализатор занят другим потоком
	Bool read;               // Флаг, что выполняется чтение
	HANDLE mutex;            // Мьютекс для ожидания чтения при записи
	char *buffer;            // Ссылка на буфер данных
} AnalyzerData;

// Кольцевой список анализаторов
typedef struct AnalyzerList
{
	AnalyzerData data;       // Данные для анализатора
	HANDLE hThread;          // Ссылка на поток
	struct AnalyzerList *next; // Следующий анализатор
} AnalyzerList;

/**
@brief Запускает процесс проверки пакетов
@param tcp_ps Список разрешенных TCP портов
@param udp_ps Список разрешенных UDP портов
*/
void run_analyzer(PList *tcp_ps, PList *udp_ps);

/**
@brief Добавляет пакет в очередь на анализ
@param data Данные о пакете
*/
void analyze_package(AdapterData *data);

/**
@brief Получение имени протокола
@param protocol Идентификатор протокола
@return Название протокола
*/
const char *get_protocol_name(const uint8_t protocol);

#endif