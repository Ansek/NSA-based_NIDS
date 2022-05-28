/******************************************************************************
     * File: analyzer.h
     * Description: Проверка пакетов на аномальные данные.
     * Created: 7 мая 2021
     * Author: Секунов Александр

******************************************************************************/

#ifndef __ANALYZER_H__
#define __ANALYZER_H__

#include "filemanager.h"

#include <windows.h>
#include <time.h>

#define PACKAGE_DATA_SIZE sizeof(void *) * 2  // Размер PackageData без буфера 
#define PACKAGE_BUFFER_SIZE            65535  // Размер буфера пакета
#define PARAM_NBSTATISTICS_COUNT 12 // Количество параметров статистики
#define NUL_FTCP 0x00   // Нет флагов
#define FIN_FTCP 0x01  // Завершение соединение
#define SYN_FTCP 0x02  // Запрос соединения
#define RST_FTCP 0x04  // Отказ в соединении
#define PSH_FTCP 0x08  // Срочная передача пакета
#define ACK_FTCP 0x10   // Есть номер подтрвеждения
#define URG_FTCP 0x20   // Есть указатель важности

// Заголовок IP-пакета
typedef struct IPHeader
{
	unsigned char	ver_len;	// Версия и длина заголовка
	unsigned char	tos;		// Тип сервиса
	unsigned short	length;		// Длина всего пакета (поменять байты местами)
	unsigned short	id;			// Идентификатор пакета
	unsigned short	offset;		// Флаги и смещения
	unsigned char	ttl;		// Время жизни пакета
	unsigned char	protocol;	// Используемый протокол
	unsigned short	xsum;		// Контрольная сумма
	unsigned long	src;		// IP-адрес отправителя
	unsigned long	dst;		// IP-адрес получателя
} IPHeader;

// Заголовок TCP протокола
typedef struct TCPHeader
{
	unsigned short	src_port;   // Порт отправителя
	unsigned short	dst_port;   // Порт получателя
	unsigned long	seq_num;    // Порядковый номер
	unsigned long	ask_num;    // Номер подтрвеждения
	unsigned char	length;     // Длина заголовка (первые 4 бита * 4 байта)
	unsigned char	flags;      // Флаги
	unsigned short	win_size;   // Размер окна
	unsigned short	xsum;       // Контрольная сумма
	unsigned short	urg;	    // Указатель срочности
} TCPHeader;

// Заголовок UDP протокола
typedef struct UDPHeader
{
	unsigned short	src_port;   // Порт отправителя
	unsigned short	dst_port;   // Порт получателя
	unsigned short	length;     // Длина дейтаграммы
	unsigned short	xsum;       // Контрольная сумма
} UDPHeader;

// Заголовок ICMP протокола
typedef struct ICMPHeader
{
	unsigned char	type;       // 0 - ответ, 8 - запрос
	unsigned char	code;       // Код ошибки
	unsigned short	xsum;       // Контрольная сумма
	unsigned short	field1;     // Поля зависят от значений 
	unsigned short	field2;     // type и code
} ICMPHeader;

// Статистика поведения сети
typedef struct NBStatistics
{
	unsigned short tcp_count;          // Общее количество пакетов TCP
	unsigned short udp_count;          // Общее количество пакетов UDP
	unsigned short icmp_count;         // Общее количество пакетов ICMP
	unsigned short ip_count;           // Общее количество пакетов других протоколов
	unsigned short syn_count;          // Количество полуоткрытых соединений TCP 
	unsigned short ask_sa_count;       // Количество открытых соединений TCP (ASK после SYN+ASK)
	unsigned short fin_count;          // Количество закрытых соединений TCP
	unsigned short rst_count;          // Количество сброшенных соединений TCP
	unsigned short al_tcp_port_count;  // Количество обращений к разрешенным портам TCP
	unsigned short un_tcp_port_count;  // Количество обращений к неразрешенным портам TCP
	unsigned short al_udp_port_count;  // Количество обращений к разрешенным портам UDP
	unsigned short un_udp_port_count;  // Количество обращений к неразрешенным портам UDP
} NBStatistics;

// Список статистик
typedef struct NBStatisticsList
{
	NBStatistics stat;                 // Статистика за данный период
	struct NBStatisticsList *next;     // Следующий статистика
} NBStatisticsList;

// Список полуоткрытых соединий
typedef struct SynTCPList
{
	unsigned long  src;                 // Адрес отправителя
	unsigned short count;				// Количество для данного адреса
	struct SynTCPList *next;     		// Следующее соединение
} SynTCPList;

// Данные для адаптера
typedef struct AdapterData
{
	char *addr; 						// Сетевой адрес
	FID fid;							// Идентификатор на файл
	char buffer[PACKAGE_BUFFER_SIZE]; 	// Для хранения данных пакета
} AdapterData;

// Тип данных для перемещения по буферу AnalyzerData
typedef struct PackageData
{
	AdapterData *adapter;		// Ссылка на информацию об адаптере
	struct PackageData *next; 	// Следующий адрес в буфере
	IPHeader header;			// Заголовок пакета
} PackageData;

// Данные для анализатора
typedef struct AnalyzerData
{
	unsigned short id;			// Идентификатор анализатора
	PackageData *r_package;		// Указатель для чтения пакетов
	PackageData *w_package;		// Указатель для записи пакетов
	size_t pack_count; 			// Количество непроверенных пакетов	
	Bool lock; 					// Флаг, что анализатор занят другим потоком
	Bool read;					// Флаг, что выполняется чтение
	HANDLE mutex;				// Мьютекс для ожидания чтения при записи
	char *buffer;				// Ссылка на буфер данных
} AnalyzerData;

// Кольцевой список анализаторов
typedef struct AnalyzerList
{
	AnalyzerData data;			// Данные для анализатора
	HANDLE hThread;				// Ссылка на поток
	struct AnalyzerList *next;	// Следующий анализатор
} AnalyzerList;

// Список промежутков, когда надо сохранять файл детекторов
typedef struct SavePeriodsList
{
	int period;						// Время между записью в файл (минуты)
	struct SavePeriodsList* next;	// Следующее время ожидания
} SavePeriodsList;

// Для фиксирования времени обучения
typedef struct TimeData
{
	size_t days;			// Дни
	unsigned char hours;	// Часы
	unsigned char minutes;	// Минуты
} TimeData;

/**
@brief Запускает процесс проверки пакетов
*/
void run_analyzer();

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
char *get_protocol_name(const unsigned char protocol);

/**
@brief Получение имени протокола
@param fid Идентификатор на лог статистики
*/
void set_fid_stat(FID fid);

/**
@brief Добавляет порт в список TCP
@param hport Порт в формате хоста
*/
void add_tcp_port(unsigned short hport);

// 
/**
@brief Добавляет порт в список UDP
@param hport Порт в формате хоста
*/
void add_udp_port(unsigned short hport);

#endif