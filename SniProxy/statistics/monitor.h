/*
 * monitor.h
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#include <stdbool.h>
#include "statistics.h"

typedef struct
{
	int fd;
	statistics_t *state;
}mon_t;

statistics_t *monitor_Init(uint16_t *Port);

