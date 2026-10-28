/*
 * loglock.c
 *
 *  Created on: Jan 30, 2020
 *      Author: zeus
 */
#include <pthread.h>
#include <zroxy/log.h>

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void lock_callback(void *udata, int lock)
{
	if (lock)
		pthread_mutex_lock(udata);
	else
		pthread_mutex_unlock(udata);
}

void log_init(void)
{
	log_set_udata(&log_mutex);
	log_set_lock(lock_callback);
}
