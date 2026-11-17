/*
 * SniClient.c
 *
 *  Created on: Jan 29, 2020
 *      Author: zeus
 *
 * The connection cap defaults to 1024 and is set once at startup with
 * sni_worker_set_limit. Those slots are connections on the listener event
 * loop, not pthreads. sni_client_handler remains for tests: it
 * drives one connection on the calling thread through the same state machine.
 */
#include <stdlib.h>
#include <pthread.h>
#include "sniclient.h"
#include "sni_event_loop.h"

static pthread_mutex_t sni_worker_mu = PTHREAD_MUTEX_INITIALIZER;
static int sni_workers = 0;
static int sni_max_workers = SNI_CONN_LIMIT_DEFAULT;

bool sni_worker_acquire(void)
{
	bool ok = false;
	pthread_mutex_lock(&sni_worker_mu);
	if (sni_workers < sni_max_workers)
	{
		sni_workers++;
		ok = true;
	}
	pthread_mutex_unlock(&sni_worker_mu);
	return ok;
}

int sni_worker_limit(void)
{
	int limit;
	pthread_mutex_lock(&sni_worker_mu);
	limit = sni_max_workers;
	pthread_mutex_unlock(&sni_worker_mu);
	return limit;
}

void sni_worker_set_limit(int limit)
{
	if (limit < 1)
		limit = 1;
	if (limit > SNI_CONN_LIMIT_MAX)
		limit = SNI_CONN_LIMIT_MAX;
	pthread_mutex_lock(&sni_worker_mu);
	sni_max_workers = limit;
	pthread_mutex_unlock(&sni_worker_mu);
}

void sni_worker_release(void)
{
	pthread_mutex_lock(&sni_worker_mu);
	if (sni_workers > 0)
		sni_workers--;
	pthread_mutex_unlock(&sni_worker_mu);
}

void *sni_client_handler(void *arg)
{
	sniclient_t *client = (sniclient_t *)arg;
	if (!client)
		return NULL;
	sni_connection_run(client);
	sni_worker_release();
	free(client);
	return NULL;
}
