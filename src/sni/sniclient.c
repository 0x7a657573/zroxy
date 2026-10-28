/*
 * SniClient.c
 *
 *  Created on: Jan 29, 2020
 *      Author: zeus
 *
 * The connection cap is still 1024. Those slots are connections on the
 * listener event loop, not pthreads. sni_client_handler remains for tests: it
 * drives one connection on the calling thread through the same state machine.
 */
#include <stdlib.h>
#include <pthread.h>
#include "sniclient.h"
#include "sni_event_loop.h"

#define SNI_MAX_WORKERS 1024

static pthread_mutex_t sni_worker_mu = PTHREAD_MUTEX_INITIALIZER;
static int sni_workers = 0;

bool sni_worker_acquire(void)
{
	bool ok = false;
	pthread_mutex_lock(&sni_worker_mu);
	if (sni_workers < SNI_MAX_WORKERS)
	{
		sni_workers++;
		ok = true;
	}
	pthread_mutex_unlock(&sni_worker_mu);
	return ok;
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
