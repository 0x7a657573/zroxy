/*
 * SniClient.c
 *
 *  Created on: Jan 29, 2020
 *      Author: zeus
 *
 * The connection cap defaults to 1024 and is set once at startup with
 * sni_conn_set_limit. Those slots are connections on the listener event
 * loop, not pthreads. Under SNI_TEST_HOOKS the file also has sni_client_handler,
 * which drives one connection on the calling thread through the same state
 * machine.
 */
#include <stdlib.h>
#include <pthread.h>
#include "sniclient.h"
#include "sni_event_loop.h"

static pthread_mutex_t sni_conn_mu = PTHREAD_MUTEX_INITIALIZER;
static int sni_conns = 0;
static int sni_conn_max = SNI_CONN_LIMIT_DEFAULT;

bool sni_conn_acquire(void)
{
	bool ok = false;
	pthread_mutex_lock(&sni_conn_mu);
	if (sni_conns < sni_conn_max)
	{
		sni_conns++;
		ok = true;
	}
	pthread_mutex_unlock(&sni_conn_mu);
	return ok;
}

int sni_conn_limit(void)
{
	int limit;
	pthread_mutex_lock(&sni_conn_mu);
	limit = sni_conn_max;
	pthread_mutex_unlock(&sni_conn_mu);
	return limit;
}

void sni_conn_set_limit(int limit)
{
	if (limit < 1)
		limit = 1;
	if (limit > SNI_CONN_LIMIT_MAX)
		limit = SNI_CONN_LIMIT_MAX;
	pthread_mutex_lock(&sni_conn_mu);
	sni_conn_max = limit;
	pthread_mutex_unlock(&sni_conn_mu);
}

void sni_conn_release(void)
{
	pthread_mutex_lock(&sni_conn_mu);
	if (sni_conns > 0)
		sni_conns--;
	pthread_mutex_unlock(&sni_conn_mu);
}

#ifdef SNI_TEST_HOOKS
void *sni_client_handler(void *arg)
{
	sniclient_t *client = (sniclient_t *)arg;
	if (!client)
		return NULL;
	sni_connection_run(client);
	sni_conn_release();
	free(client);
	return NULL;
}
#endif /* SNI_TEST_HOOKS */
