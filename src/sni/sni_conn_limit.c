/*
 * Copyright (c) 2020-2026 zeus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*
 *
 * Process-wide cap on SNI connections. It defaults to 1024 and is set once at
 * startup with sni_conn_set_limit. Slots are connections on the listener
 * event loop, not pthreads.
 */
#include <pthread.h>
#include <zroxy/sniproxy.h>

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
