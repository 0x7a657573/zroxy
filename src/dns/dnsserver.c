/*
 * DnsServer.c
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */
#include <zroxy/dnsserver.h>

#include <zroxy/log.h>
#include <unistd.h>  	/*Header file for sleep(). man 3 sleep for details.*/
#include <pthread.h>	/* http://www.csc.villanova.edu/~mdamian/threads/posixthreads.html */
#include <stdlib.h>
#include <zroxy/dnsproxy.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <zroxy/dns.h>

struct dns_boot
{
	dnshost_t *conf;
	bool ok;
	bool ready;
	pthread_mutex_t mu;
	pthread_cond_t cv;
};

static void dns_boot_signal(struct dns_boot *boot, bool ok)
{
	pthread_mutex_lock(&boot->mu);
	boot->ok = ok;
	boot->ready = true;
	pthread_cond_signal(&boot->cv);
	pthread_mutex_unlock(&boot->mu);
}

static void *dnsserver_HandleIncomingConnection(void *vargp)
{
	struct dns_boot *boot = (struct dns_boot *)vargp;
	dnshost_t *conf = boot->conf;
	dnsserver_t *dns;

	dns = localdns_init_config(conf);
	if(!dns)
	{
		log_error("dns server config error...");
		dns_boot_signal(boot, false);
		return NULL;
	}

	if(!localdns_init_sockets(dns))
	{
		localdns_free(dns);
		log_error("dns server socket error.");
		dns_boot_signal(boot, false);
		return NULL;
	}

	if(!localdns_start_worker(dns))
	{
		localdns_free(dns);
		log_error("dns server worker error.");
		dns_boot_signal(boot, false);
		return NULL;
	}

	dns_boot_signal(boot, true);

	log_info("dns server start on %s:%d",conf->Local.ip,conf->Local.port);

	while(1)
	{
		if(!localdns_pull(dns))
			break;
	}

	log_error("dns server crashed.");
	localdns_free(dns);
	return NULL;
}

bool dnsserver_init(dnshost_t *config)
{
	struct dns_boot boot;
	pthread_t thread_id;

	memset(&boot, 0, sizeof(boot));
	boot.conf = config;
	if (pthread_mutex_init(&boot.mu, NULL) != 0)
	{
		log_error("dns server mutex init failed");
		return false;
	}
	if (pthread_cond_init(&boot.cv, NULL) != 0)
	{
		log_error("dns server condition init failed");
		pthread_mutex_destroy(&boot.mu);
		return false;
	}
	if (pthread_create(&thread_id, NULL, dnsserver_HandleIncomingConnection, &boot) != 0)
	{
		log_error("dns server thread create failed");
		pthread_cond_destroy(&boot.cv);
		pthread_mutex_destroy(&boot.mu);
		return false;
	}
	pthread_detach(thread_id);

	pthread_mutex_lock(&boot.mu);
	while (!boot.ready)
		pthread_cond_wait(&boot.cv, &boot.mu);
	pthread_mutex_unlock(&boot.mu);

	pthread_cond_destroy(&boot.cv);
	pthread_mutex_destroy(&boot.mu);
	return boot.ok;
}
