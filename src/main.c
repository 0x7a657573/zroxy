/*
 ============================================================================
 Name        : Zroxy.c
 Author      : Zeus
 Version     :
 Copyright   : Copyright 2020 Mohammad Mazarei This program is free software
 Description : simple and smart sni-proxy.
 ============================================================================
 */
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <zroxy/log.h>
#include <zroxy/sniproxy.h>
#include <zroxy/monitor.h>
#include <zroxy/filter.h>
#include <zroxy/dnsproxy.h>
#include <zroxy/args.h>

static zroxy_t prg_setting = {0};

/*
 * Block until SIGINT or SIGTERM. SIGHUP reloads the whitelist.
 * The signals are blocked in every thread, so only this sigwait sees them.
 */
static int wait_for_shutdown(const sigset_t *sigs, filter_t *whitelist)
{
	for (;;)
	{
		int sig = 0;
		if (sigwait(sigs, &sig) != 0)
			continue;
		if (sig == SIGHUP)
		{
			if (whitelist)
				filter_reload(whitelist);
			else
				log_info("SIGHUP ignored: no whitelist configured");
			continue;
		}
		return sig;
	}
}

int main(int argc, const char **argv)
{
	struct sigaction ignore_pipe;
	sigset_t sigs;
	int rc = 1;
	mon_t *monitor = NULL;
	filter_t *whitelist = NULL;
	struct dnsserver *dns = NULL;
	sni_listener **listeners = NULL;
	size_t listener_count = 0;
	size_t i = 0;
	statistics_t *SniStat = NULL;
	SniServer_t Xconf;

	log_init();
	memset(&ignore_pipe, 0, sizeof(ignore_pipe));
	ignore_pipe.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &ignore_pipe, NULL);

	/* before any thread exists, so all of them inherit the mask */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);

	if(args_init(&prg_setting,argc,argv)==false)
	{
		args_print_usage();
		return 1;
	}
	if (!args_validate(&prg_setting))
	{
		args_print_usage();
		return 1;
	}

	/*check white list before listeners so a bad file does not become an open proxy*/
	if(prg_setting.WhitePath)
	{
		log_info("load white list from %s",prg_setting.WhitePath);
		whitelist = filter_init(prg_setting.WhitePath);
		free(prg_setting.WhitePath);
		prg_setting.WhitePath = NULL;
		if (!whitelist)
		{
			log_error("whitelist load failed");
			goto out;
		}
	}

	/*check Monitor*/
	if(prg_setting.monitorPort)
	{
		const char *bind_ip = prg_setting.monitor_bind[0] ? prg_setting.monitor_bind : "127.0.0.1";
		log_info("enable monitor on %s:%i", bind_ip, *prg_setting.monitorPort);
		monitor = monitor_init(*prg_setting.monitorPort, bind_ip, prg_setting.monitor_token, prg_setting.monitor_header_timeout);
		if (!monitor)
		{
			log_error("monitor failed to start");
			goto out;
		}
	}

	/*check for dns server*/
	if(prg_setting.dnsserver)
	{
		if(monitor)
			prg_setting.dnsserver->Stat = monitor_add_stat(monitor,"DNS_Server");

		prg_setting.dnsserver->whitelist = whitelist;

		log_info("start dns server ...");
		dns = dnsserver_start(prg_setting.dnsserver);
		if (!dns)
		{
			log_error("dns server failed to start");
			goto out;
		}
	}

	if(monitor)
		SniStat = monitor_add_stat(monitor,"SNI_Server");

	memset(&Xconf, 0, sizeof(Xconf));
	Xconf.sta = SniStat;
	Xconf.wlist = whitelist;
	Xconf.snitimeout = prg_setting.snitimeout;
	/*if Set Socks proxy*/
	if(prg_setting.socks)
	{
		log_info("enable socks on %s:%i",prg_setting.socks->host,prg_setting.socks->port);
		Xconf.Socks = prg_setting.socks;
	}

	for (lport_t *p = prg_setting.ports; p; p = p->next)
		listener_count++;
	if (listener_count)
	{
		listeners = calloc(listener_count, sizeof(*listeners));
		if (!listeners)
		{
			log_error("listener allocation failed");
			listener_count = 0;
			goto out;
		}
	}

	for (lport_t *p = prg_setting.ports; p; p = p->next, i++)
	{
		Xconf.Port = *p;
		listeners[i] = sniproxy_start(&Xconf);
		if (!listeners[i])
		{
			log_error("sni listener failed on %s:%u", Xconf.Port.bindip, (unsigned)Xconf.Port.local_port);
			goto out;
		}
	}
	args_free_ports(&prg_setting); /*free Port List*/

	log_info("shutting down on signal %d", wait_for_shutdown(&sigs, whitelist));
	rc = 0;

out:
	/*
	 * Stop the data paths. The monitor and whitelist watcher stay up until
	 * exit: they only read shared state and own nothing that needs flushing.
	 */
	for (i = 0; i < listener_count; i++)
		sniproxy_stop(listeners ? listeners[i] : NULL);
	free(listeners);
	dnsserver_stop(dns);
	args_free_ports(&prg_setting);
	args_free_dns(&prg_setting);
	if (rc == 0)
		log_info("zroxy stopped");
	return rc;
}
