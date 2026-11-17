/*
 ============================================================================
 Name        : Zroxy.c
 Author      : Zeus
 Version     :
 Copyright   : Copyright 2020 zeus This program is free software
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
#include <zroxy/resolver.h>
#include <zroxy/dnsserver.h>
#include <zroxy/args.h>
#include <zroxy/priv.h>
#include <zroxy/fdlimit.h>

static zroxy_t prg_setting = {0};

/*
 * A running service. main pushes one as each service starts and stops them
 * in reverse order, so a service is never stopped before the ones using it
 * (the monitor reads the statistics of SNI and DNS and the whitelist).
 */
typedef struct
{
	const char *name;
	void *handle;
	void (*stop)(void *handle);
	void (*reload)(void *handle);	/* NULL when SIGHUP means nothing to it */
}service_t;

static bool monitor_clean = true;	/* false when monitor_stop gave up on its workers */
static void reload_whitelist(void *h) { filter_reload(h); }
static void stop_monitor(void *h) { monitor_clean = monitor_stop(h); }
static void stop_whitelist(void *h)
{
	/* the monitor's Whitelist section may still run in a worker that never finished */
	if (!monitor_clean)
	{
		log_warn("whitelist left allocated: monitor clients are still running");
		return;
	}
	filter_free(h);
}
static void stop_dns(void *h) { dnsserver_stop(h); }
static void stop_sni(void *h) { sniproxy_stop(h); }

static void service_add(service_t *list, size_t *count, const service_t *svc)
{
	list[(*count)++] = *svc;
}

static void services_stop(service_t *list, size_t *count)
{
	while (*count > 0)
	{
		service_t *svc = &list[--*count];
		log_info("stopping %s", svc->name);
		svc->stop(svc->handle);
	}
}

/*
 * Block until SIGINT or SIGTERM. SIGHUP reloads the services that can.
 * The signals are blocked in every thread, so only this sigwait sees them.
 */
static int wait_for_shutdown(const sigset_t *sigs, const service_t *list, size_t count)
{
	for (;;)
	{
		int sig = 0;
		if (sigwait(sigs, &sig) != 0)
			continue;
		if (sig == SIGHUP)
		{
			bool any = false;
			for (size_t k = 0; k < count; k++)
			{
				if (list[k].reload)
				{
					list[k].reload(list[k].handle);
					any = true;
				}
			}
			if (!any)
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
	service_t *services = NULL;
	size_t service_count = 0;
	size_t listener_count = 0;
	statistics_t *SniStat = NULL;
	statistics_t *DnsStat = NULL;
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

	bool args_ok = args_init(&prg_setting,argc,argv);
	args_scrub_argv();
	if(args_ok==false)
	{
		args_print_usage();
		return 1;
	}
	if (!args_validate(&prg_setting))
	{
		args_print_usage();
		return 1;
	}

	for (lport_t *p = prg_setting.ports; p; p = p->next)
		listener_count++;
	/*
	 * Raise the open-file limit before any socket is made. A limit that stays
	 * too low only lowers the SNI cap; it never stops startup.
	 */
	if (listener_count > 0)
	{
		fdlimit_plan plan = {
			.sni_conns = prg_setting.snimaxconn,
			.sni_listeners = (int)listener_count,
			.dns_enabled = prg_setting.dnsserver != NULL,
			.dns_upstreams = prg_setting.dnsserver ? prg_setting.dnsserver->upstream_connections : 0,
			.monitor_enabled = prg_setting.monitorPort != NULL
		};
		int cap = prg_setting.snimaxconn;
		unsigned long soft = fdlimit_apply(&plan, &cap);
		if (cap < prg_setting.snimaxconn)
			log_warn("open-file limit %lu serves only %d SNI connections, not the configured %d; raise LimitNOFILE or ulimit -n",
				soft, cap, prg_setting.snimaxconn);
		prg_setting.snimaxconn = cap;
	}

	/* whitelist, monitor, DNS and one entry per SNI listener */
	services = calloc(listener_count + 3, sizeof(*services));
	if (!services)
	{
		log_error("service list allocation failed");
		goto out;
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
		service_add(services, &service_count, &(service_t){ "whitelist", whitelist, stop_whitelist, reload_whitelist });
	}

	/*check Monitor*/
	if(prg_setting.monitorPort)
	{
		const char *bind_ip = prg_setting.monitor_bind[0] ? prg_setting.monitor_bind : "127.0.0.1";
		log_info("enable monitor on %s:%i", bind_ip, *prg_setting.monitorPort);
		monitor = monitor_init(*prg_setting.monitorPort, bind_ip, prg_setting.monitor_token, prg_setting.monitor_header_timeout);
		args_free_monitor_token(&prg_setting); /*monitor keeps its own copy*/
		if (!monitor)
		{
			log_error("monitor failed to start");
			goto out;
		}
		service_add(services, &service_count, &(service_t){ "monitor", monitor, stop_monitor, NULL });
	}

	if(monitor && whitelist)
	{
		if (!monitor_add_section(monitor, "Whitelist", filter_stats_json, whitelist))
			log_error("monitor whitelist section failed");
	}

	if(monitor)
	{
		if (!monitor_add_section(monitor, "Resolver", resolver_stats_json, NULL))
			log_error("monitor resolver section failed");
	}

	/*check for dns server*/
	if(prg_setting.dnsserver)
	{
		stats_init(&DnsStat,"DNS_Server");
		if(monitor)
			monitor_attach_stat(monitor,DnsStat);
		prg_setting.dnsserver->Stat = DnsStat;

		prg_setting.dnsserver->whitelist = whitelist;

		log_info("start dns server ...");
		dns = dnsserver_start(prg_setting.dnsserver);
		if (!dns)
		{
			log_error("dns server failed to start");
			goto out;
		}
		service_add(services, &service_count, &(service_t){ "dns", dns, stop_dns, NULL });
	}

	if(listener_count > 0 || monitor)
	{
		stats_init(&SniStat,"SNI_Server");
		if(monitor)
		{
			monitor_attach_stat(monitor,SniStat);
			stats_set_extra(SniStat, sni_stats_json, NULL);
		}
	}

	sni_worker_set_limit(prg_setting.snimaxconn);
	memset(&Xconf, 0, sizeof(Xconf));
	Xconf.sta = SniStat;
	Xconf.wlist = whitelist;
	Xconf.snitimeout = prg_setting.snitimeout;
	Xconf.sniidletimeout = prg_setting.sniidletimeout;
	Xconf.allow_loopback = prg_setting.allow_loopback;
	Xconf.deny_private = prg_setting.deny_private;
	Xconf.acl = prg_setting.sacl;
	Xconf.acl_count = prg_setting.sacl_count;
	/*if Set Socks proxy*/
	if(prg_setting.socks)
	{
		log_info("enable socks on %s:%i",prg_setting.socks->host,prg_setting.socks->port);
		Xconf.Socks = prg_setting.socks;
	}

	for (lport_t *p = prg_setting.ports; p; p = p->next)
	{
		sni_listener *ls;
		Xconf.Port = *p;
		ls = sniproxy_start(&Xconf);
		if (!ls)
		{
			log_error("sni listener failed on %s:%u", Xconf.Port.bindip, (unsigned)Xconf.Port.local_port);
			goto out;
		}
		service_add(services, &service_count, &(service_t){ "sni", ls, stop_sni, NULL });
	}
	args_free_ports(&prg_setting); /*free Port List*/

	/*
	 * Everything that needs root is done: the sockets are bound and the
	 * config, whitelist and secret files are read. The threads already
	 * run; priv_drop checks that each one took the change.
	 */
	if (prg_setting.drop_priv)
	{
		if (!priv_drop(prg_setting.drop_uid, prg_setting.drop_gid))
		{
			log_error("can not drop privileges to %s", prg_setting.run_user);
			goto out;
		}
		log_info("running as %s (uid %lu)", prg_setting.run_user, (unsigned long)prg_setting.drop_uid);
	}
	priv_harden(prg_setting.drop_priv);

	log_info("shutting down on signal %d", wait_for_shutdown(&sigs, services, service_count));
	rc = 0;

out:
	/* reverse start order: SNI and DNS first, then the monitor, then the whitelist */
	services_stop(services, &service_count);
	/* a monitor that gave up may still read them from a worker */
	if (monitor_clean)
	{
		stats_free(SniStat);
		stats_free(DnsStat);
	}
	free(services);
	args_free_ports(&prg_setting);
	args_free_dns(&prg_setting);
	args_free_socks(&prg_setting);
	args_free_sacl(&prg_setting);
	args_free_monitor_token(&prg_setting);
	free(prg_setting.run_user);
	free(prg_setting.run_group);
	if (rc == 0)
		log_info("zroxy stopped");
	return rc;
}
