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

static zroxy_t settings = {0};

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
	void (*reload)(void *handle); /* NULL when SIGHUP means nothing to it */
} service_t;

static void reload_whitelist(void *h) { filter_reload(h); }
static void stop_monitor(void *h) { monitor_stop(h); }
static void stop_whitelist(void *h) { filter_free(h); }
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
	statistics_t *sni_stats = NULL;
	statistics_t *dns_stats = NULL;
	sni_server_t sni_cfg;

	memset(&ignore_pipe, 0, sizeof(ignore_pipe));
	ignore_pipe.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &ignore_pipe, NULL);

	/* before any thread exists, so all of them inherit the mask */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);

	bool args_ok = args_init(&settings, argc, argv);
	args_scrub_argv();
	if (args_ok == false)
	{
		args_print_usage();
		return 1;
	}
	if (!args_validate(&settings))
	{
		args_print_usage();
		return 1;
	}

	for (lport_t *p = settings.ports; p; p = p->next)
		listener_count++;
	/*
	 * Raise the open-file limit before any socket is made. A limit that stays
	 * too low only lowers the SNI cap; it never stops startup.
	 */
	if (listener_count > 0)
	{
		fdlimit_plan plan = {
		        .sni_conns = settings.snimaxconn,
		        .sni_listeners = (int)listener_count,
		        .dns_enabled = settings.dnsserver != NULL,
		        .dns_upstreams = settings.dnsserver ? settings.dnsserver->upstream_connections : 0,
		        .monitor_enabled = settings.monitor_port != 0};
		int cap = settings.snimaxconn;
		unsigned long soft = fdlimit_apply(&plan, &cap);
		if (cap < settings.snimaxconn)
			log_warn("open-file limit %lu serves only %d SNI connections, not the configured %d; raise LimitNOFILE or ulimit -n",
			        soft, cap, settings.snimaxconn);
		settings.snimaxconn = cap;
	}

	/* whitelist, monitor, DNS and one entry per SNI listener */
	services = calloc(listener_count + 3, sizeof(*services));
	if (!services)
	{
		log_error("service list allocation failed");
		goto out;
	}

	/*check white list before listeners so a bad file does not become an open proxy*/
	if (settings.whitelist_path)
	{
		log_info("load white list from %s", settings.whitelist_path);
		whitelist = filter_init(settings.whitelist_path);
		free(settings.whitelist_path);
		settings.whitelist_path = NULL;
		if (!whitelist)
		{
			log_error("whitelist load failed");
			goto out;
		}
		service_add(services, &service_count, &(service_t){"whitelist", whitelist, stop_whitelist, reload_whitelist});
	}

	/*check Monitor*/
	if (settings.monitor_port)
	{
		const char *bind_ip = settings.monitor_bind[0] ? settings.monitor_bind : "127.0.0.1";
		log_info("enable monitor on %s:%i", bind_ip, settings.monitor_port);
		monitor = monitor_init(settings.monitor_port, bind_ip, settings.monitor_token, settings.monitor_header_timeout);
		args_free_monitor_token(&settings); /*monitor keeps its own copy*/
		if (!monitor)
		{
			log_error("monitor failed to start");
			goto out;
		}
		service_add(services, &service_count, &(service_t){"monitor", monitor, stop_monitor, NULL});
	}

	if (monitor && whitelist)
	{
		if (!monitor_add_section(monitor, "Whitelist", filter_stats_json, whitelist))
			log_error("monitor whitelist section failed");
	}

	if (monitor)
	{
		if (!monitor_add_section(monitor, "Resolver", resolver_stats_json, NULL))
			log_error("monitor resolver section failed");
	}

	/*check for dns server*/
	if (settings.dnsserver)
	{
		stats_init(&dns_stats, "DNS_Server");
		if (monitor)
		{
			if (!monitor_add_section(monitor, dns_stats->name, stats_json, dns_stats))
				log_error("monitor DNS statistics section failed");
		}
		settings.dnsserver->stats = dns_stats;

		settings.dnsserver->whitelist = whitelist;

		log_info("start dns server ...");
		dns = dnsserver_start(settings.dnsserver);
		if (!dns)
		{
			log_error("dns server failed to start");
			goto out;
		}
		service_add(services, &service_count, &(service_t){"dns", dns, stop_dns, NULL});
	}

	if (listener_count > 0 || monitor)
	{
		stats_init(&sni_stats, "SNI_Server");
		if (monitor)
		{
			stats_set_extra(sni_stats, sni_stats_json, NULL);
			if (!monitor_add_section(monitor, sni_stats->name, stats_json, sni_stats))
				log_error("monitor SNI statistics section failed");
		}
	}

	sni_conn_set_limit(settings.snimaxconn);
	memset(&sni_cfg, 0, sizeof(sni_cfg));
	sni_cfg.stats = sni_stats;
	sni_cfg.whitelist = whitelist;
	sni_cfg.snitimeout = settings.snitimeout;
	sni_cfg.sniidletimeout = settings.sniidletimeout;
	sni_cfg.allow_loopback = settings.allow_loopback;
	sni_cfg.deny_private = settings.deny_private;
	sni_cfg.acl = settings.sacl;
	sni_cfg.acl_count = settings.sacl_count;
	/*if Set socks proxy*/
	if (settings.socks)
	{
		log_info("enable socks on %s:%i", settings.socks->host, settings.socks->port);
		sni_cfg.socks = settings.socks;
	}

	for (lport_t *p = settings.ports; p; p = p->next)
	{
		sni_listener *ls;
		sni_cfg.port = *p;
		ls = sniproxy_start(&sni_cfg);
		if (!ls)
		{
			log_error("sni listener failed on %s:%u", sni_cfg.port.bindip, (unsigned)sni_cfg.port.local_port);
			goto out;
		}
		service_add(services, &service_count, &(service_t){"sni", ls, stop_sni, NULL});
	}
	args_free_ports(&settings); /*free port List*/

	/*
	 * Everything that needs root is done: the sockets are bound and the
	 * config, whitelist and secret files are read. The threads already
	 * run; priv_drop checks that each one took the change.
	 */
	if (settings.drop_priv)
	{
		if (!priv_drop(settings.drop_uid, settings.drop_gid))
		{
			log_error("can not drop privileges to %s", settings.run_user);
			goto out;
		}
		log_info("running as %s (uid %lu)", settings.run_user, (unsigned long)settings.drop_uid);
	}
	priv_harden(settings.drop_priv);

	log_info("shutting down on signal %d", wait_for_shutdown(&sigs, services, service_count));
	rc = 0;

out:
	/* reverse start order: SNI and DNS first, then the monitor, then the whitelist */
	services_stop(services, &service_count);
	stats_free(sni_stats);
	stats_free(dns_stats);
	free(services);
	args_free(&settings);
	if (rc == 0)
		log_info("zroxy stopped");
	return rc;
}
