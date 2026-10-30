#define _GNU_SOURCE

#include <zroxy/dnsproxy.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <zroxy/dns.h>
#include <zroxy/log.h>

static bool dns_stats_append(char **ptr, char *end, const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t left;

	if (!ptr || !*ptr || *ptr >= end)
		return false;
	left = (size_t)(end - *ptr);
	va_start(ap, fmt);
	n = vsnprintf(*ptr, left, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= left)
		return false;
	*ptr += n;
	return true;
}

bool dns_stats_json(void *ctx, char **ptr, char *end)
{
	dnsserver_t *dns = ctx;
	dnscache_counters cache = {0};

	if (!dns)
		return false;
	dnscache_get_counters(dns->cache, &cache);
	return dns_stats_append(ptr, end, ",\n\"CacheHits\" : %" PRIu64 ",\n"
		"\"CacheMisses\" : %" PRIu64 ",\n"
		"\"CacheShared\" : %" PRIu64 ",\n"
		"\"CacheEntries\" : %zu,\n"
		"\"CacheEvictions\" : %" PRIu64 ",\n"
		"\"QueueStaleDropped\" : 0,\n"
		"\"QueueFull\" : 0,\n"
		"\"AclDropped\" : %" PRIu32 ",\n"
		"\"RateDropped\" : %" PRIu32 ",\n"
		"\"TcpRefused\" : %" PRIu32 ",\n"
		"\"TcpActive\" : %d,\n"
		"\"QueueDropped\" : %" PRIu32 ",\n"
		"\"UpstreamTimeouts\" : %" PRIu32 ",\n"
		"\"UpstreamErrors\" : %" PRIu32 ",\n"
		"\"ActiveUpstreams\" : %" PRIu32,
		cache.hits, cache.misses, cache.shared, cache.entries, cache.evicted,
		__atomic_load_n(&dns->acl_dropped, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->rate_dropped, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->tcp_refused, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->tcp_active, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->queue_dropped, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->upstream_timeouts, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->upstream_errors, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->active_upstreams, __ATOMIC_RELAXED));
}

static void close_fd(int *fd)
{
	if (fd && *fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

bool dnsproxy_test_throttle_take(log_throttle_t *throttle, int64_t now_ms,
		int64_t interval_ms, uint32_t *dropped)
{
	uint32_t last;
	uint32_t now;
	uint32_t interval;

	if (!throttle || !dropped || interval_ms < 0)
		return false;
	*dropped = 0;
	now = (uint32_t)now_ms;
	if (now == 0)
		now = 1;
	interval = interval_ms > (int64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)interval_ms;
	for (;;) {
		last = __atomic_load_n(&throttle->last_ms, __ATOMIC_ACQUIRE);
		if (last != 0 && now - last < interval) {
			(void)__atomic_fetch_add(&throttle->suppressed, 1u, __ATOMIC_RELAXED);
			return false;
		}
		if (__atomic_compare_exchange_n(&throttle->last_ms, &last, now, false,
				__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
			*dropped = __atomic_exchange_n(&throttle->suppressed, 0u, __ATOMIC_ACQ_REL);
			return true;
		}
	}
}

dnsserver_t *localdns_init_config(dnshost_t *conf)
{
	dnsserver_t *dns;

	if (!conf)
		return NULL;
	dns = calloc(1, sizeof(*dns));
	if (!dns)
		return NULL;
	dns->local_sock = -1;
	dns->tcp_sock = -1;
	dns->wake[0] = -1;
	dns->wake[1] = -1;
	if (strlen(conf->Local.ip) >= sizeof(dns->listen_addr)) {
		localdns_free(dns);
		return NULL;
	}
	memcpy(dns->listen_addr, conf->Local.ip, strlen(conf->Local.ip) + 1);
	snprintf(dns->listen_port, sizeof(dns->listen_port), "%u",
		(unsigned)conf->Local.port);
	dns->socks = conf->Socks;
	if (conf->acl_set) {
		dns->acl = malloc(conf->acl_count * sizeof(*dns->acl));
		if (!dns->acl) {
			localdns_free(dns);
			return NULL;
		}
		memcpy(dns->acl, conf->acl, conf->acl_count * sizeof(*dns->acl));
		dns->acl_count = conf->acl_count;
	} else {
		struct in_addr listen_ip;
		if (inet_pton(AF_INET, dns->listen_addr, &listen_ip) != 1 ||
				(ntohl(listen_ip.s_addr) & 0xff000000u) != 0x7f000000u) {
			static const dns_cidr_t private_acl[] = {
				{ 0x7f000000u, 0xff000000u }, { 0x0a000000u, 0xff000000u },
				{ 0xac100000u, 0xfff00000u }, { 0xc0a80000u, 0xffff0000u },
				{ 0x64400000u, 0xffc00000u },
			};
			dns->acl = malloc(sizeof(private_acl));
			if (!dns->acl) {
				localdns_free(dns);
				return NULL;
			}
			memcpy(dns->acl, private_acl, sizeof(private_acl));
			dns->acl_count = sizeof(private_acl) / sizeof(private_acl[0]);
		}
	}
	dns->rate.qps = conf->rate_qps;
	if (conf->cache_entries > 0) {
		dns->cache = dnscache_create(conf->cache_entries);
		if (!dns->cache) {
			localdns_free(dns);
			return NULL;
		}
	}
	dns->upstream = conf->Remote;
	dns->Stat = conf->Stat;
	dns->whitelist = conf->whitelist;
	memcpy(dns->sni_ip, conf->sni_ip, sizeof(dns->sni_ip));
	dns->timeout = conf->timeout;
	dns->local_ttl = conf->local_ttl;
	dns->upstream_connections = conf->upstream_connections;
	return dns;
}

void localdns_free(dnsserver_t *dns)
{
	if (!dns)
		return;
	close_fd(&dns->local_sock);
	close_fd(&dns->tcp_sock);
	close_fd(&dns->wake[0]);
	close_fd(&dns->wake[1]);
	free(dns->acl);
	dnscache_free(dns->cache);
	free(dns);
}

bool localdns_init_sockets(dnsserver_t *dns)
{
	struct sockaddr_in addr;
	char *end = NULL;
	unsigned long port;

	if (!dns)
		return false;
	dns->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (dns->local_sock < 0)
		return false;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	port = strtoul(dns->listen_port, &end, 10);
	if (dns->listen_port[0] == '\0' || !end || *end != '\0' || port > 65535UL ||
			inet_pton(AF_INET, dns->listen_addr, &addr.sin_addr) != 1) {
		close_fd(&dns->local_sock);
		return false;
	}
	addr.sin_port = htons((uint16_t)port);
	if (bind(dns->local_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		log_error("Can't bind address %s:%s", dns->listen_addr, dns->listen_port);
		close_fd(&dns->local_sock);
		return false;
	}
	return true;
}

bool localdns_init_tcp(dnsserver_t *dns)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int on = 1;

	if (!dns || dns->local_sock < 0 ||
			getsockname(dns->local_sock, (struct sockaddr *)&addr, &len) != 0)
		return false;
	dns->tcp_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (dns->tcp_sock < 0)
		return false;
	(void)setsockopt(dns->tcp_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(dns->tcp_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
			listen(dns->tcp_sock, 256) != 0) {
		close_fd(&dns->tcp_sock);
		return false;
	}
	return true;
}

int localdns_answer_local(dnsserver_t *dns, struct Message *msg, uint8_t *buf)
{
	struct ResourceRecord *rr;
	size_t written = 0;

	if (!dns || !msg || !msg->questions || !msg->questions->qName || !buf)
		return 0;
	msg->qr = 1;
	msg->aa = 1;
	msg->tc = 0;
	msg->ra = 1;
	msg->rcode = Ok_ResponseType;
	msg->anCount = msg->nsCount = msg->arCount = 0;
	if (msg->questions->qType == A_Resource_RecordType &&
			msg->questions->qClass == DNS_CLASS_IN) {
		rr = calloc(1, sizeof(*rr));
		if (!rr)
			return 0;
		rr->name = strdup(msg->questions->qName);
		if (!rr->name) {
			free(rr);
			return 0;
		}
		rr->type = A_Resource_RecordType;
		rr->class = DNS_CLASS_IN;
		rr->ttl = dns->local_ttl;
		rr->rd_length = 4;
		memcpy(rr->rd_data.a_record.addr, dns->sni_ip, 4);
		msg->answers = rr;
		msg->anCount = 1;
	} else {
		rr = calloc(1, sizeof(*rr));
		if (!rr)
			return 0;
		rr->name = strdup(msg->questions->qName);
		rr->rd_data.soa_record.mname = strdup(msg->questions->qName);
		rr->rd_data.soa_record.rname = strdup(msg->questions->qName);
		if (!rr->name || !rr->rd_data.soa_record.mname || !rr->rd_data.soa_record.rname) {
			free(rr->name);
			free(rr->rd_data.soa_record.mname);
			free(rr->rd_data.soa_record.rname);
			free(rr);
			return 0;
		}
		rr->type = SOA_Resource_RecordType;
		rr->class = DNS_CLASS_IN;
		rr->ttl = dns->local_ttl;
		rr->rd_data.soa_record.serial = 1;
		rr->rd_data.soa_record.refresh = 3600;
		rr->rd_data.soa_record.retry = 600;
		rr->rd_data.soa_record.expire = 86400;
		rr->rd_data.soa_record.minimum = dns->local_ttl;
		msg->authorities = rr;
		msg->nsCount = 1;
	}
	if (!dns_encode_msg_n(msg, buf, DNS_MSG_SIZE, &written) || written > DNS_MSG_SIZE) {
		if (msg->authorities) {
			free(msg->authorities->name);
			free(msg->authorities->rd_data.soa_record.mname);
			free(msg->authorities->rd_data.soa_record.rname);
			free(msg->authorities);
			msg->authorities = NULL;
			msg->nsCount = 0;
		}
		if (!dns_encode_msg_n(msg, buf, DNS_MSG_SIZE, &written) || written > DNS_MSG_SIZE)
			return 0;
	}
	return (int)written;
}
