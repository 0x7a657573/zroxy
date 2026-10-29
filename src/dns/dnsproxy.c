#define _GNU_SOURCE
/*
 * dnsproxy.c
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */
#include <zroxy/dnsproxy.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <zroxy/log.h>
#include <stdbool.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <zroxy/socks.h>
#include <pthread.h>
#include <zroxy/dns.h>
#include <unistd.h>
#include <zroxy/net.h>
#include <zroxy/filter.h>
#include <time.h>
#include <zroxy/net_io.h>
#include <poll.h>

/*
 * Local answers are short-lived so a whitelist reload or a new SNIP reaches
 * clients quickly.
 */
#define DNS_LOCAL_TTL	300

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
	dnsserver_t *dns = (dnsserver_t *)ctx;
	dnscache_counters c = {0};
	if (!dns)
		return false;
	dnscache_get_counters(dns->cache, &c);
	return dns_stats_append(ptr, end, ",\n\"CacheHits\" : %" PRIu64 ",\n"
		"\"CacheMisses\" : %" PRIu64 ",\n"
		"\"CacheShared\" : %" PRIu64 ",\n"
		"\"CacheEntries\" : %zu,\n"
		"\"CacheEvictions\" : %" PRIu64 ",\n"
		"\"QueueStaleDropped\" : %" PRIu32 ",\n"
		"\"QueueFull\" : %" PRIu32 ",\n"
		"\"AclDropped\" : %" PRIu32 ",\n"
		"\"RateDropped\" : %" PRIu32 ",\n"
		"\"TcpRefused\" : %" PRIu32 ",\n"
		"\"TcpActive\" : %d",
		c.hits, c.misses, c.shared, c.entries, c.evicted,
		__atomic_load_n(&dns->stale_dropped, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->fifo_full, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->acl_dropped, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->rate_dropped, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->tcp_refused, __ATOMIC_RELAXED),
		__atomic_load_n(&dns->tcp_active, __ATOMIC_RELAXED));
}

/* The receive loop owns its FIFO/TCP throttle state; NO DATA is worker-shared. */
static bool throttle_take(log_throttle_t *t, int64_t now_ms, int64_t interval_ms,
		uint32_t *dropped)
{
	uint32_t next;
	uint32_t now = (uint32_t)now_ms;

	if (!t || !dropped || interval_ms < 0)
		return false;
	*dropped = 0;
	for (;;)
	{
		next = __atomic_load_n(&t->next_ms, __ATOMIC_ACQUIRE);
		if ((int32_t)(now - next) < 0)
		{
			(void)__atomic_fetch_add(&t->suppressed, 1u, __ATOMIC_RELAXED);
			return false;
		}
		if (__atomic_compare_exchange_n(&t->next_ms, &next,
				 now + (uint32_t)interval_ms,
				false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		{
			*dropped = __atomic_exchange_n(&t->suppressed, 0u, __ATOMIC_ACQ_REL);
			return true;
		}
	}
}

bool dnsproxy_test_throttle_take(log_throttle_t *t, int64_t now_ms,
		int64_t interval_ms, uint32_t *dropped)
{
	return throttle_take(t, now_ms, interval_ms, dropped);
}

static void log_fifo_full(log_throttle_t *t, const char *suffix)
{
	uint32_t dropped;
	if (!throttle_take(t, net_mono_ms(), 1000, &dropped))
		return;
	if (dropped > 0)
		log_error("%s (%u more in the last 1s)", suffix, dropped);
	else
		log_error("%s", suffix);
}

static void log_no_data(dnsserver_t *dns, const char *domain_resolve,
		double time_taken, const char *source)
{
	uint32_t dropped;
	if (!throttle_take(&dns->no_data_log, net_mono_ms(), 1000, &dropped))
		return;
	if (dropped > 0)
		log_error("NO DATA %s in %0.3fs%s (%u more in the last 1s)",
			domain_resolve, time_taken, source, dropped);
	else
		log_error("NO DATA %s in %0.3fs%s", domain_resolve, time_taken, source);
}

static void close_fd(int *fd)
{
	if (fd && *fd >= 0)
	{
		close(*fd);
		*fd = -1;
	}
}

dnsserver_t *localdns_init_config(dnshost_t *conf)
{
	dnsserver_t *ptr = (dnsserver_t*)malloc(sizeof(dnsserver_t));
	if(!ptr)
		return NULL;
	memset(ptr,0,sizeof(dnsserver_t));
	ptr->local_sock = -1;
	ptr->tcp_sock = -1;
	ptr->wake[0] = -1;
	ptr->wake[1] = -1;

	/* fifo init*/
	ptr->fifo = (fifo_t*)malloc(sizeof(fifo_t));
	if(!ptr->fifo || !fifo_init(ptr->fifo,DNS_QUEUE_ITEM_SIZE,DNS_QUEUE_LEN))
	{
		log_error("[!] Error DNS fifo not Set");
		free(ptr->fifo);
		ptr->fifo = NULL;
		localdns_free(ptr);
		return NULL;
	}

	if (strlen(conf->Local.ip) >= sizeof(ptr->listen_addr))
	{
		log_error("[!] DNS listen address too long");
		localdns_free(ptr);
		return NULL;
	}
	memcpy(ptr->listen_addr, conf->Local.ip, strlen(conf->Local.ip) + 1);
	snprintf(ptr->listen_port, sizeof(ptr->listen_port), "%u", (unsigned)conf->Local.port);
	ptr->socks = conf->Socks;
	if (conf->acl_set)
	{
		ptr->acl = malloc(conf->acl_count * sizeof(*ptr->acl));
		if (!ptr->acl)
		{
			localdns_free(ptr);
			return NULL;
		}
		memcpy(ptr->acl, conf->acl, conf->acl_count * sizeof(*ptr->acl));
		ptr->acl_count = conf->acl_count;
	}
	else
	{
		struct in_addr listen_ip;
		if (inet_pton(AF_INET, ptr->listen_addr, &listen_ip) != 1 ||
			(ntohl(listen_ip.s_addr) & 0xff000000u) != 0x7f000000u)
		{
			static const dns_cidr_t private_acl[] = {
				{ 0x7f000000u, 0xff000000u },
				{ 0x0a000000u, 0xff000000u },
				{ 0xac100000u, 0xfff00000u },
				{ 0xc0a80000u, 0xffff0000u },
				{ 0x64400000u, 0xffc00000u },
			};
			ptr->acl = malloc(sizeof(private_acl));
			if (!ptr->acl)
			{
				localdns_free(ptr);
				return NULL;
			}
			memcpy(ptr->acl, private_acl, sizeof(private_acl));
			ptr->acl_count = sizeof(private_acl) / sizeof(private_acl[0]);
			log_info("DNS ACL default: allow 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and 100.64.0.0/10");
		}
	}
	ptr->rate.qps = conf->rate_qps;

	if (conf->cache_entries > 0)
		ptr->cache = dnscache_create(conf->cache_entries);
	if (conf->cache_entries > 0 && !ptr->cache)
	{
		log_error("[!] DNS cache not set");
		localdns_free(ptr);
		return NULL;
	}

	/*init upstream dns server*/
	ptr->upstream = conf->Remote;

	// copy stat handler
	ptr->Stat = conf->Stat;

	// copy whitelist status;
	ptr->whitelist = conf->whitelist;

	// copy sni ip
	memcpy(ptr->sni_ip,conf->sni_ip,4);

	// copy timeout
	ptr->timeout = conf->timeout;
	ptr->local_ttl = conf->local_ttl;

	return ptr;
}

static void *localdns_worker(void *arg);

bool localdns_start_workers(dnsserver_t *dns)
{
	int i;
	if (!dns || dns->worker_count != 0)
		return false;
	for (i = 0; i < DNS_WORKER_COUNT; i++)
	{
		if (pthread_create(&dns->workers[i], NULL, localdns_worker, dns) != 0)
		{
			log_error("can not create dns worker %d", i);
			localdns_stop_workers(dns);
			return false;
		}
		dns->worker_count++;
	}
	log_info("DNS started %d workers", dns->worker_count);
	return true;
}

void localdns_stop_workers(dnsserver_t *dns)
{
	int i;
	if (!dns || dns->worker_count == 0)
		return;
	fifo_close(dns->fifo);
	for (i = 0; i < dns->worker_count; i++)
		pthread_join(dns->workers[i], NULL);
	dns->worker_count = 0;
}

void localdns_free(dnsserver_t *dns)
{
	if (!dns)
		return;
	/* socks aliases configuration memory and is not owned here. */
	close_fd(&dns->local_sock);
	close_fd(&dns->tcp_sock);
	close_fd(&dns->wake[0]);
	close_fd(&dns->wake[1]);
	if (dns->fifo)
	{
		fifo_deinit(dns->fifo);
		free(dns->fifo);
		dns->fifo = NULL;
	}
	free(dns->acl);
	dnscache_free(dns->cache);
	free(dns);
}

bool localdns_init_sockets(dnsserver_t *dns)
{
  struct sockaddr_in addr;
  char *end = NULL;
  unsigned long port;

  dns->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dns->local_sock < 0)
  {
    log_error("dns socket creation failed");
    return false;
  }

  /*
   * The listen address is an IPv4 literal. inet_pton avoids getaddrinfo, which
   * on this glibc can leave a resolver allocation behind if the process exits
   * immediately after a failed bind.
   */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  port = strtoul(dns->listen_port, &end, 10);
  if (dns->listen_port[0] == '\0' || end == NULL || *end != '\0' || port > 65535UL ||
      inet_pton(AF_INET, dns->listen_addr, &addr.sin_addr) != 1)
  {
    log_error("dns listen address rejected %s:%s", dns->listen_addr, dns->listen_port);
    close_fd(&dns->local_sock);
    return false;
  }
  addr.sin_port = htons((uint16_t)port);

  if (bind(dns->local_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    log_error("Can't bind address %s:%s\n", dns->listen_addr, dns->listen_port);
    close_fd(&dns->local_sock);
    return false;
  }

  return true;
}

bool localdns_pull(dnsserver_t *dns)
{
	socklen_t client_size = sizeof(struct sockaddr_in);

	dnsMessage_t	msg;
	ssize_t nread;
	memset(&msg, 0, sizeof(msg));
	// receive a dns request from the client
	/* MSG_TRUNC reports the real datagram size, so an oversized query is seen. */
	nread = recvfrom(dns->local_sock, &msg.message[2], DNS_MSG_SIZE - 2, MSG_TRUNC, (struct sockaddr *)&msg.client, &client_size);

	// lets not fork if recvfrom was interrupted
	if (nread < 0 && errno == EINTR)
	{
		return true;
	}

	// other invalid values from recvfrom
	if (nread < 0)
	{
		log_error("recvfrom failed: %s\n", strerror(errno));
		return true;
	}

	if (dns->acl_count > 0 &&
		!dns_acl_allows(dns->acl, dns->acl_count, ntohl(msg.client.sin_addr.s_addr)))
	{
		(void)__atomic_fetch_add(&dns->acl_dropped, 1u, __ATOMIC_RELAXED);
		return true;
	}
	if (!dns_rate_take(&dns->rate, ntohl(msg.client.sin_addr.s_addr), net_mono_ms()))
	{
		(void)__atomic_fetch_add(&dns->rate_dropped, 1u, __ATOMIC_RELAXED);
		return true;
	}

	/* Not a query: too short for a header, too large, or a response (QR set). */
	if (nread < DNS_HEADER_SIZE || (size_t)nread > DNS_MSG_SIZE - 2 ||
		((uint8_t)msg.message[4] & 0x80) != 0)
	{
		return true;
	}
	msg.len = (uint16_t)nread;
	msg.received_ms = net_mono_ms();

	// the tcp query requires the length to precede the packet, so we put the length there
	msg.message[0] = (char)((msg.len>>8) & 0xFF);
	msg.message[1] = (char)(msg.len & 0xFF);

	/*send dns message to dns fifo*/
	if(fifo_push(dns->fifo,&msg))
	{
		if(dns->Stat)
			stats_open_connection(dns->Stat);
	}
	else
	{
		(void)__atomic_fetch_add(&dns->fifo_full, 1u, __ATOMIC_RELAXED);
		uint8_t reply[DNS_MSG_SIZE];
		size_t n = dns_build_error((const uint8_t *)&msg.message[2], msg.len,
				ServerFailure_ResponseType, reply, sizeof(reply));
		if (n > 0)
			sendto(dns->local_sock, reply, n, 0, (const struct sockaddr *)&msg.client, sizeof(struct sockaddr_in));
		/* Only the receive thread reaches this path, so no external lock is needed. */
		log_fifo_full(&dns->fifo_log, "dns fifo is full");
	}

	return true;
}

/*
 * Answer a whitelisted name. Only A gets a record, pointing at the SNI proxy.
 * Every other type, including AAAA, HTTPS and SVCB, gets NODATA with a
 * negative-caching SOA: forwarding those would hand the client real addresses
 * that bypass the proxy, and IPv6 is not proxied at all. Returns the packet
 * length, or 0.
 */
static int localdns_answer_local(dnsserver_t *dns,struct Message *msg,uint8_t *buf)
{
	struct ResourceRecord *rr;
	size_t written = 0;

	if (!msg || !msg->questions || !msg->questions->qName || !buf)
		return 0;

	// leave most values intact for response
	msg->qr = 1; // this is a response
	msg->aa = 1; // this server is authoritative
	msg->tc = 0;
	msg->ra = 1; // stub resolvers expect recursion from their server
	msg->rcode = Ok_ResponseType;
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;

	if (msg->questions->qType == A_Resource_RecordType && msg->questions->qClass == DNS_CLASS_IN)
	{
		rr = calloc(1, sizeof(struct ResourceRecord));
		if (!rr)
			return 0;
		rr->name = strdup(msg->questions->qName);
		if (!rr->name)
		{
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
	}
	else
	{
		rr = calloc(1, sizeof(struct ResourceRecord));
		if (!rr)
			return 0;
		rr->name = strdup(msg->questions->qName);
		rr->rd_data.soa_record.mname = strdup(msg->questions->qName);
		rr->rd_data.soa_record.rname = strdup(msg->questions->qName);
		if (!rr->name || !rr->rd_data.soa_record.mname || !rr->rd_data.soa_record.rname)
		{
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

	if (!dns_encode_msg_n(msg, buf, DNS_MSG_SIZE, &written) || written > DNS_MSG_SIZE)
	{
		/* A long qname may not leave room for the SOA. Keep NODATA valid. */
		if (msg->authorities)
		{
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

static const char *dns_type_name(uint16_t type)
{
  switch(type)
  {
  	case A_Resource_RecordType: return "A";
  	case NS_Resource_RecordType: return "NS";
  	case CNAME_Resource_RecordType: return "CNAME";
  	case SOA_Resource_RecordType: return "SOA";
  	case PTR_Resource_RecordType: return "PTR";
  	case MX_Resource_RecordType:  return "MX";
  	case TXT_Resource_RecordType: return "TXT";
  	case AAAA_Resource_RecordType: return "AAAA";
  	case SRV_Resource_RecordType: return "SRV";
	case HTTPS_Resource_RecordType: return "HTTPS";
	case SVCB_Resource_RecordType: return "SVCB";
	default:	return "unknown";
  }
  return "";
}



/*
 * Drop an idle upstream connection if the server already closed it (or sent
 * something unsolicited). Catches the common "server closes idle TCP" case
 * before a query is written into a dead socket.
 */
static void upstream_drop_if_stale(int *fd)
{
	struct pollfd p;
	if (*fd < 0)
		return;
	p.fd = *fd;
	p.events = POLLIN;
	p.revents = 0;
	if (poll(&p, 1, 0) != 0)
		close_fd(fd);
}

static bool upstream_connect(dnsserver_t *dns, int *fd)
{
	if (dns->socks)
		return socks5_connect(fd, dns->socks, dns->upstream.ip, dns->upstream.port, true, (int)dns->timeout);
	return net_connect(fd, dns->upstream.ip, dns->upstream.port, (int)dns->timeout);
}

static int remaining_ms(int64_t deadline)
{
	int64_t left = deadline - net_mono_ms();
	if (left <= 0)
		return 0;
	return left > INT32_MAX ? INT32_MAX : (int)left;
}

/*
 * One length-prefixed query/response. The first cap bytes are stored in resp
 * and the rest is read and discarded, so the connection stays in step.
 * Returns the full response length, or 0.
 */
static uint16_t upstream_exchange(dnsserver_t *dns, int fd, const dnsMessage_t *msg,
		uint8_t *resp, size_t cap)
{
	int64_t deadline = net_mono_ms() + net_timeout_ms((int)dns->timeout);
	uint8_t prefix[2];
	uint8_t discard[512];
	uint16_t response_len;
	size_t stored;
	size_t left;

	if (!net_write_all_ms(fd, msg->message, (size_t)msg->len + 2u, remaining_ms(deadline)))
		return 0;
	if (!net_read_exact_ms(fd, prefix, sizeof(prefix), remaining_ms(deadline)))
		return 0;

	response_len = (uint16_t)((prefix[0] << 8) | prefix[1]);
	if (response_len < DNS_HEADER_SIZE)
	{
		log_error("DNS: upstream response length rejected: %u", response_len);
		return 0;
	}
	stored = response_len < cap ? response_len : cap;
	if (!net_read_exact_ms(fd, resp, stored, remaining_ms(deadline)))
		return 0;
	for (left = response_len - stored; left > 0; )
	{
		size_t n = left < sizeof(discard) ? left : sizeof(discard);
		if (!net_read_exact_ms(fd, discard, n, remaining_ms(deadline)))
			return 0;
		left -= n;
	}
	return response_len;
}

/*
 * Forward over the worker's persistent connection, opening one if needed.
 * A failure on a reused connection is retried once on a fresh one; a failure
 * on a fresh connection is final.
 */
static uint16_t upstream_forward(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd,
		uint8_t *resp, size_t cap)
{
	int attempt;

	upstream_drop_if_stale(upstream_fd);
	for (attempt = 0; attempt < 2; attempt++)
	{
		bool reused = *upstream_fd >= 0;
		uint16_t n;

		if (!reused && !upstream_connect(dns, upstream_fd))
			return 0;
		n = upstream_exchange(dns, *upstream_fd, msg, resp, cap);
		if (n > 0)
			return n;
		close_fd(upstream_fd);
		if (!reused)
			return 0;
	}
	return 0;
}

static void reply_client(dnsserver_t *dns, const dnsMessage_t *msg, const uint8_t *buf, size_t len)
{
	if (len == 0)
		return;
	if (msg->kind == DNS_MSG_TCP)
	{
		/* TCP_NODELAY is set, so the prefix and body leave without waiting. */
		int timeout_ms = net_timeout_ms((int)dns->timeout);
		uint8_t prefix[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
		if (len > DNS_TCP_MSG_MAX ||
			!net_write_all_ms(msg->tcp_fd, prefix, sizeof(prefix), timeout_ms) ||
			!net_write_all_ms(msg->tcp_fd, buf, len, timeout_ms))
			log_error("dns TCP reply failed");
		return;
	}
	sendto(dns->local_sock, buf, len, 0, (const struct sockaddr *)&msg->client, sizeof(struct sockaddr_in));
}

static void reply_error(dnsserver_t *dns, const dnsMessage_t *msg, uint8_t rcode)
{
	uint8_t buf[DNS_MSG_SIZE];
	size_t n = dns_build_error((const uint8_t *)&msg->message[2], msg->len, rcode, buf, sizeof(buf));
	reply_client(dns, msg, buf, n);
}

/*
 * resp receives the upstream reply: DNS_UDP_MAX_PAYLOAD bytes are enough for
 * UDP (the rest of a larger answer is discarded); TCP passes DNS_TCP_MSG_MAX.
 */
static void handle_query(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd,
		uint8_t *resp, size_t cap)
{
	const uint8_t *query = (const uint8_t *)&msg->message[2];
	char domain_resolve[1024] = {0};
	int64_t start_time = net_mono_ms();
	uint16_t rlen = 0;
	bool handled_local = false;
	struct Message dns_msg = {0};

	if (msg->len < DNS_HEADER_SIZE)
	{
		/* localdns_pull never queues these; keep the statistics balanced anyway. */
		handled_local = true;
	}
	else if (((query[2] >> 3) & 0x0F) != QUERY_OperationCode)
	{
		reply_error(dns, msg, NotImplemented_ResponseType);
		handled_local = true;
	}
	else if (((query[4] << 8) | query[5]) != 1)
	{
		/* RFC 9619: a query carries exactly one question. */
		reply_error(dns, msg, FormatError_ResponseType);
		handled_local = true;
	}
	/* A query the decoder rejects is still forwarded; upstream judges it. */
	else if(dns_decode_msg(&dns_msg, query, msg->len))
	{
		struct Question *q = dns_msg.questions;
		if (q && q->qName)
		{
			snprintf(domain_resolve,sizeof(domain_resolve),"resolve { (%s) qName '%s'} ",dns_type_name(q->qType),q->qName);

			if(dns->whitelist && filter_match(dns->whitelist,q->qName))
			{
				uint8_t buffer[DNS_MSG_SIZE];
				int len = localdns_answer_local(dns,&dns_msg,buffer);
				handled_local = true;
				if(len > 0)
					reply_client(dns, msg, buffer, (size_t)len);
				else
					reply_error(dns, msg, ServerFailure_ResponseType);
				log_trace("%s in %0.3fs Local reply",domain_resolve,
						(double)(net_mono_ms() - start_time) / 1000);
			}
		}
	}
	dns_free_msg(&dns_msg);

	if (!handled_local && msg->received_ms > 0 && start_time - msg->received_ms > DNS_QUEUE_MAX_AGE_MS)
	{
		(void)__atomic_fetch_add(&dns->stale_dropped, 1u, __ATOMIC_RELAXED);
		log_trace("%s dropped after %lldms in queue",domain_resolve,
				(long long)(start_time - msg->received_ms));
		handled_local = true;
	}

	if (!handled_local)
	{
		bool tcp = msg->kind == DNS_MSG_TCP;
		size_t full = 0;
		const char *source = "";
		dnscache_flight *flight = NULL;
		dnscache_result cached = dnscache_begin(dns->cache, query, msg->len, start_time,
				resp, cap, &full, &flight);
		bool fetch = cached == DNSCACHE_LEAD || cached == DNSCACHE_BYPASS;
		double time_taken;

		if (cached == DNSCACHE_HIT)
		{
			source = " cache";
		}
		else if (cached == DNSCACHE_FOLLOW)
		{
			/* The leader's fetch is bounded by connect + exchange, retried once. */
			int64_t deadline = start_time + 2 * (int64_t)net_timeout_ms((int)dns->timeout);
			full = dnscache_follow(dns->cache, flight, query, msg->len, deadline, resp, cap);
			source = " shared";
			/* A shared reply holds at most a UDP-sized prefix; TCP needs all of it. */
			if (tcp && full > DNS_UDP_MAX_PAYLOAD)
			{
				full = 0;
				fetch = true;
			}
		}
		if (fetch)
		{
			rlen = upstream_forward(dns, msg, upstream_fd, resp, cap);
			if (rlen > 0 && !dns_reply_matches(query, msg->len, resp, rlen < cap ? rlen : cap))
			{
				/* Never relay or cache an answer to a different question. */
				log_error("DNS: upstream reply does not match the query");
				close_fd(upstream_fd);
				rlen = 0;
			}
			full = rlen;
			if (cached == DNSCACHE_LEAD)
				dnscache_finish(dns->cache, flight, resp, full < cap ? full : cap,
						full, net_mono_ms());
		}
		time_taken = ((double)(net_mono_ms() - start_time))/(1000); // convert to sec

		if(full>0)
		{
			/* TCP carries the whole reply; UDP is cut to the client's size. */
			size_t limit = tcp ? cap : dns_udp_limit(query, msg->len, DNS_UDP_MAX_PAYLOAD);
			if (full <= limit)
			{
				reply_client(dns, msg, resp, full);
				log_info("%s in %0.3fs txrx(%i/%u)%s",domain_resolve,time_taken,msg->len,
						(unsigned)full + 2u,source);
			}
			else
			{
				/* TC tells the client the answer needs TCP. */
				uint8_t tc[DNS_MSG_SIZE];
				size_t n = dns_build_truncated(resp, full < cap ? full : cap, tc, sizeof(tc));
				if (n > 0)
					reply_client(dns, msg, tc, n);
				else
					reply_error(dns, msg, ServerFailure_ResponseType);
				log_info("%s in %0.3fs truncated %u > %u%s",domain_resolve,time_taken,
						(unsigned)full,(unsigned)limit,source);
			}
		}
		else
		{
			reply_error(dns, msg, ServerFailure_ResponseType);
			log_no_data(dns, domain_resolve, time_taken, source);
		}
	}

	//Update statistics
	if(dns->Stat)
	{
		stats_close_connection(dns->Stat, rlen > 0 ? (uint32_t)rlen + 2u : 0u, (uint32_t)msg->len + 2u);
	}
}

void localdns_handle_request(dnsserver_t *dns, const dnsMessage_t *msg, int *upstream_fd)
{
	uint8_t resp[DNS_UDP_MAX_PAYLOAD];
	handle_query(dns, msg, upstream_fd, resp, sizeof(resp));
}

bool localdns_init_tcp(dnsserver_t *dns)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int on = 1;

	/* Same address and port as the UDP socket, which is already bound. */
	if (dns->local_sock < 0 || getsockname(dns->local_sock, (struct sockaddr *)&addr, &len) != 0)
		return false;
	dns->tcp_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (dns->tcp_sock < 0)
		return false;
	(void)setsockopt(dns->tcp_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
	(void)setsockopt(dns->tcp_sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
	if (bind(dns->tcp_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
		listen(dns->tcp_sock, DNS_TCP_MAX_CONNS * 2) != 0)
	{
		log_error("Can't bind TCP address %s:%s", dns->listen_addr, dns->listen_port);
		close_fd(&dns->tcp_sock);
		return false;
	}
	return true;
}

void localdns_accept(dnsserver_t *dns)
{
	dnsMessage_t job;
	struct sockaddr_in peer;
	socklen_t peer_len = sizeof(peer);
	int on = 1;
	int fd;

	do {
		fd = accept4(dns->tcp_sock, NULL, NULL, SOCK_CLOEXEC);
	} while (fd < 0 && errno == EINTR);
	if (fd < 0)
		return;
	if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0 ||
		(dns->acl_count > 0 &&
		 !dns_acl_allows(dns->acl, dns->acl_count, ntohl(peer.sin_addr.s_addr))))
	{
		(void)__atomic_fetch_add(&dns->acl_dropped, 1u, __ATOMIC_RELAXED);
		close(fd);
		return;
	}
	if (__atomic_add_fetch(&dns->tcp_active, 1, __ATOMIC_ACQ_REL) > DNS_TCP_MAX_CONNS)
	{
		(void)__atomic_fetch_add(&dns->tcp_refused, 1u, __ATOMIC_RELAXED);
		__atomic_sub_fetch(&dns->tcp_active, 1, __ATOMIC_ACQ_REL);
		close(fd);
		/* Only the receive thread reaches this path, so no external lock is needed. */
		log_fifo_full(&dns->tcp_limit_log, "dns TCP connection limit reached");
		return;
	}
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

	memset(&job, 0, sizeof(job));
	job.kind = DNS_MSG_TCP_CONN;
	job.tcp_fd = fd;
	if (!fifo_push(dns->fifo, &job))
	{
		(void)__atomic_fetch_add(&dns->fifo_full, 1u, __ATOMIC_RELAXED);
		__atomic_sub_fetch(&dns->tcp_active, 1, __ATOMIC_ACQ_REL);
		close(fd);
		/* Only the receive thread reaches this path, so no external lock is needed. */
		log_fifo_full(&dns->tcp_fifo_log, "dns fifo is full: TCP connection dropped");
	}
}

/* Wait until fd is readable; false on idle timeout, error, or service stop. */
static bool tcp_wait_query(dnsserver_t *dns, int fd, int64_t deadline)
{
	for (;;)
	{
		struct pollfd p[2];
		int64_t left = deadline - net_mono_ms();
		int rc;

		if (left <= 0)
			return false;
		p[0].fd = fd;
		p[0].events = POLLIN;
		p[0].revents = 0;
		/* dnsserver_stop leaves the wake pipe readable. */
		p[1].fd = dns->wake[0];
		p[1].events = POLLIN;
		p[1].revents = 0;
		rc = poll(p, 2, left > INT32_MAX ? INT32_MAX : (int)left);
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0 || p[1].revents != 0)
			return false;
		return (p[0].revents & POLLIN) != 0;
	}
}

void localdns_serve_tcp(dnsserver_t *dns, int fd, int *upstream_fd)
{
	uint8_t *resp = malloc(DNS_TCP_MSG_MAX);
	int timeout_ms = net_timeout_ms((int)dns->timeout);
	int served;

	for (served = 0; resp && served < DNS_TCP_MAX_QUERIES; served++)
	{
		dnsMessage_t msg;
		uint8_t prefix[2];
		uint16_t len;

		if (!tcp_wait_query(dns, fd, net_mono_ms() + DNS_TCP_IDLE_MS) ||
			!net_read_exact_ms(fd, prefix, sizeof(prefix), timeout_ms))
			break;
		len = (uint16_t)((prefix[0] << 8) | prefix[1]);
		/* The queue's message buffer bounds a query, as on UDP. */
		if (len < DNS_HEADER_SIZE || len > DNS_MSG_SIZE - 2)
			break;
		memset(&msg, 0, sizeof(msg));
		msg.kind = DNS_MSG_TCP;
		msg.tcp_fd = fd;
		msg.len = len;
		msg.message[0] = (char)prefix[0];
		msg.message[1] = (char)prefix[1];
		if (!net_read_exact_ms(fd, &msg.message[2], len, timeout_ms))
			break;
		/* A response (QR set) is not a query. */
		if (((uint8_t)msg.message[4] & 0x80) != 0)
			break;
		msg.received_ms = net_mono_ms();
		if (dns->Stat)
			stats_open_connection(dns->Stat);
		handle_query(dns, &msg, upstream_fd, resp, DNS_TCP_MSG_MAX);
	}
	free(resp);
	close(fd);
}

/* Fixed pool member: one query at a time over its own upstream connection. */
static void *localdns_worker(void *arg)
{
	dnsserver_t *dns = (dnsserver_t*) arg;
	dnsMessage_t msg;
	int upstream_fd = -1;

	while (fifo_pop_wait(dns->fifo, &msg))
	{
		if (msg.kind == DNS_MSG_TCP_CONN)
		{
			localdns_serve_tcp(dns, msg.tcp_fd, &upstream_fd);
			__atomic_sub_fetch(&dns->tcp_active, 1, __ATOMIC_ACQ_REL);
		}
		else
			localdns_handle_request(dns, &msg, &upstream_fd);
	}

	close_fd(&upstream_fd);
	return NULL;
}
