#include <sys/resource.h>

#include <zroxy/fdlimit.h>

unsigned long fdlimit_other_need(const fdlimit_plan *plan)
{
	unsigned long need = FDLIMIT_MARGIN;

	if (plan->sni_listeners > 0)
		need += FDLIMIT_PER_LISTENER * (unsigned long)plan->sni_listeners;
	if (plan->dns_enabled)
	{
		need += FDLIMIT_DNS_CLIENTS;
		if (plan->dns_upstreams > 0)
			need += (unsigned long)plan->dns_upstreams;
	}
	if (plan->monitor_enabled)
		need += FDLIMIT_MONITOR_WORKERS;
	return need;
}

unsigned long fdlimit_needed(const fdlimit_plan *plan)
{
	unsigned long conns = plan->sni_conns > 0 ? (unsigned long)plan->sni_conns : 0ul;
	return fdlimit_other_need(plan) + 2ul * conns;
}

int fdlimit_sni_cap(const fdlimit_plan *plan, unsigned long soft)
{
	unsigned long other = fdlimit_other_need(plan);
	unsigned long cap;

	if (soft <= other)
		return 1;
	cap = (soft - other) / 2ul;
	if (cap < 1ul)
		cap = 1ul;
	if (cap > (unsigned long)plan->sni_conns)
		cap = (unsigned long)plan->sni_conns;
	return (int)cap;
}

unsigned long fdlimit_apply(const fdlimit_plan *plan, int *sni_cap)
{
	struct rlimit lim;
	unsigned long need = fdlimit_needed(plan);
	unsigned long soft;

	*sni_cap = plan->sni_conns;
	if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
		return 0;
	if (lim.rlim_cur != RLIM_INFINITY && lim.rlim_cur < (rlim_t)need)
	{
		struct rlimit want = lim;
		want.rlim_cur = (lim.rlim_max == RLIM_INFINITY || lim.rlim_max >= (rlim_t)need)
			? (rlim_t)need : lim.rlim_max;
		if (want.rlim_cur > lim.rlim_cur && setrlimit(RLIMIT_NOFILE, &want) == 0)
			lim = want;
		else if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
			return 0;
	}
	if (lim.rlim_cur == RLIM_INFINITY)
		return (unsigned long)-1;
	soft = (unsigned long)lim.rlim_cur;
	if (soft < need)
		*sni_cap = fdlimit_sni_cap(plan, soft);
	return soft;
}
