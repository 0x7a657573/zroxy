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
/* Test-only fault injection and counter state for the SNI engine. */

#include "sni_internal.h"

#include <string.h>

#ifdef SNI_TEST_HOOKS
static int g_read_limit;
static int g_write_limit;
static int g_eagain_write;
static int g_eintr_read;
static int g_eintr_write;
static int g_eintr_connect;
static int g_eintr_wait;
static int g_fail_wait;
static int g_fail_allocs;
static int g_fail_accept;
static uint32_t g_accept_pauses;
static uint32_t g_client_bytes;
static uint32_t g_max_pending;
static uint32_t g_eagain;
static uint32_t g_wait_calls;
static uint32_t g_relay_yields;
static int g_hello_idle_ms = SNI_HELLO_IDLE_MS;
static uint32_t g_relay_budget = SNI_RELAY_BUDGET;

int sni_take_fault(enum sni_fault which)
{
	int *counter;
	int cur;
	switch (which)
	{
	case SNI_FAULT_EINTR_READ: counter = &g_eintr_read; break;
	case SNI_FAULT_EAGAIN_WRITE: counter = &g_eagain_write; break;
	case SNI_FAULT_EINTR_WRITE: counter = &g_eintr_write; break;
	case SNI_FAULT_FAIL_ACCEPT: counter = &g_fail_accept; break;
	case SNI_FAULT_EINTR_CONNECT: counter = &g_eintr_connect; break;
	case SNI_FAULT_EINTR_WAIT: counter = &g_eintr_wait; break;
	case SNI_FAULT_FAIL_WAIT: counter = &g_fail_wait; break;
	case SNI_FAULT_FAIL_ALLOCS: counter = &g_fail_allocs; break;
	default: return 0;
	}
	cur = __atomic_load_n(counter, __ATOMIC_RELAXED);
	while (cur > 0)
	{
		if (__atomic_compare_exchange_n(counter, &cur, cur - 1, 1,
		            __ATOMIC_RELAXED, __ATOMIC_RELAXED))
			return 1;
	}
	return 0;
}

int sni_read_limit(void)
{
	return __atomic_load_n(&g_read_limit, __ATOMIC_RELAXED);
}

int sni_write_limit(void)
{
	return __atomic_load_n(&g_write_limit, __ATOMIC_RELAXED);
}

int sni_hello_idle_ms_override(void)
{
	return __atomic_load_n(&g_hello_idle_ms, __ATOMIC_RELAXED);
}

uint32_t sni_relay_budget_override(void)
{
	return __atomic_load_n(&g_relay_budget, __ATOMIC_RELAXED);
}

void sni_note_client_read(uint32_t n)
{
	__atomic_fetch_add(&g_client_bytes, n, __ATOMIC_RELAXED);
}

void sni_note_pending(uint32_t n)
{
	uint32_t cur = __atomic_load_n(&g_max_pending, __ATOMIC_RELAXED);
	while (n > cur)
	{
		if (__atomic_compare_exchange_n(&g_max_pending, &cur, n, 1,
		            __ATOMIC_RELAXED, __ATOMIC_RELAXED))
			break;
	}
}

void sni_note_eagain(void)
{
	__atomic_fetch_add(&g_eagain, 1, __ATOMIC_RELAXED);
}

void sni_note_wait(void)
{
	__atomic_fetch_add(&g_wait_calls, 1u, __ATOMIC_RELAXED);
}

void sni_note_relay_yield(void)
{
	__atomic_fetch_add(&g_relay_yields, 1u, __ATOMIC_RELAXED);
}

void sni_note_accept_pause(void)
{
	__atomic_fetch_add(&g_accept_pauses, 1u, __ATOMIC_RELAXED);
}

void sni_test_set_faults(const sni_test_faults *faults)
{
	sni_test_faults none;
	if (!faults)
	{
		memset(&none, 0, sizeof(none));
		faults = &none;
	}
	__atomic_store_n(&g_read_limit, faults->read_limit, __ATOMIC_RELAXED);
	__atomic_store_n(&g_write_limit, faults->write_limit, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eagain_write, faults->eagain_write, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_read, faults->eintr_read, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_write, faults->eintr_write, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_connect, faults->eintr_connect, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eintr_wait, faults->eintr_wait, __ATOMIC_RELAXED);
	__atomic_store_n(&g_fail_wait, faults->fail_wait, __ATOMIC_RELAXED);
	__atomic_store_n(&g_fail_allocs, faults->fail_allocs, __ATOMIC_RELAXED);
	__atomic_store_n(&g_fail_accept, faults->fail_accept, __ATOMIC_RELAXED);
}

void sni_test_clear_faults(void)
{
	sni_test_set_faults(NULL);
}

void sni_test_reset_counters(void)
{
	__atomic_store_n(&g_client_bytes, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_max_pending, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_eagain, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_wait_calls, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_relay_yields, 0u, __ATOMIC_RELAXED);
	__atomic_store_n(&g_accept_pauses, 0u, __ATOMIC_RELAXED);
}

uint32_t sni_test_client_bytes(void)
{
	return __atomic_load_n(&g_client_bytes, __ATOMIC_RELAXED);
}

uint32_t sni_test_max_pending(void)
{
	return __atomic_load_n(&g_max_pending, __ATOMIC_RELAXED);
}

uint32_t sni_test_eagain_count(void)
{
	return __atomic_load_n(&g_eagain, __ATOMIC_RELAXED);
}

uint32_t sni_test_wait_calls(void)
{
	return __atomic_load_n(&g_wait_calls, __ATOMIC_RELAXED);
}

void sni_test_set_hello_idle_ms(int ms)
{
	if (ms <= 0)
		ms = SNI_HELLO_IDLE_MS;
	__atomic_store_n(&g_hello_idle_ms, ms, __ATOMIC_RELAXED);
}

uint32_t sni_test_accept_pauses(void)
{
	return __atomic_load_n(&g_accept_pauses, __ATOMIC_RELAXED);
}

uint32_t sni_test_relay_yields(void)
{
	return __atomic_load_n(&g_relay_yields, __ATOMIC_RELAXED);
}

void sni_test_set_relay_budget(uint32_t bytes)
{
	if (bytes == 0)
		bytes = SNI_RELAY_BUDGET;
	__atomic_store_n(&g_relay_budget, bytes, __ATOMIC_RELAXED);
}
#endif
