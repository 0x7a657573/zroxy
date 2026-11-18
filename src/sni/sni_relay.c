#define _GNU_SOURCE

/* Relay state, buffering, half-close handling, and relay fairness budget. */

#include "sni_internal.h"

#include <string.h>

#include <zroxy/net_io.h>

static void note_idle(sni_conn *c)
{
	int64_t now = net_mono_ms();
	c->touched = 1;
	if (now < 0)
		return;
	if (c->c2u_off < c->c2u_len || c->u2c_off < c->u2c_len)
		return;
	/* idle_ms is clamped, so a zero timeout cannot make the idle timer fire at once. */
	c->idle_at = now + (int64_t)c->idle_ms;
}

static uint32_t relay_budget(void)
{
#ifdef SNI_TEST_HOOKS
	uint32_t b = sni_relay_budget_override();
	if (b > 0)
		return b;
#endif
	return SNI_RELAY_BUDGET;
}

void sni_enter_relay(sni_engine *e, sni_conn *c)
{
	int64_t now = net_mono_ms();
	if (now < 0) {
		sni_conn_kill(e, c, SNI_CLOSE_NONE);
		return;
	}
	sni_conn_set_state(e, c, SNI_ST_RELAY);
	sni_count_relayed();
	if (c->hello_len > SNI_RELAY_CAP) {
		sni_conn_kill(e, c, SNI_CLOSE_NONE);
		return;
	}
	if (c->hello_len > 0) {
		memcpy(c->c2u, c->hello, (size_t)c->hello_len);
		c->c2u_len = c->hello_len;
		c->c2u_off = 0;
		c->c2u_by = now + (int64_t)c->io_ms;
		sni_note_pending(c->c2u_len);
	}
	c->idle_at = now + (int64_t)c->idle_ms;
	c->touched = 1;
	sni_relay_pump(e, c);
}

void sni_relay_pump(sni_engine *e, sni_conn *c)
{
	uint32_t budget = relay_budget();
	uint32_t moved = 0;
	while (!c->dead) {
		int progress = 0;
		int wr;
		int rr;
		if (c->up_fd >= 0 && !c->up_shut && c->c2u_off < c->c2u_len) {
			uint32_t before = c->c2u_off;
			wr = sni_write_some(c->up_fd, c->c2u, c->c2u_len, &c->c2u_off, &c->tx);
			if (wr < 0) {
				sni_conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			}
			if (c->c2u_off > before) {
				progress = 1;
				moved += c->c2u_off - before;
			}
			if (c->c2u_off == c->c2u_len)
				c->c2u_by = 0;
			if (c->c2u_len >= c->c2u_off)
				sni_note_pending(c->c2u_len - c->c2u_off);
		}
		if (!c->dead && !c->client_shut && c->u2c_off < c->u2c_len) {
			uint32_t before = c->u2c_off;
			wr = sni_write_some(c->client_fd, c->u2c, c->u2c_len, &c->u2c_off, &c->rx);
			if (wr < 0) {
				sni_conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			}
			if (c->u2c_off > before) {
				progress = 1;
				moved += c->u2c_off - before;
			}
			if (c->u2c_off == c->u2c_len)
				c->u2c_by = 0;
			if (c->u2c_len >= c->u2c_off)
				sni_note_pending(c->u2c_len - c->u2c_off);
		}
		if (!c->dead && !c->client_eof && c->c2u_off == c->c2u_len) {
			c->c2u_off = 0;
			c->c2u_len = 0;
			rr = sni_read_some(c->client_fd, c->c2u, SNI_RELAY_CAP, &c->c2u_len);
			if (rr == -2) {
				c->client_eof = 1;
			} else if (rr < 0) {
				sni_conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			} else if (rr == 1) {
				progress = 1;
				c->c2u_by = net_mono_ms() + (int64_t)c->io_ms;
				sni_note_pending(c->c2u_len);
			}
		}
		if (!c->dead && c->up_fd >= 0 && !c->up_eof && c->u2c_off == c->u2c_len) {
			c->u2c_off = 0;
			c->u2c_len = 0;
			rr = sni_read_some(c->up_fd, c->u2c, SNI_RELAY_CAP, &c->u2c_len);
			if (rr == -2) {
				c->up_eof = 1;
			} else if (rr < 0) {
				sni_conn_kill(e, c, SNI_CLOSE_NONE);
				return;
			} else if (rr == 1) {
				progress = 1;
				c->u2c_by = net_mono_ms() + (int64_t)c->io_ms;
				sni_note_pending(c->u2c_len);
			}
		}
		if (!c->dead && c->client_eof && c->c2u_off == c->c2u_len &&
				c->up_fd >= 0 && !c->up_shut) {
			(void)sni_shut_write(c->up_fd);
			c->up_shut = 1;
			progress = 1;
		}
		if (!c->dead && c->up_eof && c->u2c_off == c->u2c_len && !c->client_shut) {
			(void)sni_shut_write(c->client_fd);
			c->client_shut = 1;
			progress = 1;
		}
		if (!c->dead && c->client_eof && c->up_eof &&
				c->c2u_off == c->c2u_len && c->u2c_off == c->u2c_len) {
			sni_conn_kill(e, c, SNI_CLOSE_NONE);
			return;
		}
		if (progress)
			note_idle(c);
		if (!progress)
			break;
		/*
		 * Stop only after a whole pass, so EOF and shutdown steps above are
		 * never skipped. Whatever is left is a buffered write or a readable
		 * socket, and conn_arm keeps both armed.
		 */
		if (moved >= budget) {
			sni_note_relay_yield();
			break;
		}
	}
	if (!c->dead && !sni_conn_arm(e, c))
		sni_conn_kill(e, c, SNI_CLOSE_NONE);
}
