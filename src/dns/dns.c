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
 * dns.c
 *
 *  Created on: Apr 26, 2022
 *      Author: zeus
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <zroxy/dns.h>

static uint16_t get_u16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void put_u16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)(value >> 8);
	p[1] = (uint8_t)(value & 0xFF);
}

/*
 * Advance *pos past one on-wire name. A compression pointer ends the name;
 * with allow_ptr false it is rejected, so the bytes can be copied verbatim.
 */
static bool skip_name(const uint8_t *pkt, size_t len, size_t *pos, bool allow_ptr)
{
	size_t p = *pos;
	for (;;)
	{
		uint8_t lab;
		if (p >= len)
			return false;
		lab = pkt[p];
		if (lab == 0)
		{
			*pos = p + 1;
			return true;
		}
		if ((lab & 0xC0) == 0xC0)
		{
			if (!allow_ptr || p + 2 > len)
				return false;
			*pos = p + 2;
			return true;
		}
		if ((lab & 0xC0) != 0 || p + 1u + lab > len)
			return false;
		p += 1u + lab;
	}
}

/* End offset of the first question, or 0 if it is absent, compressed or cut off. */
static size_t first_question_end(const uint8_t *pkt, size_t len)
{
	size_t pos = DNS_HEADER_SIZE;
	if (len < DNS_HEADER_SIZE || get_u16(pkt + 4) == 0)
		return 0;
	if (!skip_name(pkt, len, &pos, false) || pos + 4 > len)
		return 0;
	return pos + 4;
}

/* Copy header and first question into out, keeping flags in keep_mask. */
static size_t build_header_question(const uint8_t *pkt, size_t len, uint16_t keep_mask,
        uint16_t set_flags, uint8_t *out, size_t cap)
{
	size_t qend;
	size_t n;
	uint16_t flags;

	if (!pkt || !out || len < DNS_HEADER_SIZE)
		return 0;
	qend = first_question_end(pkt, len);
	n = qend ? qend : DNS_HEADER_SIZE;
	if (n > cap)
		return 0;
	memcpy(out, pkt, n);
	flags = (uint16_t)((get_u16(pkt + 2) & keep_mask) | set_flags);
	put_u16(out + 2, flags);
	put_u16(out + 4, qend ? 1 : 0);
	put_u16(out + 6, 0);
	put_u16(out + 8, 0);
	put_u16(out + 10, 0);
	return n;
}

static bool append_bytes(uint8_t *out, size_t cap, size_t *pos, const void *src, size_t len)
{
	if (*pos > cap || len > cap - *pos)
		return false;
	memcpy(out + *pos, src, len);
	*pos += len;
	return true;
}

static bool append_u16(uint8_t *out, size_t cap, size_t *pos, uint16_t value)
{
	uint8_t bytes[2] = {(uint8_t)(value >> 8), (uint8_t)value};
	return append_bytes(out, cap, pos, bytes, sizeof(bytes));
}

static bool append_u32(uint8_t *out, size_t cap, size_t *pos, uint32_t value)
{
	uint8_t bytes[4] = {(uint8_t)(value >> 24), (uint8_t)(value >> 16),
	        (uint8_t)(value >> 8), (uint8_t)value};
	return append_bytes(out, cap, pos, bytes, sizeof(bytes));
}

bool dns_question_name(const uint8_t *query, size_t qlen, char *name, size_t cap)
{
	size_t nlen = 0;
	if (!query || !name || first_question_end(query, qlen) == 0 || get_u16(query + 4) != 1)
		return false;
	for (size_t pos = DNS_HEADER_SIZE; query[pos] != 0; pos += 1u + query[pos])
	{
		size_t lab = query[pos];
		size_t dot = nlen > 0;
		if (nlen + dot + lab >= cap)
			return false;
		if (dot)
			name[nlen++] = '.';
		memcpy(name + nlen, query + pos + 1, lab);
		nlen += lab;
	}
	if (nlen == 0)
		return false;
	name[nlen] = '\0';
	return true;
}

size_t dns_build_local_answer(const uint8_t *query, size_t qlen, const uint8_t addr[4],
        uint32_t ttl, uint8_t *out, size_t cap)
{
	static const uint8_t question_pointer[] = {0xc0, 0x0c};
	size_t qend;
	size_t pos;
	uint16_t qtype;
	uint16_t qclass;
	bool is_a;

	if (!query || !addr || !out)
		return 0;
	qend = first_question_end(query, qlen);
	if (qend == 0)
		return 0;
	pos = build_header_question(query, qlen, OPCODE_MASK | RD_MASK,
	        QR_MASK | AA_MASK | RA_MASK, out, cap);
	if (pos == 0)
		return 0;
	qtype = get_u16(query + qend - 4);
	qclass = get_u16(query + qend - 2);
	is_a = qtype == A_Resource_RecordType && qclass == DNS_CLASS_IN;
	if (!append_bytes(out, cap, &pos, question_pointer, sizeof(question_pointer)) ||
	        !append_u16(out, cap, &pos, is_a ? A_Resource_RecordType : SOA_Resource_RecordType) ||
	        !append_u16(out, cap, &pos, DNS_CLASS_IN) || !append_u32(out, cap, &pos, ttl))
		return 0;
	if (is_a)
	{
		if (!append_u16(out, cap, &pos, 4) || !append_bytes(out, cap, &pos, addr, 4))
			return 0;
		put_u16(out + 6, 1);
		return pos;
	}
	if (!append_u16(out, cap, &pos, 24) ||
	        !append_bytes(out, cap, &pos, question_pointer, sizeof(question_pointer)) ||
	        !append_bytes(out, cap, &pos, question_pointer, sizeof(question_pointer)) ||
	        !append_u32(out, cap, &pos, 1) || !append_u32(out, cap, &pos, 3600) ||
	        !append_u32(out, cap, &pos, 600) || !append_u32(out, cap, &pos, 86400) ||
	        !append_u32(out, cap, &pos, ttl))
		return 0;
	put_u16(out + 8, 1);
	return pos;
}

size_t dns_build_error(const uint8_t *query, size_t qlen, uint8_t rcode, uint8_t *out, size_t cap)
{
	return build_header_question(query, qlen, OPCODE_MASK | RD_MASK,
	        (uint16_t)(QR_MASK | RA_MASK | (rcode & RCODE_MASK)), out, cap);
}

size_t dns_build_truncated(const uint8_t *resp, size_t rlen, uint8_t *out, size_t cap)
{
	return build_header_question(resp, rlen, (uint16_t)~TC_MASK, TC_MASK, out, cap);
}

/*
 * Visit the fixed part (TYPE, CLASS, TTL, RDLENGTH) of every resource record
 * after the questions. section is 0 for answers, 1 authority, 2 additional.
 * Stops early when fn returns false. Returns false if the packet does not parse.
 */
typedef bool (*rr_visit)(uint8_t *fixed, int section, void *ctx);

static bool for_each_rr(const uint8_t *pkt, size_t len, rr_visit fn, void *ctx)
{
	size_t pos = DNS_HEADER_SIZE;
	uint32_t counts[3];
	uint32_t i;
	int section;

	if (!pkt || len < DNS_HEADER_SIZE)
		return false;
	for (i = get_u16(pkt + 4); i > 0; i--)
	{
		if (!skip_name(pkt, len, &pos, true) || pos + 4 > len)
			return false;
		pos += 4;
	}
	counts[0] = get_u16(pkt + 6);
	counts[1] = get_u16(pkt + 8);
	counts[2] = get_u16(pkt + 10);
	for (section = 0; section < 3; section++)
	{
		for (i = 0; i < counts[section]; i++)
		{
			size_t rdlen;
			if (!skip_name(pkt, len, &pos, true) || pos + 10 > len)
				return false;
			rdlen = get_u16(pkt + pos + 8);
			if (pos + 10 + rdlen > len)
				return false;
			if (!fn((uint8_t *)(uintptr_t)(pkt + pos), section, ctx))
				return true;
			pos += 10 + rdlen;
		}
	}
	return true;
}

static uint32_t get_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

typedef struct
{
	bool found;
	uint16_t size;
	uint32_t ttl;
} opt_ctx;

static bool find_opt(uint8_t *fixed, int section, void *ctx)
{
	opt_ctx *o = (opt_ctx *)ctx;
	if (section != 2 || get_u16(fixed) != DNS_OPT_RECORD_TYPE)
		return true;
	o->found = true;
	o->size = get_u16(fixed + 2);
	o->ttl = get_u32(fixed + 4);
	return false;
}

bool dns_query_opt(const uint8_t *query, size_t qlen, uint16_t *udp_size, uint32_t *ext_flags)
{
	opt_ctx o = {false, 0, 0};
	if (!for_each_rr(query, qlen, find_opt, &o) || !o.found)
		return false;
	if (udp_size)
		*udp_size = o.size;
	if (ext_flags)
		*ext_flags = o.ttl;
	return true;
}

size_t dns_udp_limit(const uint8_t *query, size_t qlen, size_t max)
{
	uint16_t size;
	if (max < DNS_UDP_MIN_PAYLOAD || !dns_query_opt(query, qlen, &size, NULL) ||
	        size <= DNS_UDP_MIN_PAYLOAD)
		return DNS_UDP_MIN_PAYLOAD;
	return size > max ? max : size;
}

static uint8_t ascii_lower(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

size_t dns_cache_key(const uint8_t *query, size_t qlen, uint8_t *key, size_t cap)
{
	size_t qend;
	size_t n;
	size_t i;
	uint32_t ext = 0;
	uint8_t bits = 0;

	if (!query || !key || qlen < DNS_HEADER_SIZE || get_u16(query + 4) != 1)
		return 0;
	qend = first_question_end(query, qlen);
	/* Lowercased wire name, TYPE and CLASS, then one byte of flags. */
	n = qend - DNS_HEADER_SIZE;
	if (qend == 0 || n + 1 > cap)
		return 0;
	for (i = 0; i < n; i++)
		key[i] = ascii_lower(query[DNS_HEADER_SIZE + i]);
	/* The answer differs with RD, CD, EDNS presence and the DO bit. */
	if (query[2] & 0x01)
		bits |= 0x01;
	if (query[3] & 0x10)
		bits |= 0x02;
	if (dns_query_opt(query, qlen, NULL, &ext))
	{
		bits |= 0x04;
		if (ext & 0x8000u)
			bits |= 0x08;
	}
	key[n] = bits;
	return n + 1;
}

bool dns_reply_matches(const uint8_t *query, size_t qlen, const uint8_t *resp, size_t rlen)
{
	size_t qend;
	size_t rend;
	size_t i;

	if (!query || !resp || qlen < DNS_HEADER_SIZE || rlen < DNS_HEADER_SIZE)
		return false;
	if (get_u16(query) != get_u16(resp) || (resp[2] & 0x80) == 0)
		return false;
	/* An error reply may omit the question. */
	if (get_u16(resp + 4) == 0)
		return (resp[3] & RCODE_MASK) != 0;
	qend = first_question_end(query, qlen);
	rend = first_question_end(resp, rlen);
	if (qend == 0 || rend != qend)
		return false;
	for (i = DNS_HEADER_SIZE; i < qend; i++)
	{
		if (ascii_lower(query[i]) != ascii_lower(resp[i]))
			return false;
	}
	return true;
}

typedef struct
{
	bool any;
	uint32_t min;
} ttl_ctx;

static bool min_ttl(uint8_t *fixed, int section, void *ctx)
{
	ttl_ctx *t = (ttl_ctx *)ctx;
	uint32_t ttl;
	if (section == 2)
		return false;
	ttl = get_u32(fixed + 4);
	if (!t->any || ttl < t->min)
		t->min = ttl;
	t->any = true;
	return true;
}

bool dns_reply_ttl(const uint8_t *resp, size_t rlen, uint32_t *ttl)
{
	ttl_ctx t = {false, 0};
	uint8_t rcode;

	if (!resp || rlen < DNS_HEADER_SIZE || (resp[2] & (TC_MASK >> 8)) != 0)
		return false;
	rcode = resp[3] & RCODE_MASK;
	if (rcode != NoError_ResponseCode && rcode != NameError_ResponseCode)
		return false;
	/* Answer and authority TTLs; a negative answer carries its SOA in authority. */
	if (!for_each_rr(resp, rlen, min_ttl, &t) || !t.any)
		return false;
	if (ttl)
		*ttl = t.min;
	return true;
}

static bool age_ttl(uint8_t *fixed, int section, void *ctx)
{
	uint32_t elapsed = *(const uint32_t *)ctx;
	uint32_t ttl;
	if (section == 2 && get_u16(fixed) == DNS_OPT_RECORD_TYPE)
		return true;
	ttl = get_u32(fixed + 4);
	ttl = ttl > elapsed ? ttl - elapsed : 0;
	fixed[4] = (uint8_t)(ttl >> 24);
	fixed[5] = (uint8_t)(ttl >> 16);
	fixed[6] = (uint8_t)(ttl >> 8);
	fixed[7] = (uint8_t)ttl;
	return true;
}

void dns_reply_age(uint8_t *resp, size_t rlen, uint32_t elapsed_s)
{
	if (elapsed_s > 0)
		(void)for_each_rr(resp, rlen, age_ttl, &elapsed_s);
}

bool dns_reply_adopt(uint8_t *resp, size_t rlen, const uint8_t *query, size_t qlen)
{
	size_t qend = first_question_end(query, qlen);
	if (!resp || rlen < DNS_HEADER_SIZE || qend == 0 || first_question_end(resp, rlen) != qend)
		return false;
	/* Id and the question as the client spelled it (0x20 case randomisation). */
	memcpy(resp, query, 2);
	memcpy(resp + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE, qend - DNS_HEADER_SIZE);
	return true;
}
