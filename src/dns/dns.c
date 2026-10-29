/**********************************************************************
 * File : dns.c
 * Copyright (c) Zeus@Sisoog.com.
 * Created On : Tue Apr 26 2022
 * based on https://github.com/mwarning/SimpleDNS
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **********************************************************************/
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <zroxy/config.h>
#include <string.h>
#include <zroxy/dns.h>
#include <zroxy/log.h>
#include <arpa/inet.h>

#define DNS_MAX_LABEL 63
#define DNS_MAX_POINTERS 16
#define DNS_MAX_QUESTIONS 32

typedef struct
{
  const uint8_t *base;
  const uint8_t *p;
  const uint8_t *end;
} dns_reader;

typedef struct
{
  uint8_t *p;
  uint8_t *end; /* NULL disables the limit; callers that know the size must set it. */
} dns_writer;

static bool reader_u8(dns_reader *r, uint8_t *out)
{
  if (r->p >= r->end)
    return false;
  *out = *r->p++;
  return true;
}

static bool reader_u16(dns_reader *r, uint16_t *out)
{
  uint8_t hi, lo;
  if (!reader_u8(r, &hi) || !reader_u8(r, &lo))
    return false;
  *out = (uint16_t)(((uint16_t)hi << 8) | lo);
  return true;
}

static bool writer_need(dns_writer *w, size_t n)
{
  if (w->end == NULL)
    return true;
  if (n > (size_t)(w->end - w->p))
    return false;
  return true;
}

static bool writer_u8(dns_writer *w, uint8_t value)
{
  if (!writer_need(w, 1))
    return false;
  *w->p++ = value;
  return true;
}

static bool writer_u16(dns_writer *w, uint16_t value)
{
  return writer_u8(w, (uint8_t)(value >> 8)) &&
         writer_u8(w, (uint8_t)(value & 0xFF));
}

static bool writer_u32(dns_writer *w, uint32_t value)
{
  return writer_u8(w, (uint8_t)((value >> 24) & 0xFF)) &&
         writer_u8(w, (uint8_t)((value >> 16) & 0xFF)) &&
         writer_u8(w, (uint8_t)((value >> 8) & 0xFF)) &&
         writer_u8(w, (uint8_t)(value & 0xFF));
}

static bool writer_bytes(dns_writer *w, const void *src, size_t n)
{
  if (!writer_need(w, n))
    return false;
  memcpy(w->p, src, n);
  w->p += n;
  return true;
}

/*
 * Presentation name: labels joined by '.', no trailing dot.
 * Compression pointers are followed with a jump limit. The message
 * cursor advances only across the first on-wire name, not the target.
 */
static bool decode_domain_name(dns_reader *r, char **out)
{
  const uint8_t *pkt = r->base;
  size_t pkt_len = (size_t)(r->end - r->base);
  size_t pos = (size_t)(r->p - r->base);
  size_t wire_end = 0;
  bool wire_done = false;
  int jumps = 0;
  char name[ZROXY_MAX_HOSTNAME];
  size_t nlen = 0;

  *out = NULL;
  if (pos >= pkt_len)
    return false;

  for (;;)
  {
    uint8_t lab;
    if (pos >= pkt_len)
      return false;
    lab = pkt[pos];
    if (lab == 0)
    {
      if (!wire_done)
        wire_end = pos + 1;
      break;
    }
    if ((lab & 0xC0) == 0xC0)
    {
      size_t off;
      if (pos + 1 >= pkt_len)
        return false;
      off = ((size_t)(lab & 0x3F) << 8) | pkt[pos + 1];
      if (off >= pkt_len)
        return false;
      if (++jumps > DNS_MAX_POINTERS)
        return false;
      if (!wire_done)
      {
        wire_end = pos + 2;
        wire_done = true;
      }
      pos = off;
      continue;
    }
    if ((lab & 0xC0) != 0)
      return false;
    if (lab > DNS_MAX_LABEL)
      return false;
    if (pos + 1u + lab > pkt_len)
      return false;
    if (nlen > 0)
    {
      if (nlen + 1 >= sizeof(name))
        return false;
      name[nlen++] = '.';
    }
    if (nlen + lab >= sizeof(name))
      return false;
    memcpy(name + nlen, pkt + pos + 1, lab);
    nlen += lab;
    pos += 1u + lab;
  }

  if (nlen == 0 || wire_end == 0 || wire_end > pkt_len)
    return false;

  name[nlen] = '\0';
  r->p = pkt + wire_end;
  *out = strdup(name);
  return *out != NULL;
}

static bool encode_domain_name(dns_writer *w, const char *domain)
{
  const char *beg;
  if (!domain || domain[0] == '\0')
    return false;

  beg = domain;
  while (*beg)
  {
    const char *pos = strchr(beg, '.');
    size_t len = pos ? (size_t)(pos - beg) : strlen(beg);
    if (len == 0 || len > DNS_MAX_LABEL)
      return false;
    if (!writer_u8(w, (uint8_t)len) || !writer_bytes(w, beg, len))
      return false;
    beg += len;
    if (*beg == '.')
      beg++;
  }
  return writer_u8(w, 0);
}

static bool dns_decode_header(struct Message *msg, dns_reader *r)
{
  uint16_t fields;
  if (!reader_u16(r, &msg->id) || !reader_u16(r, &fields))
    return false;

  msg->qr = (uint16_t)((fields & QR_MASK) >> 15);
  msg->opcode = (uint16_t)((fields & OPCODE_MASK) >> 11);
  msg->aa = (uint16_t)((fields & AA_MASK) >> 10);
  msg->tc = (uint16_t)((fields & TC_MASK) >> 9);
  msg->rd = (uint16_t)((fields & RD_MASK) >> 8);
  msg->ra = (uint16_t)((fields & RA_MASK) >> 7);
  msg->rcode = (uint16_t)(fields & RCODE_MASK);

  if (!reader_u16(r, &msg->qdCount) ||
      !reader_u16(r, &msg->anCount) ||
      !reader_u16(r, &msg->nsCount) ||
      !reader_u16(r, &msg->arCount))
    return false;
  return true;
}

static bool dns_encode_header(struct Message *msg, dns_writer *w)
{
  int fields = 0;
  fields |= (msg->qr << 15) & QR_MASK;
  fields |= (msg->opcode << 11) & OPCODE_MASK;
  fields |= (msg->aa << 10) & AA_MASK;
  fields |= (msg->tc << 9) & TC_MASK;
  fields |= (msg->rd << 8) & RD_MASK;
  fields |= (msg->ra << 7) & RA_MASK;
  fields |= (msg->rcode << 0) & RCODE_MASK;

  return writer_u16(w, msg->id) &&
         writer_u16(w, (uint16_t)fields) &&
         writer_u16(w, msg->qdCount) &&
         writer_u16(w, msg->anCount) &&
         writer_u16(w, msg->nsCount) &&
         writer_u16(w, msg->arCount);
}

bool dns_decode_msg(struct Message *msg, const uint8_t *buffer, int size)
{
  dns_reader r;
  uint32_t qcount;
  uint32_t i;

  if (!msg || !buffer || size < 12)
    return false;

  r.base = buffer;
  r.p = buffer;
  r.end = buffer + size;

  if (!dns_decode_header(msg, &r))
    return false;

  qcount = msg->qdCount;
  if (qcount > DNS_MAX_QUESTIONS)
    return false;

  for (i = 0; i < qcount; ++i)
  {
    struct Question *q = calloc(1, sizeof(*q));
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    if (!q)
      return false;

    if (!decode_domain_name(&r, &q->qName) ||
        !reader_u16(&r, &qtype) ||
        !reader_u16(&r, &qclass))
    {
      free(q->qName);
      free(q);
      log_error("Failed to decode domain name!");
      return false;
    }

    q->qType = qtype;
    q->qClass = qclass;
    q->next = msg->questions;
    msg->questions = q;
  }

  return true;
}

static void free_questions(struct Question *qq)
{
  struct Question *next;
  while (qq)
  {
    free(qq->qName);
    next = qq->next;
    free(qq);
    qq = next;
  }
}

static void free_resource_records(struct ResourceRecord *rr)
{
  struct ResourceRecord *next;
  while (rr)
  {
    free(rr->name);
    if (rr->type == SOA_Resource_RecordType)
    {
      free(rr->rd_data.soa_record.mname);
      free(rr->rd_data.soa_record.rname);
    }
    else if (rr->type == TXT_Resource_RecordType)
      free(rr->rd_data.txt_record.txt_data);
    next = rr->next;
    free(rr);
    rr = next;
  }
}

void dns_free_msg(struct Message *msg)
{
  if (!msg)
    return;
  free_questions(msg->questions);
  free_resource_records(msg->answers);
  free_resource_records(msg->authorities);
  free_resource_records(msg->additionals);
  memset(msg, 0, sizeof(*msg));
}

static bool encode_resource_records(struct ResourceRecord *rr, dns_writer *w)
{
  while (rr)
  {
    int i;
    uint8_t *rd_length_pos = NULL;
    uint8_t *rd_data_pos = NULL;
    if (!rr->name || !encode_domain_name(w, rr->name))
      return false;
    if (!writer_u16(w, rr->type) ||
        !writer_u16(w, rr->class) ||
        !writer_u32(w, rr->ttl))
      return false;
	if (rr->type == SOA_Resource_RecordType)
	{
		rd_length_pos = w->p;
		if (!writer_u16(w, 0))
			return false;
		rd_data_pos = w->p;
	}
	else if (!writer_u16(w, rr->rd_length))
		return false;

    switch (rr->type)
    {
      case A_Resource_RecordType:
        if (rr->rd_length != 4)
          return false;
        for (i = 0; i < 4; ++i)
        {
          if (!writer_u8(w, rr->rd_data.a_record.addr[i]))
            return false;
        }
        break;
      case AAAA_Resource_RecordType:
        if (rr->rd_length != 16)
          return false;
        for (i = 0; i < 16; ++i)
        {
          if (!writer_u8(w, rr->rd_data.aaaa_record.addr[i]))
            return false;
        }
        break;
      case TXT_Resource_RecordType:
        if (!rr->rd_data.txt_record.txt_data)
          return false;
        if (!writer_u8(w, rr->rd_data.txt_record.txt_data_len))
          return false;
        for (i = 0; i < rr->rd_data.txt_record.txt_data_len; i++)
        {
          if (!writer_u8(w, (uint8_t)rr->rd_data.txt_record.txt_data[i]))
            return false;
        }
        break;
      case SOA_Resource_RecordType:
        if (!rr->rd_data.soa_record.mname || !rr->rd_data.soa_record.rname ||
            !encode_domain_name(w, rr->rd_data.soa_record.mname) ||
            !encode_domain_name(w, rr->rd_data.soa_record.rname) ||
            !writer_u32(w, rr->rd_data.soa_record.serial) ||
            !writer_u32(w, rr->rd_data.soa_record.refresh) ||
            !writer_u32(w, rr->rd_data.soa_record.retry) ||
            !writer_u32(w, rr->rd_data.soa_record.expire) ||
            !writer_u32(w, rr->rd_data.soa_record.minimum))
          return false;
        if ((size_t)(w->p - rd_data_pos) > UINT16_MAX)
          return false;
        rd_length_pos[0] = (uint8_t)((w->p - rd_data_pos) >> 8);
        rd_length_pos[1] = (uint8_t)((w->p - rd_data_pos) & 0xff);
        break;
      default:
        log_error("Unknown type %u. => Ignore resource record.", rr->type);
        return false;
    }

    rr = rr->next;
  }
  return true;
}

static bool dns_encode_into(struct Message *msg, dns_writer *w)
{
  struct Question *q;
  if (!msg || !dns_encode_header(msg, w))
    return false;

  for (q = msg->questions; q; q = q->next)
  {
    if (!q->qName || !encode_domain_name(w, q->qName))
      return false;
    if (!writer_u16(w, q->qType) || !writer_u16(w, q->qClass))
      return false;
  }

  if (!encode_resource_records(msg->answers, w))
    return false;
  if (!encode_resource_records(msg->authorities, w))
    return false;
  if (!encode_resource_records(msg->additionals, w))
    return false;
  return true;
}

bool dns_encode_msg(struct Message *msg, uint8_t **buffer)
{
  dns_writer w;
  if (!buffer || !*buffer)
    return false;
  w.p = *buffer;
  w.end = NULL;
  if (!dns_encode_into(msg, &w))
    return false;
  *buffer = w.p;
  return true;
}

bool dns_encode_msg_n(struct Message *msg, uint8_t *buffer, size_t capacity, size_t *written)
{
  dns_writer w;
  if (!buffer || capacity == 0)
    return false;
  w.p = buffer;
  w.end = buffer + capacity;
  if (!dns_encode_into(msg, &w))
    return false;
  if (written)
    *written = (size_t)(w.p - buffer);
  return true;
}

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
  opt_ctx o = { false, 0, 0 };
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
  ttl_ctx t = { false, 0 };
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
