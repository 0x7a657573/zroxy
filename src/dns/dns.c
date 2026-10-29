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
    if (!rr->name || !encode_domain_name(w, rr->name))
      return false;
    if (!writer_u16(w, rr->type) ||
        !writer_u16(w, rr->class) ||
        !writer_u32(w, rr->ttl) ||
        !writer_u16(w, rr->rd_length))
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

size_t dns_udp_limit(const uint8_t *query, size_t qlen, size_t max)
{
  size_t pos = DNS_HEADER_SIZE;
  uint32_t skip;
  uint32_t ar;
  uint32_t i;

  if (!query || qlen < DNS_HEADER_SIZE || max < DNS_UDP_MIN_PAYLOAD)
    return DNS_UDP_MIN_PAYLOAD;

  for (i = get_u16(query + 4); i > 0; i--)
  {
    if (!skip_name(query, qlen, &pos, true) || pos + 4 > qlen)
      return DNS_UDP_MIN_PAYLOAD;
    pos += 4;
  }

  /* Answer and authority records, then the additional section holding OPT. */
  skip = (uint32_t)get_u16(query + 6) + get_u16(query + 8);
  ar = get_u16(query + 10);
  for (i = 0; i < skip + ar; i++)
  {
    uint16_t type;
    uint16_t size;
    if (!skip_name(query, qlen, &pos, true) || pos + 10 > qlen)
      return DNS_UDP_MIN_PAYLOAD;
    type = get_u16(query + pos);
    size = get_u16(query + pos + 2);
    if (i >= skip && type == DNS_OPT_RECORD_TYPE)
    {
      if (size <= DNS_UDP_MIN_PAYLOAD)
        return DNS_UDP_MIN_PAYLOAD;
      return size > max ? max : size;
    }
    pos += 10u + get_u16(query + pos + 8);
  }
  return DNS_UDP_MIN_PAYLOAD;
}
