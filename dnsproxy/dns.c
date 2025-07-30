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
#include <config.h>
#include <string.h>
#include "dns.h"
#include <log.h>
#include <arpa/inet.h>

#define MIN(x, y) ((x) <= (y) ? (x) : (y))
/*
* Basic memory operations.
*/

/**
 * @brief Puts 8 bits of data into the buffer.
 *
 * @param buffer The buffer to write to.
 * @param value The value to write.
 */
static void put8bits(uint8_t **buffer, uint8_t value)
{
  *(*buffer)++=value;
}

/**
 * @brief Gets 16 bits of data from the buffer.
 *
 * @param buffer The buffer to read from.
 * @return The 16-bit value.
 */
static size_t get16bits(const uint8_t **buffer)
{
  uint16_t value;
  value  = (*(*buffer)++)<<8 ;
  value |= *(*buffer)++;
  return value;
}

/**
 * @brief Puts 16 bits of data into the buffer.
 *
 * @param buffer The buffer to write to.
 * @param value The value to write.
 */
static void put16bits(uint8_t **buffer, uint16_t value)
{
  *(*buffer)++ = value>>8;
  *(*buffer)++ = value&0xFF;
}

/**
 * @brief Puts 32 bits of data into the buffer.
 *
 * @param buffer The buffer to write to.
 * @param value The value to write.
 */
static void put32bits(uint8_t **buffer, uint32_t value)
{
  *(*buffer)++ = (value>>24)&0xFF;
  *(*buffer)++ = (value>>16)&0xFF;
  *(*buffer)++ = (value>> 8)&0xFF;
  *(*buffer)++ = (value>> 0)&0xFF;
}

/**
 * @brief Decodes a domain name from the buffer.
 *
 * @param buf The buffer to read from.
 * @param len The length of the buffer.
 * @return The decoded domain name, or NULL on error.
 */
char *decode_domain_name(const uint8_t **buf, size_t len)
{
  char domain[_MaxHostName_];

    /*find end if name*/
  int domain_len = 0;
  for(size_t i=0;i<len;i++)
    if((*buf)[i]==0)
    {
      domain_len = i+1;
      break;
    }  

    if (domain_len == 0 || domain_len >= _MaxHostName_)
  {
    return NULL;
  }

  for (size_t i = 1; i < domain_len; i++)
  {
    uint8_t c = (*buf)[i];
    if (c == 0) 
    {
      domain[i - 1] = 0;
      *buf += i + 1;
      return strdup(domain);
    } 
    else if (c <= 63 && c <= (domain_len-i)) 
    {
      domain[i - 1] = '.';
    } 
    else 
    {
      domain[i - 1] = c;
    }
  }
  return NULL;
}

/**
 * @brief Encodes a domain name into the buffer.
 *
 * @param buffer The buffer to write to.
 * @param domain The domain name to encode.
 */
void encode_domain_name(uint8_t **buffer, const char *domain)
{
  uint8_t *buf = *buffer;
  const char *beg = domain;
  int i = 0;

  while (*beg)
  {
    const char *pos = strchr(beg, '.');
    int len = pos ? pos - beg : strlen(beg);

    buf[i++] = len;
    memcpy(buf + i, beg, len);
    i += len;

    beg += len;
    if (*beg == '.')
    {
      beg++;
    }
  }

  buf[i++] = 0;
  *buffer += i;
}

/**
 * @brief Decodes the header of a DNS message.
 *
 * @param msg The message to decode into.
 * @param buffer The buffer to read from.
 */
void dns_decode_header(struct Message *msg, const uint8_t **buffer)
{
  msg->id = get16bits(buffer);

  uint32_t fields = get16bits(buffer);
  msg->qr = (fields & QR_MASK) >> 15;
  msg->opcode = (fields & OPCODE_MASK) >> 11;
  msg->aa = (fields & AA_MASK) >> 10;
  msg->tc = (fields & TC_MASK) >> 9;
  msg->rd = (fields & RD_MASK) >> 8;
  msg->ra = (fields & RA_MASK) >> 7;
  msg->rcode = (fields & RCODE_MASK) >> 0;

  msg->qdCount = get16bits(buffer);
  msg->anCount = get16bits(buffer);
  msg->nsCount = get16bits(buffer);
  msg->arCount = get16bits(buffer);
}

/**
 * @brief Encodes the header of a DNS message.
 *
 * @param msg The message to encode.
 * @param buffer The buffer to write to.
 */
void dns_encode_header(struct Message *msg, uint8_t **buffer)
{
  put16bits(buffer, msg->id);

  int fields = 0;
  fields |= (msg->qr << 15) & QR_MASK;
  fields |= (msg->rcode << 0) & RCODE_MASK;
  // TODO: insert the rest of the fields
  put16bits(buffer, fields);

  put16bits(buffer, msg->qdCount);
  put16bits(buffer, msg->anCount);
  put16bits(buffer, msg->nsCount);
  put16bits(buffer, msg->arCount);
}

/**
 * @brief Decodes a DNS message.
 *
 * @param msg The message to decode into.
 * @param buffer The buffer to read from.
 * @param size The size of the buffer.
 * @return True on success, false on failure.
 */
bool dns_decode_msg(struct Message *msg, const uint8_t *buffer, int size)
{
  dns_decode_header(msg, &buffer);

  // parse questions
  uint32_t qcount = msg->qdCount;
  for (int i = 0; i < qcount; ++i) 
  {
    struct Question *q = malloc(sizeof(struct Question));

    q->qName = decode_domain_name(&buffer, size);
    q->qType = get16bits(&buffer);
    q->qClass = get16bits(&buffer);

    if (q->qName == NULL) 
    {
      log_error("Failed to decode domain name!");
      return false;
    }

    // prepend question to questions list
    q->next = msg->questions;
    msg->questions = q;
  }

  // We do not expect any resource records to parse here.
  return true;
}

/**
 * @brief Frees the memory allocated for a list of questions.
 *
 * @param qq The list of questions to free.
 */
void free_questions(struct Question *qq)
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

/**
 * @brief Frees the memory allocated for a list of resource records.
 *
 * @param rr The list of resource records to free.
 */
void free_resource_records(struct ResourceRecord *rr)
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

/**
 * @brief Frees the memory allocated for a DNS message.
 *
 * @param msg The message to free.
 */
void free_msg(struct Message *msg)
{
  free_questions(msg->questions);
  free_resource_records(msg->answers);
  free_resource_records(msg->authorities);
  free_resource_records(msg->additionals);
  memset(msg, 0, sizeof(struct Message));
}

/**
 * @brief Encodes a list of resource records into the buffer.
 *
 * @param rr The list of resource records to encode.
 * @param buffer The buffer to write to.
 * @return 0 on success, 1 on failure.
 */
int encode_resource_records(struct ResourceRecord *rr, uint8_t **buffer)
{
  int i;
  while (rr) {
    // Answer questions by attaching resource sections.
    encode_domain_name(buffer, rr->name);
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->class);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->rd_length);

    switch (rr->type) {
      case A_Resource_RecordType:
        for (i = 0; i < 4; ++i)
          put8bits(buffer, rr->rd_data.a_record.addr[i]);
        break;
      case AAAA_Resource_RecordType:
        for (i = 0; i < 16; ++i)
          put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
        break;
      case TXT_Resource_RecordType:
        put8bits(buffer, rr->rd_data.txt_record.txt_data_len);
        for (i = 0; i < rr->rd_data.txt_record.txt_data_len; i++)
          put8bits(buffer, rr->rd_data.txt_record.txt_data[i]);
        break;
      default:
        fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
      return 1;
    }

    rr = rr->next;
  }

  return 0;
}

/**
 * @brief Encodes a DNS message.
 *
 * @param msg The message to encode.
 * @param buffer The buffer to write to.
 * @return True on success, false on failure.
 */
bool dns_encode_msg(struct Message *msg, uint8_t **buffer)
{
  dns_encode_header(msg, buffer);

  for (struct Question *q = msg->questions; q; q = q->next)
  {
    encode_domain_name(buffer, q->qName);
    put16bits(buffer, q->qType);
    put16bits(buffer, q->qClass);
  }

  if (encode_resource_records(msg->answers, buffer) != 0)
    return false;
  if (encode_resource_records(msg->authorities, buffer) != 0)
    return false;
  if (encode_resource_records(msg->additionals, buffer) != 0)
    return false;

  return true;
}