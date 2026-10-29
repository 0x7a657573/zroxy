/**********************************************************************
 * File : dns.h
 * Copyright (c) Zeus@Sisoog.com.
 * Created On : Tue Apr 26 2022
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
#ifndef dns_H
#define dns_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define QR_MASK     0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK     0x0400
#define TC_MASK     0x0200
#define RD_MASK     0x0100
#define RA_MASK     0x0080
#define RCODE_MASK  0x000F

/* Response Type */
enum 
{
  Ok_ResponseType = 0,
  FormatError_ResponseType = 1,
  ServerFailure_ResponseType = 2,
  NameError_ResponseType = 3,
  NotImplemented_ResponseType = 4,
  Refused_ResponseType = 5
};

/* Resource Record Types */
/*https://en.wikipedia.org/wiki/List_of_DNS_record_types*/
enum 
{
  A_Resource_RecordType = 1,
  NS_Resource_RecordType = 2,
  CNAME_Resource_RecordType = 5,
  SOA_Resource_RecordType = 6,
  PTR_Resource_RecordType = 12,
  MX_Resource_RecordType = 15,
  TXT_Resource_RecordType = 16,
  AAAA_Resource_RecordType = 28,
  SRV_Resource_RecordType = 33,
  HTTPS_Resource_RecordType = 65,
  SVCB_Resource_RecordType = 64
};

/* Operation Code */
enum 
{
  QUERY_OperationCode = 0, /* standard query */
  IQUERY_OperationCode = 1, /* inverse query */
  STATUS_OperationCode = 2, /* server status request */
  NOTIFY_OperationCode = 4, /* request zone transfer */
  UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum 
{
  NoError_ResponseCode = 0,
  FormatError_ResponseCode = 1,
  ServerFailure_ResponseCode = 2,
  NameError_ResponseCode = 3
};

/* Query Type */
enum 
{
  IXFR_QueryType = 251,
  AXFR_QueryType = 252,
  MAILB_QueryType = 253,
  MAILA_QueryType = 254,
  STAR_QueryType = 255
};

/* Question Section */
struct Question 
{
  char      *qName;
  uint16_t qType;
  uint16_t qClass;
  struct Question *next; // for linked list
};

/* Data part of a Resource Record */
union ResourceData 
{
  struct 
  {
    uint8_t txt_data_len;
    char *txt_data;
  } txt_record;
  struct 
  {
    uint8_t addr[4];
  } a_record;
  struct 
  {
    uint8_t addr[16];
  } aaaa_record;
};

/* Resource Record Section */
struct ResourceRecord {
  char *name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rd_length;
  union ResourceData rd_data;
  struct ResourceRecord *next; // for linked list
};

struct Message 
{
  uint16_t id; /* Identifier */

  /* Flags */
  uint16_t qr; /* Query/Response Flag */
  uint16_t opcode; /* Operation Code */
  uint16_t aa; /* Authoritative Answer Flag */
  uint16_t tc; /* Truncation Flag */
  uint16_t rd; /* Recursion Desired */
  uint16_t ra; /* Recursion Available */
  uint16_t rcode; /* Response Code */

  uint16_t qdCount; /* Question Count */
  uint16_t anCount; /* Answer Record Count */
  uint16_t nsCount; /* Authority Record Count */
  uint16_t arCount; /* Additional Record Count */

  /* At least one question; questions are copied to the response 1:1 */
  struct Question *questions;

  /*
  * Resource records to be send back.
  * Every resource record can be in any of the following places.
  * But every place has a different semantic.
  */
  struct ResourceRecord *answers;
  struct ResourceRecord *authorities;
  struct ResourceRecord *additionals;
};

/*
* Deconding/Encoding functions.
*/
/*decode dns message*/
bool dns_decode_msg(struct Message *msg, const uint8_t *buffer, int size);
bool dns_encode_msg(struct Message *msg, uint8_t **buffer);
/* Encode into buffer[0, capacity). *written is the byte count on success. */
bool dns_encode_msg_n(struct Message *msg, uint8_t *buffer, size_t capacity, size_t *written);

/*free dns message struct*/
void dns_free_msg(struct Message *msg);

#define DNS_HEADER_SIZE      12
#define DNS_CLASS_IN         1
#define DNS_OPT_RECORD_TYPE  41
/* Plain UDP limit, and the largest EDNS0 size honoured (DNS flag day 2020). */
#define DNS_UDP_MIN_PAYLOAD  512
#define DNS_UDP_MAX_PAYLOAD  1232

/*
 * Wire-level helpers that work on raw packets, so they also cover messages
 * the decoder rejects. Each returns the written length, or 0.
 */
/* Reply to query with rcode: its id, opcode, RD and its question when that parses. */
size_t dns_build_error(const uint8_t *query, size_t qlen, uint8_t rcode, uint8_t *out, size_t cap);
/* resp's header and question with TC set and every record dropped. resp may be a prefix. */
size_t dns_build_truncated(const uint8_t *resp, size_t rlen, uint8_t *out, size_t cap);
/* UDP size the sender of query accepts: 512, or its EDNS0 size clamped to [512, max]. */
size_t dns_udp_limit(const uint8_t *query, size_t qlen, size_t max);
/* Find the OPT record: its UDP size and its TTL field (extended rcode, version, DO). */
bool dns_query_opt(const uint8_t *query, size_t qlen, uint16_t *udp_size, uint32_t *ext_flags);

/* Cache key: lowercased question plus RD, CD, EDNS and DO bits. 0 if not cacheable. */
size_t dns_cache_key(const uint8_t *query, size_t qlen, uint8_t *key, size_t cap);
/* resp answers query: same id, QR set, same question ignoring case. */
bool dns_reply_matches(const uint8_t *query, size_t qlen, const uint8_t *resp, size_t rlen);
/* Smallest answer/authority TTL of a NOERROR or NXDOMAIN reply without TC. */
bool dns_reply_ttl(const uint8_t *resp, size_t rlen, uint32_t *ttl);
/* Lower every TTL except OPT's by elapsed_s, stopping at 0. */
void dns_reply_age(uint8_t *resp, size_t rlen, uint32_t elapsed_s);
/* Give a stored reply the id and question spelling of query. */
bool dns_reply_adopt(uint8_t *resp, size_t rlen, const uint8_t *query, size_t qlen);

#endif /* dns.h */
