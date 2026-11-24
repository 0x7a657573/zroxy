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
 * dns.h
 *
 *  Created on: Apr 26, 2022
 *      Author: zeus
 */
#ifndef dns_H
#define dns_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define QR_MASK 0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK 0x0400
#define TC_MASK 0x0200
#define RD_MASK 0x0100
#define RA_MASK 0x0080
#define RCODE_MASK 0x000F

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
	QUERY_OperationCode = 0,  /* standard query */
	IQUERY_OperationCode = 1, /* inverse query */
	STATUS_OperationCode = 2, /* server status request */
	NOTIFY_OperationCode = 4, /* request zone transfer */
	UPDATE_OperationCode = 5  /* change resource records */
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

#define DNS_HEADER_SIZE 12
#define DNS_CLASS_IN 1
#define DNS_OPT_RECORD_TYPE 41
/* Plain UDP limit, and the largest EDNS0 size honoured (DNS flag day 2020). */
#define DNS_UDP_MIN_PAYLOAD 512
#define DNS_UDP_MAX_PAYLOAD 1232

/*
 * Wire-level helpers that work on raw packets, so they also cover malformed
 * messages. Each returns the written length, or 0.
 */
/* Name of the only question as text: labels joined by '.', no trailing dot.
 * False if qdcount is not 1, the question is cut off or compressed, the name
 * is empty, or it does not fit in cap bytes with its NUL. */
bool dns_question_name(const uint8_t *query, size_t qlen, char *name, size_t cap);
/* Authoritative reply to query for a whitelisted name: IN A gets one A record;
 * every other type gets NODATA with one SOA in authority. */
size_t dns_build_local_answer(const uint8_t *query, size_t qlen, const uint8_t addr[4],
        uint32_t ttl, uint8_t *out, size_t cap);
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
