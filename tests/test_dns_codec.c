#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "log.h"

static int failures = 0;

static void expect_true(bool value, const char *name)
{
    if (!value)
    {
        fprintf(stderr, "FAIL: %s expected true\n", name);
        failures++;
    }
}

static void expect_u16(uint16_t actual, uint16_t expected, const char *name)
{
    if (actual != expected)
    {
        fprintf(stderr, "FAIL: %s expected %u, got %u\n", name, expected, actual);
        failures++;
    }
}

static void expect_u8(uint8_t actual, uint8_t expected, const char *name)
{
    if (actual != expected)
    {
        fprintf(stderr, "FAIL: %s expected 0x%02x, got 0x%02x\n", name, expected, actual);
        failures++;
    }
}

static void expect_string(const char *actual, const char *expected, const char *name)
{
    if (strcmp(actual, expected) != 0)
    {
        fprintf(stderr, "FAIL: %s expected '%s', got '%s'\n", name, expected, actual);
        failures++;
    }
}

static const uint8_t k_query_example_com[] = {
    0x12, 0x34,
    0x01, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,
    0x00, 0x01
};

static void test_decode_basic_a_query(void)
{
    struct Message msg = {0};
    bool ok = dns_decode_msg(&msg, k_query_example_com, (int)sizeof(k_query_example_com));

    expect_true(ok, "decode basic A query");
    if (ok && msg.questions)
    {
        expect_u16(msg.id, 0x1234, "query id");
        expect_u16(msg.qdCount, 1, "question count");
        expect_string(msg.questions->qName, "example.com", "question name");
        expect_u16(msg.questions->qType, A_Resource_RecordType, "question type A");
        expect_u16(msg.questions->qClass, 1, "question class IN");
    }
    else if (ok)
    {
        fprintf(stderr, "FAIL: decode basic A query expected one question\n");
        failures++;
    }

    free_msg(&msg);
}

static void test_transaction_id_preserved_on_encode(void)
{
    struct Message msg = {0};
    uint8_t out[512] = {0};
    uint8_t *p = out;
    bool decoded = dns_decode_msg(&msg, k_query_example_com, (int)sizeof(k_query_example_com));

    expect_true(decoded, "decode before re-encode");
    if (decoded)
    {
        bool encoded = dns_encode_msg(&msg, &p);
        expect_true(encoded, "re-encode decoded query");
        if (encoded)
        {
            expect_u8(out[0], 0x12, "re-encoded id high byte");
            expect_u8(out[1], 0x34, "re-encoded id low byte");
        }
    }

    free_msg(&msg);
}

static void test_decode_rd_ra_preservation(void)
{
    struct Message msg_query = {0};
    struct Message msg_response = {0};
    static const uint8_t k_query_rd_set[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01
    };
    static const uint8_t k_response_rd_ra_set[] = {
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01
    };

    expect_true(dns_decode_msg(&msg_query, k_query_rd_set, (int)sizeof(k_query_rd_set)),
                "decode RD query");
    expect_u16(msg_query.rd, 1, "query RD decoded");
    expect_u16(msg_query.ra, 0, "query RA decoded");
    free_msg(&msg_query);

    expect_true(dns_decode_msg(&msg_response, k_response_rd_ra_set, (int)sizeof(k_response_rd_ra_set)),
                "decode RD/RA response");
    expect_u16(msg_response.qr, 1, "response QR decoded");
    expect_u16(msg_response.rd, 1, "response RD decoded");
    expect_u16(msg_response.ra, 1, "response RA decoded");
    free_msg(&msg_response);
}

static void test_encode_local_a_response(void)
{
    struct Question q = {0};
    struct ResourceRecord a = {0};
    struct Message msg = {0};
    uint8_t out[512] = {0};
    uint8_t *p = out;

    q.qName = "example.com";
    q.qType = A_Resource_RecordType;
    q.qClass = 1;
    q.next = NULL;

    a.name = "example.com";
    a.type = A_Resource_RecordType;
    a.class = 1;
    a.ttl = 300;
    a.rd_length = 4;
    a.rd_data.a_record.addr[0] = 192;
    a.rd_data.a_record.addr[1] = 0;
    a.rd_data.a_record.addr[2] = 2;
    a.rd_data.a_record.addr[3] = 10;
    a.next = NULL;

    msg.id = 0x1234;
    msg.qr = 1;
    msg.rcode = 0;
    msg.qdCount = 1;
    msg.anCount = 1;
    msg.nsCount = 0;
    msg.arCount = 0;
    msg.questions = &q;
    msg.answers = &a;

    expect_true(dns_encode_msg(&msg, &p), "encode local A response");

    expect_u8(out[0], 0x12, "response id high byte");
    expect_u8(out[1], 0x34, "response id low byte");
    expect_u8(out[4], 0x00, "response qdcount high byte");
    expect_u8(out[5], 0x01, "response qdcount low byte");
    expect_u8(out[6], 0x00, "response ancount high byte");
    expect_u8(out[7], 0x01, "response ancount low byte");

    expect_u8(out[25], 0x00, "question qtype high byte");
    expect_u8(out[26], 0x01, "question qtype low byte");
    expect_u8(out[27], 0x00, "question qclass high byte");
    expect_u8(out[28], 0x01, "question qclass low byte");

    expect_u8(out[42], 0x00, "answer type high byte");
    expect_u8(out[43], 0x01, "answer type low byte");
    expect_u8(out[44], 0x00, "answer class high byte");
    expect_u8(out[45], 0x01, "answer class low byte");
    expect_u8(out[46], 0x00, "answer ttl byte0");
    expect_u8(out[47], 0x00, "answer ttl byte1");
    expect_u8(out[48], 0x01, "answer ttl byte2");
    expect_u8(out[49], 0x2c, "answer ttl byte3");
    expect_u8(out[50], 0x00, "answer rdlength high byte");
    expect_u8(out[51], 0x04, "answer rdlength low byte");
    expect_u8(out[52], 192, "answer ip byte0");
    expect_u8(out[53], 0, "answer ip byte1");
    expect_u8(out[54], 2, "answer ip byte2");
    expect_u8(out[55], 10, "answer ip byte3");
}

static void test_encode_dns_flags(void)
{
    struct Question q = {0};
    struct Message msg = {0};
    uint8_t out[512] = {0};
    uint8_t *p = out;

    q.qName = "example.com";
    q.qType = A_Resource_RecordType;
    q.qClass = 1;

    msg.id = 0x5678;
    msg.qr = 1;
    msg.opcode = 0;
    msg.aa = 1;
    msg.tc = 0;
    msg.rd = 1;
    msg.ra = 1;
    msg.rcode = 0;
    msg.qdCount = 1;
    msg.questions = &q;

    expect_true(dns_encode_msg(&msg, &p), "encode dns flags");
    expect_u8(out[2], 0x85, "flags high byte");
    expect_u8(out[3], 0x80, "flags low byte");
}

int main(void)
{
    log_set_quiet(1);

    test_decode_basic_a_query();
    test_transaction_id_preserved_on_encode();
    test_decode_rd_ra_preservation();
    test_encode_local_a_response();
    test_encode_dns_flags();

    return failures == 0 ? 0 : 1;
}
