#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zroxy/dns.h>
#include <zroxy/log.h>

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

    dns_free_msg(&msg);
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

    dns_free_msg(&msg);
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
    dns_free_msg(&msg_query);

    expect_true(dns_decode_msg(&msg_response, k_response_rd_ra_set, (int)sizeof(k_response_rd_ra_set)),
                "decode RD/RA response");
    expect_u16(msg_response.qr, 1, "response QR decoded");
    expect_u16(msg_response.rd, 1, "response RD decoded");
    expect_u16(msg_response.ra, 1, "response RA decoded");
    dns_free_msg(&msg_response);
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

static void test_decode_rejects_truncated_and_loops(void)
{
    struct Message msg = {0};
    static const uint8_t short_header[11] = {0};
    static const uint8_t truncated_label[] = {
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 'a', 'b'
    };
    static const uint8_t pointer_loop[] = {
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C,
        0x00, 0x01, 0x00, 0x01
    };
    static const uint8_t pointer_oob[] = {
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x40,
        0x00, 0x01, 0x00, 0x01
    };

    expect_true(!dns_decode_msg(&msg, short_header, (int)sizeof(short_header)), "reject short header");
    dns_free_msg(&msg);
    expect_true(!dns_decode_msg(&msg, truncated_label, (int)sizeof(truncated_label)), "reject truncated label");
    dns_free_msg(&msg);
    expect_true(!dns_decode_msg(&msg, pointer_loop, (int)sizeof(pointer_loop)), "reject compression loop");
    dns_free_msg(&msg);
    expect_true(!dns_decode_msg(&msg, pointer_oob, (int)sizeof(pointer_oob)), "reject compression pointer past packet");
    dns_free_msg(&msg);
}

static void test_decode_valid_compression_pointer(void)
{
    struct Message msg = {0};
    static const uint8_t compressed[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xC0, 0x12,
        0x00, 0x01,
        0x00, 0x01,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00
    };

    expect_true(dns_decode_msg(&msg, compressed, (int)sizeof(compressed)), "decode compressed question");
    if (msg.questions && msg.questions->qName)
        expect_string(msg.questions->qName, "example.com", "compressed question name");
    else
    {
        fprintf(stderr, "FAIL: compressed question missing name\n");
        failures++;
    }
    dns_free_msg(&msg);
}

static void put_query_header(uint8_t *pkt, uint16_t qdcount)
{
    memset(pkt, 0, 12);
    pkt[2] = 0x01;
    pkt[4] = (uint8_t)(qdcount >> 8);
    pkt[5] = (uint8_t)qdcount;
}

static void test_decode_more_malformed(void)
{
    struct Message msg;
    uint8_t pkt[512];
    int pos;
    int lab;
    int off;

    memset(&msg, 0, sizeof(msg));
    memset(pkt, 0, sizeof(pkt));
    put_query_header(pkt, 1);
    pkt[12] = 0x40;
    pkt[13] = 'a';
    pkt[14] = 0x00;
    pkt[15] = 0x00;
    pkt[16] = 0x01;
    pkt[17] = 0x00;
    pkt[18] = 0x01;
    expect_true(!dns_decode_msg(&msg, pkt, 19), "reject reserved label type");
    dns_free_msg(&msg);

    memset(pkt, 0, sizeof(pkt));
    put_query_header(pkt, 1);
    pkt[12] = 63;
    pkt[13] = 'a';
    pkt[14] = 'b';
    expect_true(!dns_decode_msg(&msg, pkt, 15), "reject label longer than remaining bytes");
    dns_free_msg(&msg);

    memcpy(pkt, k_query_example_com, sizeof(k_query_example_com));
    pkt[5] = 2;
    expect_true(!dns_decode_msg(&msg, pkt, (int)sizeof(k_query_example_com)), "reject qdcount past the packet");
    dns_free_msg(&msg);

    memset(pkt, 0, sizeof(pkt));
    put_query_header(pkt, 1);
    pkt[12] = 0x00;
    pkt[13] = 0x00;
    pkt[14] = 0x01;
    pkt[15] = 0x00;
    pkt[16] = 0x01;
    expect_true(!dns_decode_msg(&msg, pkt, 17), "reject empty DNS name");
    dns_free_msg(&msg);

    /* 17 compression jumps: the decoder allows 16. */
    memset(pkt, 0, sizeof(pkt));
    put_query_header(pkt, 1);
    pkt[12] = 0xC0;
    pkt[13] = 18;
    pkt[14] = 0x00;
    pkt[15] = 0x01;
    pkt[16] = 0x00;
    pkt[17] = 0x01;
    for (off = 18; off <= 46; off += 2)
    {
        pkt[off] = 0xC0;
        pkt[off + 1] = (uint8_t)(off + 2);
    }
    pkt[48] = 0xC0;
    pkt[49] = 50;
    pkt[50] = 0xC0;
    pkt[51] = 0x00;
    expect_true(!dns_decode_msg(&msg, pkt, 52), "reject pointer chain over the jump limit");
    dns_free_msg(&msg);

    /* 16 jumps, then a one-letter name. This must still decode. */
    memset(pkt, 0, sizeof(pkt));
    put_query_header(pkt, 1);
    pkt[12] = 0xC0;
    pkt[13] = 18;
    pkt[14] = 0x00;
    pkt[15] = 0x01;
    pkt[16] = 0x00;
    pkt[17] = 0x01;
    for (off = 18; off <= 44; off += 2)
    {
        pkt[off] = 0xC0;
        pkt[off + 1] = (uint8_t)(off + 2);
    }
    pkt[46] = 0xC0;
    pkt[47] = 48;
    pkt[48] = 1;
    pkt[49] = 'a';
    pkt[50] = 0;
    expect_true(dns_decode_msg(&msg, pkt, 51), "accept pointer chain at the jump limit");
    if (msg.questions && msg.questions->qName)
        expect_string(msg.questions->qName, "a", "jump-limit name");
    else
    {
        fprintf(stderr, "FAIL: jump-limit name missing\n");
        failures++;
    }
    dns_free_msg(&msg);

    /* Four 63-byte labels do not fit the 255-byte presentation buffer. */
    memset(pkt, 0, sizeof(pkt));
    put_query_header(pkt, 1);
    pos = 12;
    for (lab = 0; lab < 4; lab++)
    {
        pkt[pos++] = 63;
        memset(pkt + pos, 'a' + lab, 63);
        pos += 63;
    }
    pkt[pos++] = 0;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x01;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x01;
    expect_true(!dns_decode_msg(&msg, pkt, pos), "reject DNS name longer than the hostname buffer");
    dns_free_msg(&msg);
}

static void test_encode_rejects_short_buffer(void)
{
    struct Question q = {0};
    struct Message msg = {0};
    uint8_t tiny[8];
    uint8_t enough[64];
    size_t written = 0;

    q.qName = "example.com";
    q.qType = A_Resource_RecordType;
    q.qClass = 1;
    msg.id = 0x1234;
    msg.qdCount = 1;
    msg.questions = &q;

    expect_true(!dns_encode_msg_n(&msg, tiny, sizeof(tiny), &written), "bounded encode rejects short buffer");
    expect_true(dns_encode_msg_n(&msg, enough, sizeof(enough), &written), "bounded encode accepts fitting buffer");
    expect_true(written > sizeof(tiny) && written <= sizeof(enough), "bounded encode length");
}

static void test_wire_error_and_truncation(void)
{
    uint8_t out[64];
    uint8_t garbage[16];
    uint8_t resp[sizeof(k_query_example_com) + 16];
    size_t n;

    n = dns_build_error(k_query_example_com, sizeof(k_query_example_com),
                        ServerFailure_ResponseType, out, sizeof(out));
    expect_true(n == sizeof(k_query_example_com), "error reply keeps header and question");
    expect_u8(out[0], 0x12, "error reply id hi");
    expect_u8(out[1], 0x34, "error reply id lo");
    expect_u8(out[2], 0x81, "error reply QR and RD");
    expect_u8(out[3], 0x82, "error reply RA and SERVFAIL");
    expect_true(memcmp(out + 12, k_query_example_com + 12, n - 12) == 0, "error reply question bytes");
    expect_true(dns_build_error(k_query_example_com, 11, 2, out, sizeof(out)) == 0, "error reply needs a header");
    expect_true(dns_build_error(k_query_example_com, sizeof(k_query_example_com), 2, out, 20) == 0,
                "error reply respects capacity");

    /* A question that does not parse is left out and QDCOUNT becomes 0. */
    memset(garbage, 0xff, sizeof(garbage));
    memcpy(garbage, k_query_example_com, 12);
    n = dns_build_error(garbage, sizeof(garbage), FormatError_ResponseType, out, sizeof(out));
    expect_true(n == 12, "error reply without a parsable question");
    expect_u8(out[5], 0, "error reply QDCOUNT 0");
    expect_u8(out[3], 0x81, "error reply FORMERR");

    /* A response with records and an OPT is cut to header and question with TC. */
    memcpy(resp, k_query_example_com, sizeof(k_query_example_com));
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[7] = 1;
    resp[11] = 1;
    memset(resp + sizeof(k_query_example_com), 0xee, 16);
    n = dns_build_truncated(resp, sizeof(resp), out, sizeof(out));
    expect_true(n == sizeof(k_query_example_com), "truncated reply length");
    expect_u8(out[2], 0x83, "truncated reply sets TC and keeps QR/RD");
    expect_u8(out[3], 0x80, "truncated reply keeps RA and rcode");
    expect_u8(out[7], 0, "truncated reply ANCOUNT 0");
    expect_u8(out[11], 0, "truncated reply ARCOUNT 0");
}

static void test_wire_udp_limit(void)
{
    uint8_t q[sizeof(k_query_example_com) + 11];
    const uint8_t opt[] = { 0x00, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0, 0 };

    expect_true(dns_udp_limit(k_query_example_com, sizeof(k_query_example_com), 1232) == 512,
                "no EDNS gives 512");
    memcpy(q, k_query_example_com, sizeof(k_query_example_com));
    memcpy(q + sizeof(k_query_example_com), opt, sizeof(opt));
    q[11] = 1;
    expect_true(dns_udp_limit(q, sizeof(q), 1232) == 1232, "EDNS 4096 clamped to 1232");
    q[sizeof(k_query_example_com) + 3] = 0x04;
    q[sizeof(k_query_example_com) + 4] = 0x00;
    expect_true(dns_udp_limit(q, sizeof(q), 1232) == 1024, "EDNS 1024 honoured");
    q[sizeof(k_query_example_com) + 3] = 0x00;
    q[sizeof(k_query_example_com) + 4] = 0x10;
    expect_true(dns_udp_limit(q, sizeof(q), 1232) == 512, "EDNS below 512 gives 512");
    expect_true(dns_udp_limit(q, sizeof(q) - 3, 1232) == 512, "cut OPT record gives 512");
}

int main(void)
{
    log_set_quiet(1);

    test_decode_basic_a_query();
    test_transaction_id_preserved_on_encode();
    test_decode_rd_ra_preservation();
    test_encode_local_a_response();
    test_encode_dns_flags();
    test_decode_rejects_truncated_and_loops();
    test_decode_more_malformed();
    test_decode_valid_compression_pointer();
    test_encode_rejects_short_buffer();
    test_wire_error_and_truncation();
    test_wire_udp_limit();

    return failures == 0 ? 0 : 1;
}
