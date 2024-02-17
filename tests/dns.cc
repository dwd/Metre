#include "dns.h"

#include "gtest/gtest.h"

TEST(DNS_Utils, read_octet) {
    std::string data("\x47");
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint8_t>(ss), 0x47);
}

TEST(DNS_Utils, read_octet_zero) {
    std::string data("\x00", 1);
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint8_t>(ss), 0x00);
}

TEST(DNS_Utils, read_short) {
    std::string data("\xFF\x01");
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint16_t>(ss), 0xFF01);
}

TEST(DNS_Utils, read_long) {
    std::string data("\xFF\x01\x02\x03");
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint32_t>(ss), 0xFF010203);
}

TEST(DNS_Utils, read_seq) {
    std::string data("\xFF\x01\x02\x03");
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint16_t>(ss), 0xFF01);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint16_t>(ss), 0x0203);
}

TEST(DNS_Utils, read_pstr) {
    std::string data("\x0CHello, World!");
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_pf_string<uint8_t>(ss), "Hello, World");
}

TEST(DNS_Utils, read_short_zero) {
    std::string data("\x00\x00", 2);
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint16_t>(ss), 0);
}

TEST(DNS_Utils, read_short_one) {
    std::string data("\x00\x01", 2);
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_uint<uint16_t>(ss), 1);
}

TEST(DNS_Utils, read_pstr16) {
    std::string data("\x00\x0CHello, World!", 15);
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_pf_string<uint16_t>(ss), "Hello, World");
}

TEST(DNS_Utils, read_octet_empty) {
    std::string data;
    std::istringstream ss(data);
    ASSERT_THROW(Metre::DNS::Utils::read_uint<uint8_t>(ss), std::runtime_error);
}

TEST(DNS_Utils, read_shorter) {
    std::string data("\x00");
    std::istringstream ss(data);
    ASSERT_THROW(Metre::DNS::Utils::read_uint<uint16_t>(ss), std::runtime_error);
}

TEST(DNS_Utils, read_pstr_empty) {
    std::string data("\x00", 1);
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_pf_string<uint8_t>(ss), "");
}

TEST(DNS_Utils, read_pstr_short) {
    std::string data("\xFFToo short!");
    std::istringstream ss(data);
    ASSERT_THROW(Metre::DNS::Utils::read_pf_string<uint8_t>(ss), std::runtime_error);
}

TEST(DNS_Utils, read_hostname) {
    std::string data("\x05hello\x5world\x00", 13);
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_hostname(ss), "hello.world.");
}

TEST(DNS_Utils, read_hostname_root) {
    std::string data("\x00", 1);
    std::istringstream ss(data);
    ASSERT_EQ(Metre::DNS::Utils::read_hostname(ss), ".");
}

TEST(DNS_Utils, parse_svcb_2) {
    std::string data("\x00\x00\x{03}foo\x{07}example\x{03}com\x00", 19);
    auto rr = Metre::DNS::SvcbRR::parse(data);
    ASSERT_EQ(rr.priority, 0);
    ASSERT_EQ(rr.hostname, "foo.example.com.");
}

TEST(DNS_Utils, parse_svcb_3) {
    std::string data("\x00\x10\x00", 3);
    auto rr = Metre::DNS::SvcbRR::parse(data);
    ASSERT_EQ(rr.priority, 16);
    ASSERT_EQ(rr.hostname, ".");
}

TEST(DNS_Utils, parse_svcb_4) {
    std::string data("\x00\x10\x{03}foo\x{07}example\x{03}com\x00\x00\x03\x00\x02\x00\x35", 25);
    auto rr = Metre::DNS::SvcbRR::parse(data);
    ASSERT_EQ(rr.priority, 0x10);
    ASSERT_EQ(rr.hostname, "foo.example.com.");
    ASSERT_EQ(rr.port, 53);
}

TEST(DNS_Utils, parse_svcb_5) {
    std::string data("\x00\x01\x{03}foo\x{07}example\x{03}com\x00\x02\x9b\x00\x05hello", 28);
    auto rr = Metre::DNS::SvcbRR::parse(data);
    ASSERT_EQ(rr.priority, 1);
    ASSERT_EQ(rr.hostname, "foo.example.com.");
    ASSERT_EQ(rr.port, 0);
    ASSERT_TRUE(rr.params.contains(667));
    ASSERT_EQ(rr.params[667], "hello");
}

TEST(DNS_Utils, parse_svcb_9) {
    std::string data("\x00\x10\x{03}foo\x{07}example\x{03}com\x00\x00\x00\x00\x04\x00\x01\x00\x04\x00\x01\x00\x09\x02h2\x05h3-19\x00\x04\x00\x04\xc0\x00\x02\x01", 48);
    auto rr = Metre::DNS::SvcbRR::parse(data);
    ASSERT_EQ(rr.priority, 16);
    ASSERT_EQ(rr.hostname, "foo.example.com.");
    ASSERT_EQ(rr.port, 0);
    ASSERT_EQ(rr.alpn.size(), 2);
    ASSERT_TRUE(rr.alpn.contains("h2"));
    ASSERT_TRUE(rr.alpn.contains("h3-19"));
}

TEST(DNS_Utils, parse_srv_1) {
    std::string data("\x00\x10\x00\x01\x00\x80\x{03}foo\x{07}example\x{03}com\x00", 23);
    auto rr = Metre::DNS::SrvRR::parse(data);
    ASSERT_EQ(rr.hostname, "foo.example.com.");
}

TEST(DNS_Utils, parse_tlsa_1) {
    std::string data("\x01\x02\x03The rest of this should be the match data");
    auto rr = Metre::DNS::TlsaRR::parse(data);
    ASSERT_EQ(rr.matchData, "The rest of this should be the match data");
}