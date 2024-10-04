//
// Created by dave on 02/10/2024.
//

#include <gtest/gtest.h>
#include "base64.h"
#include "yaml-cpp/yaml.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <jwt-cpp/jwt.h>

std::tuple<std::string,std::string,std::string> split(std::string s) {
    const char delimiter = '.';
    std::string header = s.substr(0, s.find(delimiter));
    s.erase(0, s.find(delimiter) + 1);
    std::string payload = s.substr(0, s.find(delimiter));
    s.erase(0, s.find(delimiter) + 1);
    std::string signature = s;
    return std::make_tuple(header, payload, signature);
}

std::string bignum_to_str(const BIGNUM * bn, size_t sz) {
    // Convert the bignum to bytes:
    std::string bytes;
    bytes.resize(sz);
    BN_bn2binpad(bn, reinterpret_cast<unsigned char *>(bytes.data()), sz);
    return bytes;
}

BIGNUM * str_to_bignum(std::string_view const & s) {
    return BN_bin2bn(reinterpret_cast<const unsigned char *>(s.data()), s.length(), nullptr);
}

std::string sig_to_jwt(std::vector<unsigned char> const & sig_in) {
    const auto * sigdata = sig_in.data();
    auto * sig_st = d2i_ECDSA_SIG(nullptr, &sigdata, sig_in.size());
    const BIGNUM * r;
    const BIGNUM * s;
    ECDSA_SIG_get0(sig_st, &r, &s);
    auto ret = bignum_to_str(r, 256/8) + bignum_to_str(s, 256/8);
    ECDSA_SIG_free(sig_st);
    return ret;
}

std::vector<unsigned char> jwt_to_sig(std::string_view const & sig_in) {
    BIGNUM * r = str_to_bignum(sig_in.substr(0, sig_in.length() / 2));
    BIGNUM * s = str_to_bignum(sig_in.substr(sig_in.length() / 2));
    auto sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);

    std::vector<unsigned char> sigdata;
    auto siglen = i2d_ECDSA_SIG(sig, nullptr);
    sigdata.resize(siglen);
    auto * sigptr = sigdata.data();
    i2d_ECDSA_SIG(sig, &sigptr);
    ECDSA_SIG_free(sig);
    return sigdata;
}

// Function to create ES256 signature
std::string es256_sign(const std::string &data, EVP_PKEY *ec_key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, ec_key) != 1) {
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(mdctx, data.c_str(), data.length()) != 1) {
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSignFinal(mdctx, sig.data(), &sig_len) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    EVP_MD_CTX_free(mdctx);

    return sig_to_jwt(sig);
}


// Function to create ES256 signature
bool es256_verify(const std::string &data, EVP_PKEY *ec_key, const std::string &signature) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    bool worky = false;

    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, ec_key) != 1) {
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestVerifyUpdate(mdctx, data.c_str(), data.length()) != 1) {
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    auto sigdata = jwt_to_sig(signature);
    if (EVP_DigestVerifyFinal(mdctx, sigdata.data(), sigdata.size()) == 1) {
        worky = true;
    }

    EVP_MD_CTX_free(mdctx);

    return worky;
}

const std::string pem_key = "-----BEGIN PRIVATE KEY-----\n"
                      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n"
                      "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n"
                      "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n"
                      "-----END PRIVATE KEY-----";

TEST(JwtTest, Split) {
    std::string jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    auto [ header, payload, signature ] = split(jwt);
    EXPECT_EQ(header, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9");
    EXPECT_EQ(payload, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0");
    EXPECT_EQ(signature, "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA");
}

TEST(JwtTest, B64) {
    std::string jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    auto [ header, payload, signature ] = split(jwt);
    std::string header_dec = base64_decode(header);
    std::string payload_dec = base64_decode(payload);
    EXPECT_EQ(header_dec, "{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
}

TEST(JwtTest, Decode) {
    std::string jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    auto [ header, payload, signature ] = split(jwt);
    std::string header_dec = base64_decode(header, true);
    std::string payload_dec = base64_decode(payload, true);
    auto header_node = YAML::Load(header_dec);
    EXPECT_EQ(header_node["alg"].as<std::string>(), "ES256");
    EXPECT_EQ(header_node["typ"].as<std::string>(), "JWT");
}

TEST(JwtTest, SigTransformers) {
    std::string jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    auto [ header, payload, signature ] = split(jwt);
    auto sig_dec = base64_decode(signature, true);
    auto sig_ossl = jwt_to_sig(sig_dec);
    auto sig_again = sig_to_jwt(sig_ossl);
    auto sig_reenc1 = base64_encode(sig_dec, true, false);
    auto sig_reenc2 = base64_encode(sig_again, true, false);
    EXPECT_EQ(sig_dec, sig_again);
    EXPECT_EQ(signature, sig_reenc1);
    EXPECT_EQ(signature, sig_reenc2);
}

TEST(JwtTest, Signature) {
    std::string jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    auto [ header, payload, signature ] = split(jwt);
    std::string header_dec = base64_decode(header);
    std::string payload_dec = base64_decode(payload);
    auto * bio = BIO_new_mem_buf(pem_key.data(), pem_key.size());
    auto * key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    EXPECT_EQ(EVP_PKEY_get_bits(key), 256);
    EXPECT_STREQ(EVP_PKEY_get0_type_name(key), "EC");
    auto siggy_stuff = header + "." + payload;
    EXPECT_TRUE(jwt.starts_with(siggy_stuff));
    auto sig_calc = base64_encode(es256_sign(siggy_stuff, key), true, false);
    EXPECT_EQ(sig_calc.length(), 86);
    EXPECT_FALSE(sig_calc.ends_with('='));
}


TEST(JwtTest, SignatureVerify) {
    std::string jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    auto [ header, payload, signature ] = split(jwt);
    std::string header_dec = base64_decode(header, true);
    std::string payload_dec = base64_decode(payload, true);
    auto * bio = BIO_new_mem_buf(pem_key.data(), pem_key.size());
    auto * key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    EXPECT_EQ(EVP_PKEY_get_bits(key), 256);
    EXPECT_STREQ(EVP_PKEY_get0_type_name(key), "EC");
    auto siggy_stuff = header + "." + payload;
    EXPECT_TRUE(jwt.starts_with(siggy_stuff));
    EXPECT_TRUE(es256_verify(siggy_stuff, key, base64_decode(signature, true)));
    auto sig_calc = base64_encode(es256_sign(siggy_stuff, key), true);
    EXPECT_TRUE(es256_verify(siggy_stuff, key, base64_decode(sig_calc, true)));
}

