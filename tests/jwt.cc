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


std::string openssl_errs() {
    std::ostringstream os;
    std::array<char, 1024> buf;
    while(auto err = ERR_get_error()) {
        os << ERR_error_string(err, buf.data()) << std::endl;
    }
    return os.str();
}

class JWTVerifier {
private:
    EVP_PKEY * m_public_key = nullptr;
    const std::string key_type = "EC";
    const std::string algo_prefix = "ES";

public:
    // Mostly exposed for testing.
    static std::tuple<std::string_view,std::string_view,std::string_view> split(std::string_view s) {
        const char delimiter = '.';
        std::string_view header = s.substr(0, s.find(delimiter));
        s.remove_prefix(s.find(delimiter) + 1);
        std::string_view payload = s.substr(0, s.find(delimiter));
        s.remove_prefix(s.find(delimiter) + 1);
        std::string_view signature = s;
        return std::make_tuple(header, payload, signature);
    }

    static BIGNUM * str_to_bignum(std::string_view const & s) {
        return BN_bin2bn(reinterpret_cast<const unsigned char *>(s.data()), s.length(), nullptr);
    }

    static std::vector<unsigned char> jwt_to_sig(std::string_view const & sig_64) {
        auto sig_in = base64_decode(sig_64, true);
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
public:
    explicit JWTVerifier(std::string const & public_key) {
        auto * bio = BIO_new_mem_buf(public_key.data(), public_key.size());
        m_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        if (!m_public_key) {
            throw std::runtime_error("PEM_read_bio_Privatekey failed: " + openssl_errs());
        }
        if (EVP_PKEY_get0_type_name(m_public_key) != key_type) {
            EVP_PKEY_free(m_public_key);
            m_public_key = nullptr;
            throw std::runtime_error("Wrong key type");
        }
    }
    explicit JWTVerifier(EVP_PKEY * public_key) : m_public_key(public_key) {
        if (EVP_PKEY_get0_type_name(m_public_key) != key_type) {
            EVP_PKEY_free(m_public_key);
            m_public_key = nullptr;
            throw std::runtime_error("Wrong key type");
        }
    }
    JWTVerifier(JWTVerifier && other)  noexcept : m_public_key(other.m_public_key) {
        other.m_public_key = nullptr;
    }
    JWTVerifier(JWTVerifier const &) = delete;

    [[nodiscard]] YAML::Node verify(std::string_view const & jwt) const {
        const auto [header64, payload64, signature64] = split(jwt);
        auto header_str = base64_decode(header64, true);
        auto header = YAML::Load(header_str);
        if (header["typ"].as<std::string>("") != "JWT") {
            throw std::runtime_error("Not a JWT");
        }
        auto alg = header["alg"].as<std::string>("");
        if (!alg.starts_with(algo_prefix)) {
            throw std::runtime_error("Not an " + algo_prefix + " type JWT - " + alg);
        }
        const EVP_MD * md = nullptr;
        if (alg == "ES256") {
            md = EVP_sha256();
        } else if (alg == "ES384") {
            md = EVP_sha384();
        } else if (alg == "ES512") {
            md = EVP_sha512();
        }
        auto signature = jwt_to_sig(signature64);
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        try {
            if (EVP_DigestVerifyInit(md_ctx, nullptr, md, nullptr, m_public_key) != 1) {
                throw std::runtime_error("EVP_DigestVerifyInit failed" + openssl_errs());
            };
            if (EVP_DigestVerifyUpdate(md_ctx, reinterpret_cast<const unsigned char *>(header64.data()), header64.size()) != 1) {
                throw std::runtime_error("EVP_DigestVerifyUpdate failed" + openssl_errs());
            };
            if (EVP_DigestVerifyUpdate(md_ctx, reinterpret_cast<const unsigned char *>("."), 1) != 1) {
                throw std::runtime_error("EVP_DigestVerifyUpdate failed" + openssl_errs());
            };
            if (EVP_DigestVerifyUpdate(md_ctx, reinterpret_cast<const unsigned char *>(payload64.data()), payload64.size()) != 1) {
                throw std::runtime_error("EVP_DigestVerifyUpdate failed" + openssl_errs());
            };
            if (EVP_DigestVerifyFinal(md_ctx, reinterpret_cast<unsigned char *>(signature.data()), signature.size()) != 1) {
                throw std::runtime_error("JWT signature failed");
            }
        } catch(...) {
            EVP_MD_CTX_free(md_ctx);
            throw;
        }
        EVP_MD_CTX_free(md_ctx);
        auto payload = base64_decode(payload64, true);
        return YAML::Load(payload);
    }

    ~JWTVerifier() {
        if (m_public_key != nullptr) EVP_PKEY_free(m_public_key);
    }
};

std::string bignum_to_str(const BIGNUM * bn, size_t sz) {
    // Convert the bignum to bytes:
    std::string bytes;
    bytes.resize(sz);
    BN_bn2binpad(bn, reinterpret_cast<unsigned char *>(bytes.data()), sz);
    return bytes;
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

// Function to create ES256 signature
std::string es_sign(const std::string &data, EVP_PKEY *ec_key, const EVP_MD * md) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, ec_key) != 1) {
        throw std::runtime_error("EVP_DigestSignInit failed" + openssl_errs());
    }

    if (EVP_DigestSignUpdate(mdctx, data.c_str(), data.length()) != 1) {
        throw std::runtime_error("EVP_DigestSignUpdate failed" + openssl_errs());
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal failed" + openssl_errs());
    }

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSignFinal(mdctx, sig.data(), &sig_len) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal failed" + openssl_errs());
    }

    EVP_MD_CTX_free(mdctx);

    return sig_to_jwt(sig);
}

std::string es256_sign(const std::string &data, EVP_PKEY *ec_key) {
    return es_sign(data, ec_key, EVP_sha256());
}

// Function to create ES256 signature
bool es_verify(const std::string &data, EVP_PKEY *ec_key, const EVP_MD * md, const std::string_view &signature) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    bool worky = false;

    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, ec_key) != 1) {
        throw std::runtime_error("EVP_DigestVerifyInit failed" + openssl_errs());
    }

    if (EVP_DigestVerifyUpdate(mdctx, data.c_str(), data.length()) != 1) {
        throw std::runtime_error("EVP_DigestVerifyUpdate failed" + openssl_errs());
    }

    auto sigdata = JWTVerifier::jwt_to_sig(signature);
    if (EVP_DigestVerifyFinal(mdctx, sigdata.data(), sigdata.size()) == 1) {
        worky = true;
    }

    EVP_MD_CTX_free(mdctx);

    return worky;
}
bool es256_verify(const std::string & data, EVP_PKEY * ec_key, const std::string_view &signature) {
    return es_verify(data, ec_key, EVP_sha256(), signature);
}

const std::string pem_key = "-----BEGIN PRIVATE KEY-----\n"
                      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n"
                      "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n"
                      "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n"
                      "-----END PRIVATE KEY-----";
const std::string pub_key = "-----BEGIN PUBLIC KEY-----\n"
                            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n"
                            "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n"
                            "-----END PUBLIC KEY-----";
const std::string jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";

const std::string ps256_jwt = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg";
const std::string ps256_pub_key = "-----BEGIN PUBLIC KEY-----\n"
                                  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n"
                                  "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n"
                                  "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n"
                                  "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n"
                                  "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n"
                                  "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n"
                                  "mwIDAQAB\n"
                                  "-----END PUBLIC KEY-----";
const std::string ps256_key = "-----BEGIN PRIVATE KEY-----\n"
                              "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj\n"
                              "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
                              "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n"
                              "qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg\n"
                              "p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR\n"
                              "ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi\n"
                              "VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV\n"
                              "laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8\n"
                              "sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H\n"
                              "mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY\n"
                              "dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw\n"
                              "ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ\n"
                              "DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T\n"
                              "N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t\n"
                              "0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv\n"
                              "t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU\n"
                              "AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk\n"
                              "48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL\n"
                              "DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK\n"
                              "xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA\n"
                              "mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh\n"
                              "2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz\n"
                              "et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr\n"
                              "VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD\n"
                              "TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc\n"
                              "dn/RsYEONbwQSjIfMPkvxF+8HQ==\n"
                              "-----END PRIVATE KEY-----";

TEST(JwtTest, Split) {
    auto [ header, payload, signature ] = JWTVerifier::split(jwt);
    EXPECT_EQ(header, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9");
    EXPECT_EQ(payload, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0");
    EXPECT_EQ(signature, "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA");
}

TEST(JwtTest, B64) {
    auto [ header, payload, signature ] = JWTVerifier::split(jwt);
    std::string header_dec = base64_decode(header);
    std::string payload_dec = base64_decode(payload);
    EXPECT_EQ(header_dec, "{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
}

TEST(JwtTest, Decode) {
    auto [ header, payload, signature ] = JWTVerifier::split(jwt);
    std::string header_dec = base64_decode(header, true);
    std::string payload_dec = base64_decode(payload, true);
    auto header_node = YAML::Load(header_dec);
    EXPECT_EQ(header_node["alg"].as<std::string>(), "ES256");
    EXPECT_EQ(header_node["typ"].as<std::string>(), "JWT");
}

TEST(JwtTest, SigTransformers) {
    auto [ header, payload, signature ] = JWTVerifier::split(jwt);
    auto sig_ossl = JWTVerifier::jwt_to_sig(signature);
    auto sig_again = sig_to_jwt(sig_ossl);
    auto sig_dec = base64_decode(signature, true);
    auto sig_reenc1 = base64_encode(sig_dec, true, false);
    auto sig_reenc2 = base64_encode(sig_again, true, false);
    EXPECT_EQ(sig_dec, sig_again);
    EXPECT_EQ(signature, sig_reenc1);
    EXPECT_EQ(signature, sig_reenc2);
}

TEST(JwtTest, Signature) {
    auto [ header, payload, signature ] = JWTVerifier::split(jwt);
    std::string header_dec = base64_decode(header);
    std::string payload_dec = base64_decode(payload);
    auto * bio = BIO_new_mem_buf(pem_key.data(), pem_key.size());
    auto * key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    EXPECT_EQ(EVP_PKEY_get_bits(key), 256);
    EXPECT_STREQ(EVP_PKEY_get0_type_name(key), "EC");
    auto siggy_stuff = std::string(header) + "." + std::string(payload);
    EXPECT_TRUE(jwt.starts_with(siggy_stuff));
    auto sig_calc = base64_encode(es256_sign(siggy_stuff, key), true, false);
    EXPECT_EQ(sig_calc.length(), 86);
    EXPECT_FALSE(sig_calc.ends_with('='));
}


TEST(JwtTest, SignatureVerify) {
    auto [ header, payload, signature ] = JWTVerifier::split(jwt);
    std::string header_dec = base64_decode(header, true);
    std::string payload_dec = base64_decode(payload, true);
    auto * public_bio = BIO_new_mem_buf(pub_key.data(), pub_key.size());
    auto * public_key = PEM_read_bio_PUBKEY(public_bio, nullptr, nullptr, nullptr);
    EXPECT_EQ(EVP_PKEY_get_bits(public_key), 256);
    EXPECT_STREQ(EVP_PKEY_get0_type_name(public_key), "EC");
    auto siggy_stuff = std::string(header) + "." + std::string(payload);
    EXPECT_TRUE(jwt.starts_with(siggy_stuff));
    EXPECT_TRUE(es256_verify(siggy_stuff, public_key, signature));
    auto * bio = BIO_new_mem_buf(pem_key.data(), pem_key.size());
    auto * key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    auto sig_calc = base64_encode(es256_sign(siggy_stuff, key), true);
    EXPECT_TRUE(es256_verify(siggy_stuff, public_key, sig_calc));
}

TEST(JWTVerifier, VerifyKey) {
    auto * public_bio = BIO_new_mem_buf(pub_key.data(), pub_key.size());
    auto * public_key = PEM_read_bio_PUBKEY(public_bio, nullptr, nullptr, nullptr);
    EXPECT_EQ(EVP_PKEY_get_bits(public_key), 256);
    EXPECT_STREQ(EVP_PKEY_get0_type_name(public_key), "EC");
    auto const & verifier = JWTVerifier(public_key);
    auto payload = verifier.verify(jwt);
    EXPECT_TRUE(payload);
    EXPECT_EQ(payload["sub"].as<std::string>(), "1234567890");
    EXPECT_TRUE(payload["admin"].as<bool>());
    EXPECT_ANY_THROW(auto dummy = verifier.verify(ps256_jwt));
}

TEST(JWTVerifier, Verify) {
    auto const & verifier = JWTVerifier(pub_key);
    auto payload = verifier.verify(jwt);
    EXPECT_TRUE(payload);
    EXPECT_EQ(payload["sub"].as<std::string>(), "1234567890");
    EXPECT_TRUE(payload["admin"].as<bool>());
    EXPECT_ANY_THROW(auto dummy = verifier.verify(ps256_jwt));
}
