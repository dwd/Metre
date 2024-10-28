//
// Created by dave on 17/10/2024.
//
#include "jwt.h"
#include "base64.h"
#include <yaml-cpp/yaml.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace {
    std::string openssl_errs() {
        std::ostringstream os;
        std::array<char, 1024> buf;
        while(auto err = ERR_get_error()) {
            os << ERR_error_string(err, buf.data()) << std::endl;
        }
        return os.str();
    }
}

using namespace Metre;

const std::string JWTVerifier::key_type = "EC";
const std::string JWTVerifier::algo_prefix = "ES";

std::tuple<std::string_view,std::string_view,std::string_view> JWTVerifier::split(std::string_view s) {
    const char delimiter = '.';
    std::string_view header = s.substr(0, s.find(delimiter));
    s.remove_prefix(s.find(delimiter) + 1);
    std::string_view payload = s.substr(0, s.find(delimiter));
    s.remove_prefix(s.find(delimiter) + 1);
    std::string_view signature = s;
    return std::make_tuple(header, payload, signature);
}

BIGNUM * JWTVerifier::str_to_bignum(std::string_view const & s) {
    return BN_bin2bn(reinterpret_cast<const unsigned char *>(s.data()), s.length(), nullptr);
}

std::vector<unsigned char> JWTVerifier::jwt_to_sig(std::string_view const & sig_64) {
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

JWTVerifier::JWTVerifier(std::string const & public_key) {
    if (public_key.starts_with("-----BEGIN PUBLIC KEY-----")) {
        auto *bio = BIO_new_mem_buf(public_key.data(), public_key.size());
        m_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    } else {
        auto * fp = std::fopen(public_key.c_str(), "r");
        if (fp) {
            m_public_key = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
            std::fclose(fp);
        } else {
            throw std::runtime_error("Couldn't open file: " + public_key);
        }
    }
    if (!m_public_key) {
        throw std::runtime_error("PEM_read_bio_PUBKEY failed: " + openssl_errs());
    }
    if (EVP_PKEY_get0_type_name(m_public_key) != key_type) {
        EVP_PKEY_free(m_public_key);
        m_public_key = nullptr;
        throw std::runtime_error("Wrong key type");
    }
}

JWTVerifier::JWTVerifier(EVP_PKEY * public_key) : m_public_key(public_key) {
    if (EVP_PKEY_get0_type_name(m_public_key) != key_type) {
        EVP_PKEY_free(m_public_key);
        m_public_key = nullptr;
        throw std::runtime_error("Wrong key type");
    }
}

JWTVerifier::JWTVerifier(JWTVerifier && other)  noexcept : m_public_key(other.m_public_key) {
    other.m_public_key = nullptr;
}

YAML::Node JWTVerifier::verify(std::string_view const & jwt) const {
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
    } else {
        throw std::runtime_error("Unknown algorithm " + alg);
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

JWTVerifier::~JWTVerifier() {
    if (m_public_key != nullptr) EVP_PKEY_free(m_public_key);
}

