//
// Created by dave on 17/10/2024.
//

#ifndef METRE_JWT_H
#define METRE_JWT_H

#include <string>
#include <yaml-cpp/yaml.h>
#include <openssl/types.h>
#include <vector>

/**
 * This is a very quick JWT verifier. It cannot sign, and only handles ES* - and is only tested with ES256.
 * If you want it expanded, shout! (or give me a PR).
 */

namespace Metre {
    class JWTVerifier {
    private:
        EVP_PKEY * m_public_key = nullptr;
        static const std::string key_type;
        static const std::string algo_prefix;

    public:
        // Mostly exposed for testing.
        static std::tuple<std::string_view,std::string_view,std::string_view> split(std::string_view s);
        static BIGNUM * str_to_bignum(std::string_view const & s);
        static std::vector<unsigned char> jwt_to_sig(std::string_view const & sig_64);
    public:
        explicit JWTVerifier(std::string const & public_key);
        explicit JWTVerifier(EVP_PKEY * public_key);
        JWTVerifier(JWTVerifier && other)  noexcept;
        JWTVerifier(JWTVerifier const &) = delete;

        [[nodiscard]] YAML::Node verify(std::string_view const & jwt) const;

        ~JWTVerifier();
    };
}

#endif //METRE_JWT_H
