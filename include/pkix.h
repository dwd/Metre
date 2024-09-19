/***

Copyright 2016-2024 Dave Cridland
Copyright 2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/


#ifndef METRE_PKIX_H
#define METRE_PKIX_H

#include <openssl/ossl_typ.h>
#include <yaml-cpp/yaml.h>
#include "defs.h"
#include "dns.h"
#include <sigslot/tasklet.h>


namespace Metre {
    sigslot::tasklet<bool> verify_tls(std::shared_ptr<sentry::span>, XMLStream &stream, Route &route);

    bool start_tls(XMLStream &stream, bool send_proceed);

    class PKIXIdentity {
    public:
        PKIXIdentity() = delete;
        PKIXIdentity(PKIXIdentity const &) = delete;
        explicit PKIXIdentity(YAML::Node const & config);

        void operator=(PKIXIdentity const &) = delete;
        void apply(SSL_CTX *) const;
        [[nodiscard]] YAML::Node write() const;

    private:
        std::string m_cert_chain_file;
        std::string m_pkey_file;
        bool m_generate;
    };

    class PKIXValidator {
    public:
        PKIXValidator() = delete;
        PKIXValidator(PKIXValidator const &) = delete;
        explicit PKIXValidator(YAML::Node const & config);
        sigslot::tasklet<bool> verify_tls(std::shared_ptr<sentry::span> span, SSL *, std::string);
        sigslot::tasklet<void> fetch_crls(std::shared_ptr<sentry::span>, const SSL *, X509 * cert);
        void load();
        [[nodiscard]] YAML::Node write() const;

    private:
        bool m_crls;
        std::set<std::string, std::less<>> m_trust_anchors;
        std::vector<X509 *> m_trust_blobs;
        spdlog::logger m_log;
    };

    class TLSContext {
    public:
        TLSContext() = delete;
        TLSContext(TLSContext const &) = delete;
        void operator = (TLSContext const &) = delete;
        TLSContext(YAML::Node const & config, std::string const & domain);
        SSL_CTX* context();
        SSL * instantiate(bool connecting, std::string const & remote_domain);
        bool enabled();
        void add_identity(std::unique_ptr<PKIXIdentity> && identity);
        YAML::Node write() const;

    private:
        bool m_enabled = true;
        std::string m_domain;
        std::string m_dhparam;
        std::string m_cipherlist;
        int m_min_version;
        int m_max_version;
        std::set<std::unique_ptr<PKIXIdentity>> m_identities;
        SSL_CTX * m_ssl_ctx = nullptr;
        spdlog::logger m_log;
    };

    class pkix_error : public std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    class pkix_config_error : public pkix_error {
        using pkix_error::pkix_error;
    };

    class pkix_identity_load_error : public pkix_config_error {
        using pkix_config_error::pkix_config_error;
    };

    class dhparam_error : public pkix_error {
        using pkix_error::pkix_error;
    };
}

#endif //METRE_PKIX_H
