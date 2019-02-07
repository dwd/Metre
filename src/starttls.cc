/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

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

#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include "router.h"
#include "netsession.h"
#include "config.h"
#include "log.h"
#include "tls.h"
#include <memory>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <dhparams.h>
#include <openssl/x509v3.h>
#include <evdns.h>
#include <http.h>

using namespace Metre;
using namespace rapidxml;
namespace {
    DH *dh_callback(SSL *, int, int keylength) {
        if (keylength < 2048) {
            METRE_LOG(Metre::Log::DEBUG, "DH used 1024");
            return get_dh1024();
        } else if (keylength < 4096) {
            METRE_LOG(Metre::Log::DEBUG, "DH used 2048");
            return get_dh2048();
        } else {
            METRE_LOG(Metre::Log::DEBUG, "DH used 4096");
            return get_dh4096();
        }
    }

    template<int minkey>
    DH *dh_callback(SSL *, int, int keylength) {
        METRE_LOG(Metre::Log::DEBUG, "DH params requested, keylength " << keylength << ", min " << minkey);
        return dh_callback(nullptr, 0, keylength < minkey ? minkey : keylength);
    }

    void setup_session(SSL *ssl, std::string const &remote_domain) {
        Config::Domain const &domain = Config::config().domain(remote_domain);
        SSL_set_cipher_list(ssl, domain.cipherlist().c_str());
        std::string const &dhparam = domain.dhparam();
        if (dhparam == "4096") {
            SSL_set_tmp_dh_callback(ssl, dh_callback<4096>);
        } else if (dhparam == "1024") {
            SSL_set_tmp_dh_callback(ssl, dh_callback<1024>);
        } else if (dhparam == "2048") {
            SSL_set_tmp_dh_callback(ssl, dh_callback<2048>);
        } else {
            METRE_LOG(Metre::Log::DEBUG, "Don't know what dhparam size " << dhparam << " means, using 2048");
            SSL_set_tmp_dh_callback(ssl, dh_callback<2048>);
        }
    }
}

namespace {
    const std::string tls_ns = "urn:ietf:params:xml:ns:xmpp-tls";

    class StartTls : public Feature, public sigslot::has_slots {
    public:
        explicit StartTls(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<StartTls> {
        public:
            Description() : Feature::Description<StartTls>(tls_ns, FEAT_SECURE) {};

            sigslot::tasklet<bool> offer(xml_node<> *node, XMLStream &s) override {
                if (s.secured()) co_returnfalse;
                SSL_CTX *ctx = Config::config().domain(s.local_domain()).ssl_ctx();
                if (!ctx) co_returnfalse;
                xml_document<> *d = node->document();
                auto feature = d->allocate_node(node_element, "starttls");
                feature->append_attribute(d->allocate_attribute("xmlns", tls_ns.c_str()));
                if (Config::config().domain(s.local_domain()).require_tls()) {
                    auto required = d->allocate_node(node_element, "required");
                    feature->append_node(required);
                }
                node->append_node(feature);
                co_return
                true;
            }
        };

        sigslot::tasklet<bool> handle(rapidxml::xml_node<> *node) override {
            xml_document<> *d = node->document();
            d->fixup<parse_default>(node, true);
            std::string name = node->name();
            if ((name == "starttls" && m_stream.direction() == INBOUND) ||
                (name == "proceed" && m_stream.direction() == OUTBOUND)) {
                if (!m_stream.remote_domain().empty()) {
                    std::shared_ptr<Route> &route = RouteTable::routeTable(m_stream.local_domain()).route(
                            m_stream.remote_domain());
                    m_stream.freeze();
                    route->collateNames().connect(this, [this](Route &r) {
                        METRE_LOG(Metre::Log::DEBUG, "Negotiating TLS");
                        m_stream.in_context([this]() { start_tls(m_stream, true); });
                    }, true);
                    co_return true;
                } else if (m_stream.type() == COMP) {
                    start_tls(m_stream, true);
                    co_return true;
                } else {
                    xml_document<> doc;
                    auto failure = doc.allocate_node(node_element, "failure");
                    failure->append_attribute(doc.allocate_attribute("xmlns", tls_ns.c_str()));
                    m_stream.send(doc);
                    co_return false;
                }
            }
            co_return false;
        }

        bool negotiate(rapidxml::xml_node<> *) override {
            SSL_CTX *ctx = Config::config().domain(m_stream.local_domain()).ssl_ctx();
            if (!ctx) return false;
            xml_document<> d;
            auto n = d.allocate_node(node_element, "starttls");
            n->append_attribute(d.allocate_attribute("xmlns", tls_ns.c_str()));
            d.append_node(n);
            m_stream.send(d);
            return true;
        }
    };

    DECLARE_FEATURE(StartTls, S2S);
    DECLARE_FEATURE(StartTls, C2S);
    DECLARE_FEATURE(StartTls, COMP);
}

namespace Metre {
    bool tlsa_matches(DNS::TlsaRR const &rr, X509 *cert) {
        unsigned char *freeme = nullptr;
        unsigned char *matchdata;
        unsigned char digest[SHA512_DIGEST_LENGTH];
        int len = 0;
        bool retval = false;
        if (rr.selector == DNS::TlsaRR::FullCert) {
            len = i2d_X509(cert, &freeme);
        } else if (rr.selector == DNS::TlsaRR::SubjectPublicKeyInfo) {
            X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
            len = i2d_X509_PUBKEY(pubkey, &freeme);
        } else {
            goto match_fail;
        }
        if (len <= 0) goto match_fail;
        matchdata = freeme;
        if (rr.matchType == DNS::TlsaRR::Sha256) {
            SHA256(freeme, len, digest);
            matchdata = digest;
            len = SHA256_DIGEST_LENGTH;
        } else if (rr.matchType == DNS::TlsaRR::Sha512) {
            SHA256(freeme, len, digest);
            matchdata = digest;
            len = SHA512_DIGEST_LENGTH;
        } else if (rr.matchType != DNS::TlsaRR::Full) {
            goto match_fail;
        }
        if (rr.matchData == std::string(reinterpret_cast<char *>(matchdata), static_cast<unsigned long>(len)))
            retval = true;
        match_fail:
        OPENSSL_free(freeme);
        return retval;
    }

    sigslot::tasklet<bool> verify_tls(XMLStream &stream, Route &route) {
        SSL *ssl = bufferevent_openssl_get_ssl(stream.session().bufferevent());
        if (!ssl) co_return false; // No TLS.
        if (X509_V_OK != SSL_get_verify_result(ssl)) {
            METRE_LOG(Metre::Log::INFO, "Cert failed verification but rechecking anyway.");
        } // TLS failed basic verification.
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (!cert) {
            METRE_LOG(Metre::Log::INFO, "No cert, so no auth");
            co_return false;
        }
        METRE_LOG(Metre::Log::DEBUG, "[Re]verifying TLS for " + route.domain());
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
        SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_VERIFY_PARAM *vpm = X509_VERIFY_PARAM_new();
        if (Config::config().domain(route.domain()).auth_pkix_status()) {
            stream.crl([&](X509_CRL *crl) {
                if (!X509_STORE_add_crl(store, crl)) {
                    // Most likely already added. Wipe the error.
                    ERR_clear_error();
                }
            });
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK_ALL);
        }
        X509_VERIFY_PARAM_set1_host(vpm, route.domain().c_str(), route.domain().size());
        // Add RFC 6125 additional names.
        auto srv = *co_await Config::config().domain(route.domain()).SrvLookup(route.domain());
        if (srv.error.empty()) {
            if (srv.dnssec) {
                for (auto &rr : srv.rrs) {
                    X509_VERIFY_PARAM_add1_host(vpm, rr.hostname.c_str(), rr.hostname.size());
                }
            }
        }
        X509_STORE_CTX *st = X509_STORE_CTX_new();
        X509_STORE_CTX_set0_param(st, vpm); // Hands ownership to st.
        X509_STORE_CTX_init(st, store, cert, chain);
        bool valid = (X509_verify_cert(st) == 1);
        if (!valid) {
            auto error = X509_STORE_CTX_get_error(st);
            auto depth = X509_STORE_CTX_get_error_depth(st);
            char buf[1024];
            METRE_LOG(Log::WARNING,
                      "Chain failed validation: " << ERR_error_string(error, buf) << " (at " << depth << ")");
        }
        STACK_OF(X509) *verified = X509_STORE_CTX_get1_chain(st);
        // If we have DANE records, iterate through them to find one that works.
        bool dane_ok = false;
        bool dane_present = false;
        if (srv.dnssec) {
            for (auto &rr : srv.rrs) {
                auto tlsa = *co_await Config::config().domain(route.domain()).TlsaLookup(rr.port, rr.hostname);
                if (!tlsa.dnssec) continue;
                if (!tlsa.error.empty()) continue;
                dane_present = true;
                for (auto &rr : tlsa.rrs) {
                    switch (rr.certUsage) {
                        case DNS::TlsaRR::CertConstraint:
                            if (!valid) continue;
                            // Fallthrough
                        case DNS::TlsaRR::DomainCert:
                            if (tlsa_matches(rr, sk_X509_value(verified, 0))) {
                                dane_ok = true;
                                goto tlsa_done;
                            }
                            break;
                        case DNS::TlsaRR::CAConstraint:
                            if (!valid) continue;
                            // Fallthrough
                        case DNS::TlsaRR::TrustAnchorAssertion:
                            if (sk_X509_num(verified) == 0) continue; // Problem there.
                            X509 *ta = sk_X509_value(verified, sk_X509_num(verified) - 1);
                            if (tlsa_matches(rr, ta)) {
                                if (rr.certUsage == DNS::TlsaRR::TrustAnchorAssertion) {
                                    dane_ok = (1 ==
                                               X509_check_host(cert, route.domain().c_str(), route.domain().size(),
                                                               0,
                                                               NULL));
                                } else {
                                    dane_ok = true;
                                }
                                if (dane_ok) goto tlsa_done;
                            }
                    }
                }
            }
        }
        tlsa_done:
        sk_X509_pop_free(verified, &X509_free);
        X509_STORE_CTX_free(st);
        METRE_LOG(Metre::Log::INFO, "[Re]verify: DANE " << (dane_present ? "Present" : "Not present") << ", checked "
                                                        << (dane_ok ? "OK" : "Not OK") << ", PKIX "
                                                        << (valid ? "Passed" : "Failed"));
        co_return dane_present ? dane_ok : valid;
    }

    bool prep_crl(XMLStream & stream) {
        if (Config::config().fetch_pkix_status()) return false;
        SSL *ssl = bufferevent_openssl_get_ssl(stream.session().bufferevent());
        if (!ssl) return false; // No TLS.
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (!cert) {
            METRE_LOG(Metre::Log::INFO, "No cert, so no auth");
            return false;
        }
        bool fetch_any = false;
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
        SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_CTX *st = X509_STORE_CTX_new();
        X509_STORE_CTX_init(st, store, cert, chain);
        X509_verify_cert(st);
        STACK_OF(X509) *verified = X509_STORE_CTX_get1_chain(st);
        for (int certnum = 0; certnum != sk_X509_num(verified); ++certnum) {
            auto cert = sk_X509_value(verified, certnum);
            std::unique_ptr<STACK_OF(DIST_POINT),std::function<void(STACK_OF(DIST_POINT) *)>> crldp_ptr{(STACK_OF(DIST_POINT)*)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL),[](STACK_OF(DIST_POINT) * crldp){ sk_DIST_POINT_pop_free(crldp, DIST_POINT_free); }};
            auto crldp = crldp_ptr.get();
            if (crldp) {
                for (int i = 0; i != sk_DIST_POINT_num(crldp); ++i) {
                    DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
                    if (dp->distpoint->type == 0) { // Full Name
                        auto names = dp->distpoint->name.fullname;
                        for (int ii = 0; ii != sk_GENERAL_NAME_num(names); ++ii) {
                            GENERAL_NAME *name = sk_GENERAL_NAME_value(names, ii);
                            if (name->type == GEN_URI) {
                                ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
                                std::string uristr{reinterpret_cast<char *>(uri->data),
                                                   static_cast<std::size_t>(uri->length)};
                                METRE_LOG(Metre::Log::INFO, "Fetching CRL - " << uristr);
                                stream.fetch_crl(uristr);
                                fetch_any = true;
                            }
                        }
                    }
                }
            }
        }
        return fetch_any;
    }

    bool start_tls(XMLStream &stream, bool send_proceed) {
        SSL_CTX *ctx = Config::config().domain(stream.local_domain()).ssl_ctx();
        if (!ctx) throw std::runtime_error("Failed to load certificates");
        SSL *ssl = SSL_new(ctx);
        setup_session(ssl, stream.remote_domain());
        if (!ssl) throw std::runtime_error("Failure to initiate TLS, sorry!");
        bufferevent_ssl_state st = BUFFEREVENT_SSL_ACCEPTING;
        if (stream.direction() == INBOUND) {
            SSL_set_accept_state(ssl);
            if (send_proceed) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "proceed");
                n->append_attribute(d.allocate_attribute("xmlns", tls_ns.c_str()));
                d.append_node(n);
                stream.send(d);
            }
        } else { //m_stream.direction() == OUTBOUND
            SSL_set_connect_state(ssl);
            SSL_set_tlsext_host_name(ssl, stream.remote_domain().c_str());
            st = BUFFEREVENT_SSL_CONNECTING;
        }
        struct bufferevent *bev = stream.session().bufferevent();
        struct bufferevent *bev_ssl = bufferevent_openssl_filter_new(bufferevent_get_base(bev), bev, ssl, st,
                                                                     BEV_OPT_CLOSE_ON_FREE);
        stream.session().bufferevent(bev_ssl); // Might set it to NULL - this is OK!
        if (!bev_ssl) throw std::runtime_error("Cannot create OpenSSL filter");
        stream.set_secured();
        return true;
    }
}