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
#include "pkix.h"
#include <memory>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/decoder.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <evdns.h>
#include <http.h>

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string tls_ns = "urn:ietf:params:xml:ns:xmpp-tls";

    class StartTls : public Feature, public sigslot::has_slots {
    public:
        explicit StartTls(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<StartTls> {
        public:
            Description() : Feature::Description<StartTls>(tls_ns, Type::FEAT_SECURE) {};

            sigslot::tasklet<bool> offer(std::shared_ptr<sentry::span>, optional_ptr<xml_node<>> node, XMLStream &s) override {
                if (s.secured()) co_return false;
                if (!Config::config().domain(s.local_domain()).tls_enabled()) co_return false;
                auto feature = node->append_element({tls_ns, "starttls"});
                if (Config::config().domain(s.local_domain()).require_tls()) {
                    feature->append_element("required");
                }
                co_return true;
            }
        };

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction>, rapidxml::optional_ptr<rapidxml::xml_node<>> node) override {
            METRE_LOG(Metre::Log::DEBUG, "Handle StartTLS");
            if ((node->name() == "starttls" && m_stream.direction() == SESSION_DIRECTION::INBOUND) ||
                (node->name() == "proceed" && m_stream.direction() == SESSION_DIRECTION::OUTBOUND)) {
                if (!m_stream.remote_domain().empty()) {
                    m_stream.logger().debug("Negotiating TLS");
                    start_tls(m_stream, true);
                    co_return true;
                } else if (m_stream.type() == SESSION_TYPE::COMP) {
                    start_tls(m_stream, true);
                    co_return true;
                } else {
                    xml_document<> doc;
                    doc.append_element({tls_ns, "failure"});
                    m_stream.send(doc);
                    co_return false;
                }
            }
            co_return false;
        }

        bool negotiate(rapidxml::optional_ptr<rapidxml::xml_node<>> offer) override {
            if (m_stream.secured()) {
                m_stream.logger().warn("Remote is offering TLS but we already have it?");
                return false;
            }
            bool tls_enabled = Config::config().domain(m_stream.local_domain()).tls_enabled();
            if (tls_enabled) {
                xml_document<> d;
                d.append_element({tls_ns, "starttls"});
                m_stream.send(d);
                return true;
            } else {
                m_stream.logger().warn("Can't negotiate TLS as have no CTX - maybe configure a chain and pkey for {}?", m_stream.local_domain());
                if (offer->first_node("required")) {
                    m_stream.logger().warn("Remote end requires TLS, this is likely to go wrong.");
                }
                if (Config::config().domain(m_stream.remote_domain()).require_tls()) {
                    m_stream.logger().warn("We require TLS, aborting.");
                    throw Metre::stanza_policy_violation("We require TLS but you don't offer it, boo!");
                }
                return false;
            }
        }
    };

    DECLARE_FEATURE(StartTls, S2S);
    DECLARE_FEATURE(StartTls, C2S);
    DECLARE_FEATURE(StartTls, COMP);
}

namespace Metre {
    sigslot::tasklet<void> fetch_crls(std::shared_ptr<sentry::span> span, spdlog::logger & logger, const SSL *ssl, X509 *cert) {
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
        const SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_CTX *st = X509_STORE_CTX_new();
        X509_STORE_CTX_init(st, store, cert, chain);
        X509_verify_cert(st);
        STACK_OF(X509) *verified = X509_STORE_CTX_get1_chain(st);
        std::list<std::pair<std::string,std::shared_ptr<sentry::span>>> all_crls;
        for (int certnum = 0; certnum != sk_X509_num(verified); ++certnum) {
            auto current_cert = sk_X509_value(verified, certnum);
            std::unique_ptr<STACK_OF(DIST_POINT), std::function<void(STACK_OF(DIST_POINT) *)>> crldp_ptr{
                    (STACK_OF(DIST_POINT) *) X509_get_ext_d2i(current_cert, NID_crl_distribution_points, nullptr, nullptr),
                    [](STACK_OF(DIST_POINT) *crldp) { sk_DIST_POINT_pop_free(crldp, DIST_POINT_free); }};
            if (crldp_ptr) {
                auto crldp = crldp_ptr.get();
                for (int i = 0; i != sk_DIST_POINT_num(crldp); ++i) {
                    const auto *dp = sk_DIST_POINT_value(crldp, i);
                    if (dp->distpoint->type == 0) { // Full Name
                        auto names = dp->distpoint->name.fullname;
                        for (int ii = 0; ii != sk_GENERAL_NAME_num(names); ++ii) {
                            const auto *name = sk_GENERAL_NAME_value(names, ii);
                            if (name->type == GEN_URI) {
                                const auto *uri = name->d.uniformResourceIdentifier;
                                std::string uristr{reinterpret_cast<char *>(uri->data),
                                                   static_cast<std::size_t>(uri->length)};
                                logger.info("verify_tls: Fetching CRL - {}", uristr);
                                all_crls.emplace_back(std::make_pair(uristr, span->start_child("http.client", uristr)));
                                Http::crl(uristr);
                                // We don't await here, just get them going in parallel.
                            }
                        }
                    }
                }
            }
        }
        // Now we wait for them all. Order doesn't matter - we'll get new copies
        // in the rare case we happen to cross an expiry boundary, but that's
        // no biggie.
        for (auto & [uri, child_span] : all_crls) {
            auto [uristr, code, crl] = co_await Http::crl(uri);
            child_span.reset();
            logger.info("verify_tls: Fetched CRL - {}, with code {}", uri, code);
            if (!X509_STORE_add_crl(store, crl)) {
                // Erm. Whoops? Probably doesn't matter.
                ERR_clear_error();
            }
        }
    }

    int reverify_callback(int preverify_ok, X509_STORE_CTX * st) {
        std::array<char, 256> buffer{};
        std::string cert_name{"<no cert name>"};
        if (auto cert = X509_STORE_CTX_get_current_cert(st)) {
            X509_NAME_oneline(X509_get_subject_name(cert), buffer.data(), buffer.size());
            cert_name = buffer.data();
        }
        auto depth = X509_STORE_CTX_get_error_depth(st);
        if (preverify_ok) {
            Config::config().logger().info("Cert {} passed reverification: {}", depth, cert_name);
        } else {
            Config::config().logger().info("Cert {} failed reverification: {}", depth, cert_name);
            Config::config().logger().info("Error is {}", X509_verify_cert_error_string(X509_STORE_CTX_get_error(st)));
        }
        return preverify_ok;
    }

/**
     * This is a fairly massive coroutine, but I've kept it this way because it's
     * difficult to break apart. Indeed, I pulled it together out of two major callback
     * loops which were pretty nasty in complexity terms.
     *
     * @param stream
     * @param route
     * @return true if TLS verified correctly.
     */
    sigslot::tasklet<bool> verify_tls(std::shared_ptr<sentry::span> span, XMLStream &stream, Route &route) {
        SSL *ssl = bufferevent_openssl_get_ssl(stream.session().bufferevent());
        auto & domain = Config::config().domain(route.domain());
        if (!ssl) co_return false; // No TLS.
        auto & validator = domain.pkix_validator();
        auto result = co_await validator.verify_tls(span->start_child("PKIXValidator::verify_tls", route.domain()), ssl, domain.domain());
        if (result) {
            stream.logger().info("verify_tls: DANE verification succeeded");
        }
        co_return result;
    }

    bool start_tls(XMLStream &stream, bool send_proceed) {
        SSL *ssl = Config::config().domain(stream.local_domain()).tls_context().instantiate(stream.direction() == SESSION_DIRECTION::OUTBOUND, stream.remote_domain());
        bufferevent_ssl_state st = BUFFEREVENT_SSL_ACCEPTING;
        if (stream.direction() == SESSION_DIRECTION::INBOUND) {
            if (send_proceed) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "proceed");
                n->append_attribute(d.allocate_attribute("xmlns", tls_ns.c_str()));
                d.append_node(n);
                stream.send(d);
            }
            stream.restart();
        } else { //m_stream.direction() == OUTBOUND
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
