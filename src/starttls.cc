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
#include <openssl/decoder.h>
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
    /**
     * @param stream
     * @param route
     * @return true if TLS verified correctly.
     */
    sigslot::tasklet<bool> verify_tls(std::shared_ptr<sentry::span> span, XMLStream &stream, Route const &route) {
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
        stream.logger().debug("Trying to start TLS from {} to {}", stream.local_domain(), stream.remote_domain());
        auto & domain = Config::config().domain(stream.local_domain());
        stream.logger().debug("Trying to start TLS as {}", domain.domain());
        if (!domain.tls_enabled()) return false;
        SSL *ssl = domain.tls_context().instantiate(stream.direction() == SESSION_DIRECTION::OUTBOUND, stream.remote_domain());
        bufferevent_ssl_state st = BUFFEREVENT_SSL_ACCEPTING;
        if (stream.direction() == SESSION_DIRECTION::INBOUND) {
            if (send_proceed) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "proceed");
                n->append_attribute(d.allocate_attribute("xmlns", tls_ns));
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
        if (!bev_ssl) throw pkix_error("Cannot create OpenSSL filter");
        stream.set_secured();
        return true;
    }
}
