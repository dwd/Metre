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

#include "log.h"
#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include "router.h"
#include "netsession.h"
#include "config.h"
#include <memory>
#include "base64.h"
#include "rapidxml_iterators.hpp"

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string sasl_ns = "urn:ietf:params:xml:ns:xmpp-sasl";

    class SaslExternal : public Feature {
    private:
    public:
        explicit SaslExternal(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<SaslExternal> {
        public:
            Description() : Feature::Description<SaslExternal>(sasl_ns, Type::FEAT_AUTH) {};

            sigslot::tasklet<bool> offer(std::shared_ptr<sentry::span> span, optional_ptr<xml_node<>> node, XMLStream &stream) override {
                if (stream.remote_domain().empty()) co_return false;
                if (stream.s2s_auth_pair(stream.local_domain(), stream.remote_domain(), SESSION_DIRECTION::INBOUND) ==
                    XMLStream::AUTHORIZED)
                    co_return false;
                std::shared_ptr<Route> &route = RouteTable::routeTable(stream.local_domain()).route(
                        stream.remote_domain());
                if (co_await *stream.start_task("SASL EXTERNAL offer tls_auth_ok", stream.tls_auth_ok(span->start_child("tls", stream.remote_domain()), *route))) {
                    auto feature = node->append_element({sasl_ns, "mechanisms"});
                    feature->append_element("mechanism", "EXTERNAL");
                }
                co_return true;
            }
        };

        sigslot::tasklet<bool> auth(std::shared_ptr<sentry::span> span, optional_ptr<rapidxml::xml_node<>> node) {
            if (m_stream.remote_domain().empty()) co_return true;
            auto mechattr = node->first_attribute("mechanism");
            if (!mechattr || mechattr->value().empty()) throw std::runtime_error("No mechanism attribute");
            if (mechattr->value() != "EXTERNAL") {
                throw std::runtime_error("No such mechanism");
            }
            auto task = m_stream.start_task("SASL auth->response", response(span->start_child("sasl.response", m_stream.remote_domain()), node));
            co_await *task;
            co_return true;
        }

        sigslot::tasklet<bool> response(std::shared_ptr<sentry::span> span, optional_ptr<rapidxml::xml_node<>> node) {
            std::string authzid;
            if (!node->value().empty()) {
                authzid = node->value();
            }
            if (authzid == "=") {
                authzid = m_stream.remote_domain();
            } else {
                authzid = Jid(base64_decode(authzid)).domain();
            }
            if (authzid.empty()) {
                xml_document<> d;
                d.append_element({sasl_ns, "challenge"});
                m_stream.send(d);
                co_return
                true;
            }
            if (authzid != m_stream.remote_domain()) {
                xml_document<> d;
                d.append_element({sasl_ns, "success"});
                m_stream.send(d);
                co_return true;
            }
            std::shared_ptr<Route> &route = RouteTable::routeTable(m_stream.local_domain()).route(
                    m_stream.remote_domain());
            if (co_await *m_stream.start_task("SASL EXTERNAL response tls_auth_ok", m_stream.tls_auth_ok(span->start_child("tls", m_stream.remote_domain()), *route))) {
                xml_document<> d;
                d.append_element({sasl_ns, "success"});
                m_stream.send(d);
                m_stream.s2s_auth_pair(m_stream.local_domain(), authzid, SESSION_DIRECTION::INBOUND, XMLStream::AUTHORIZED);
                m_stream.set_auth_ready();
                m_stream.restart();
                co_return
                true;
            }
            throw Metre::not_authorized("Authorization failure.");
        }

        void challenge(optional_ptr<rapidxml::xml_node<>> node) {
            // Odd case - we have already told them.
            xml_document<> d;
            std::string authzid = base64_encode(m_stream.local_domain());
            d.append_element({sasl_ns, "response"}, authzid);
            m_stream.send(d);
        }

        void success(optional_ptr<rapidxml::xml_node<>> node) {
            // Good-oh.
            m_stream.s2s_auth_pair(m_stream.local_domain(), m_stream.remote_domain(), SESSION_DIRECTION::OUTBOUND, XMLStream::AUTHORIZED);
            m_stream.restart();
        }

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction> trans, optional_ptr<rapidxml::xml_node<>> node) override {
            METRE_LOG(Metre::Log::DEBUG, "Handle SASL External");
            std::string name{node->name()};
            if ((node->name() == "auth" && m_stream.direction() == SESSION_DIRECTION::INBOUND)) {
                auto task = m_stream.start_task("SASL auth", auth(trans->start_child("sasl.auth", m_stream.remote_domain()), node));
                co_await *task;
                co_return true;
            } else if (node->name() == "response" && m_stream.direction() == SESSION_DIRECTION::INBOUND) {
                auto task = m_stream.start_task("SASL response", response(trans->start_child("sasl.response", m_stream.remote_domain()), node));
                co_await *task;
                co_return true;
            } else if (node->name() == "challenge" && m_stream.direction() == SESSION_DIRECTION::OUTBOUND) {
                challenge(node);
                co_return true;
            } else if (node->name() == "success" && m_stream.direction() == SESSION_DIRECTION::OUTBOUND) {
                success(node);
                co_return true;
            } else if (node->name() == "failure" && m_stream.direction() == SESSION_DIRECTION::OUTBOUND) {
                m_stream.logger().warn("EXTERNAL was offered but not accepted.");
                // Try Dialback.
                m_stream.set_auth_ready();
                co_return true;
            }
            throw Metre::unsupported_stanza_type("Unexpected SASL element");
            co_return false;
        }

        bool negotiate(optional_ptr<rapidxml::xml_node<>> feat) override {
            bool external_found = false;
            for (auto & mech : rapidxml::children(feat)) {
                if (mech.name() != "mechanism") {
                    continue;
                }
                std::string mechanism{mech.value()};
                for (auto &c : mechanism) {
                    c = std::toupper(c);
                }
                if (mechanism == "EXTERNAL") {
                    external_found = true;
                    break;
                }
            }
            if (!external_found) return false;
            std::string authzid = base64_encode(m_stream.local_domain());
            xml_document<> d;
            auto n = d.append_element({sasl_ns, "auth"});
            n->value(authzid);
            auto mech = d.allocate_attribute("mechanism", "EXTERNAL");
            n->append_attribute(mech);
            m_stream.send(d);
            return true;
        }
    };

    DECLARE_FEATURE(SaslExternal, S2S);
}
