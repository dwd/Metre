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
#include <memory>
#include "base64.h"

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string sasl_ns = "urn:ietf:params:xml:ns:xmpp-sasl";

    class SaslExternal : public Feature {
    private:
    public:
        SaslExternal(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<SaslExternal> {
        public:
            Description() : Feature::Description<SaslExternal>(sasl_ns, FEAT_AUTH) {};

            virtual void offer(xml_node<> *node, XMLStream &stream) override {
                if (stream.remote_domain().empty()) return;
                if (stream.s2s_auth_pair(stream.local_domain(), stream.remote_domain(), INBOUND) ==
                    XMLStream::AUTHORIZED)
                    return;
                std::shared_ptr<Route> &route = RouteTable::routeTable(stream.local_domain()).route(
                        stream.remote_domain());
                if (stream.tls_auth_ok(*route)) {
                    xml_document<> *d = node->document();
                    auto feature = d->allocate_node(node_element, "mechanisms");
                    feature->append_attribute(d->allocate_attribute("xmlns", sasl_ns.c_str()));
                    auto mech = d->allocate_node(node_element, "mechanism");
                    mech->value("EXTERNAL");
                    feature->append_node(mech);
                    node->append_node(feature);
                }
            }
        };

        void auth(rapidxml::xml_node<> *node) {
            if (m_stream.remote_domain().empty()) return;
            auto mechattr = node->first_attribute("mechanism");
            if (!mechattr || !mechattr->value()) throw std::runtime_error("No mechanism attribute");
            std::string mechname = mechattr->value();
            if (mechname != "EXTERNAL") {
                throw std::runtime_error("No such mechanism");
            }
            response(node);
        }

        void response(rapidxml::xml_node<> *node) {
            std::string authzid;
            if (node->value()) {
                authzid = node->value();
            }
            if (authzid == "=") {
                authzid = m_stream.remote_domain();
            } else {
                authzid = Jid(base64_decode(authzid)).domain();
            }
            if (authzid.empty()) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "challenge");
                n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
                d.append_node(n);
                m_stream.send(d);
                return;
            }
            if (authzid != m_stream.remote_domain()) {
                throw Metre::not_authorized("Authzid and stream from differ");
            }
            std::shared_ptr<Route> &route = RouteTable::routeTable(m_stream.local_domain()).route(
                    m_stream.remote_domain());
            if (m_stream.tls_auth_ok(*route)) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "success");
                n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
                d.append_node(n);
                m_stream.send(d);
                m_stream.s2s_auth_pair(m_stream.local_domain(), authzid, INBOUND, XMLStream::AUTHORIZED);
                m_stream.set_auth_ready();
                m_stream.restart();
                return;
            }
            throw Metre::not_authorized("Authorization failure.");
        }

        void challenge(rapidxml::xml_node<> *node) {
            // Odd case - we have already told them.
            xml_document<> d;
            auto n = d.allocate_node(node_element, "response");
            n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
            std::string authzid = base64_encode(
                    reinterpret_cast<unsigned const char *>(m_stream.local_domain().c_str()),
                    m_stream.local_domain().size());
            n->value(m_stream.local_domain().c_str());
            d.append_node(n);
            m_stream.send(d);
        }

        void success(rapidxml::xml_node<> *node) {
            // Good-oh.
            m_stream.s2s_auth_pair(m_stream.local_domain(), m_stream.remote_domain(), OUTBOUND, XMLStream::AUTHORIZED);
            m_stream.restart();
        }

        bool handle(rapidxml::xml_node<> *node) override {
            xml_document<> *d = node->document();
            d->fixup<parse_default>(node, true);
            std::string name = node->name();
            if ((name == "auth" && m_stream.direction() == INBOUND)) {
                auth(node);
                return true;
            } else if (name == "response" && m_stream.direction() == INBOUND) {
                response(node);
                return true;
            } else if (name == "challenge" && m_stream.direction() == OUTBOUND) {
                challenge(node);
                return true;
            } else if (name == "success" && m_stream.direction() == OUTBOUND) {
                success(node);
                return true;
            } else {
                throw std::runtime_error("Unimplemented");
            }
            return false;
        }

        bool negotiate(rapidxml::xml_node<> *feat) override {
            bool external_found = false;
            for (auto external = feat->first_node("mechanism"); external; external = external->next_sibling(
                    "mechanism")) {
                if (external->value()) {
                    std::string mechanism{external->value(), external->value_size()};
                    for (auto &c : mechanism) {
                        c = std::toupper(c);
                    }
                    if (mechanism == "EXTERNAL") {
                        external_found = true;
                        break;
                    }
                }
            }
            if (!external_found) return false;
            xml_document<> d;
            auto n = d.allocate_node(node_element, "auth");
            n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
            auto mech = d.allocate_attribute("mechanism", "EXTERNAL");
            n->append_attribute(mech);
            std::string authzid = base64_encode(m_stream.local_domain());
            n->value(authzid.c_str());
            d.append_node(n);
            m_stream.send(d);
            return true;
        }
    };

    bool s2s_declared = Feature::declare<SaslExternal>(S2S);
}
