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
        SaslExternal(XMLStream & s) : Feature(s) {}
        class Description : public Feature::Description<SaslExternal> {
        public:
            Description() : Feature::Description<SaslExternal>(sasl_ns, FEAT_AUTH) {};
            virtual void offer(xml_node<> * node, XMLStream & stream) override {
                if (stream.tls_auth_ok()) {
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

        void auth(rapidxml::xml_node<> * node) {
            auto mechattr = node->first_attribute("mechanism");
            if (!mechattr || !mechattr->value()) throw std::runtime_error("No mechanism attribute");
            std::string mechname = mechattr->value();
            if (mechname != "EXTERNAL") {
                throw std::runtime_error("No such mechanism");
            }
            response(node);
        }

        void response(rapidxml::xml_node<> * node) {
            std::string authzid;
            if (node->value()) {
                authzid = node->value();
            }
            if (authzid == "=") {
                authzid = m_stream.remote_domain();
            } else {
                authzid = base64_decode(authzid);
            }
            if (authzid.empty()) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "challenge");
                n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
                d.append_node(n);
                m_stream.send(d);
                return;
            }
            if (m_stream.tls_auth_ok() && (m_stream.remote_domain() == authzid)) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "success");
                n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
                d.append_node(n);
                m_stream.send(d);
                m_stream.restart();
                m_stream.s2s_auth_pair(m_stream.local_domain(), m_stream.remote_domain(), INBOUND, XMLStream::AUTHORIZED);
                m_stream.set_auth_ready();
            }
        }

        void challenge(rapidxml::xml_node<> * node) {
            // Odd case - we have already told them.
            xml_document<> d;
            auto n = d.allocate_node(node_element, "response");
            n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
            std::string authzid = base64_encode(reinterpret_cast<unsigned const char *>(m_stream.local_domain().c_str()), m_stream.local_domain().size());
            n->value(m_stream.local_domain().c_str());
            d.append_node(n);
            m_stream.send(d);
        }

        void success(rapidxml::xml_node<> * node) {
            // Good-oh.
            m_stream.restart();
            m_stream.s2s_auth_pair(m_stream.local_domain(), m_stream.remote_domain(), OUTBOUND, XMLStream::AUTHORIZED);
            m_stream.set_auth_ready();
        }

        bool handle(rapidxml::xml_node<> * node) override {
            xml_document<> * d = node->document();
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

        bool negotiate(rapidxml::xml_node<> * feat) override {
            bool external_found = false;
            for (auto external = feat->first_node("mechanism"); external; external = external->next_sibling("mechanism")) {
                if (std::string(external->name()) == "EXTERNAL") {
                    external_found = true;
                    break;
                }
            }
            if (!external_found) return false;
            xml_document<> d;
            auto n = d.allocate_node(node_element, "auth");
            n->append_attribute(d.allocate_attribute("xmlns", sasl_ns.c_str()));
            auto mech = d.allocate_attribute("mechanism", "EXTERNAL");
            n->append_attribute(mech);
            n->value(m_stream.local_domain().c_str());
            d.append_node(n);
            m_stream.send(d);
            return true;
        }
    };

    bool s2s_declared = Feature::declare<SaslExternal>(S2S);
}
