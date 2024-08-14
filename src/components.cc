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
#include "netsession.h"
#include "stanza.h"
#include "router.h"
#include "log.h"
#include "config.h"
#include "endpoint.h"
#include <openssl/sha.h>

using namespace rapidxml;
using namespace Metre;

namespace {
    const std::string sasl_ns = "jabber:component:accept";

    class Component : public Feature, public sigslot::has_slots {
    public:
        explicit Component(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<Component> {
        public:
            Description() : Feature::Description<Component>(sasl_ns, FEAT_POSTAUTH) {};
        };

        [[nodiscard]] std::string handshake_content() const {
            Config::Domain const &domain = Config::config().domain(m_stream.local_domain());
            if (domain.transport_type() != COMP) {
                throw Metre::host_unknown("Not a known component domain");
            }
            if (!domain.auth_secret().has_value()) {
                throw Metre::host_unknown("No secret for known component domain");
            }
            std::string const &key(*domain.auth_secret());
            std::string concat = m_stream.stream_id() + key;
            std::string binoutput;
            binoutput.resize(20);
            SHA1(reinterpret_cast<const unsigned char *>(concat.data()), concat.length(),
                 const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(binoutput.data())));
            std::string hexoutput;
            for (char sc : binoutput) {
                auto c = reinterpret_cast<unsigned char &>(sc);
                int low = c & 0x0F;
                int high = (c & 0xF0) >> 4;
                hexoutput += static_cast<char>(((high < 0x0A) ? '0' : ('a' - 10)) + high);
                hexoutput += static_cast<char>(((low < 0x0A) ? '0' : ('a' - 10)) + low);
            }
            assert(hexoutput.length() == 40);
            return hexoutput;
        }

        void send_handshake(XMLStream &s) {
            std::string hexoutput(handshake_content());
            xml_document<> d;
            d.append_element("handshake", hexoutput);
            m_stream.send(d);
        }

        bool negotiate(optional_ptr<rapidxml::xml_node<>>) override {
            m_stream.auth_state_changed.connect(this, &Component::send_handshake);
            return false;
        }

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction> span, optional_ptr<rapidxml::xml_node<>> node) override {
            METRE_LOG(Metre::Log::DEBUG, "Handle component");

            std::unique_ptr<Stanza> s;
            if (node->name() == "message") {
                s = std::make_unique<Message>(node);
            } else if (node->name() == "iq") {
                s = std::make_unique<Iq>(node);
            } else if (node->name() == "presence") {
                s = std::make_unique<Presence>(node);
            } else if (node->name() == "handshake") {
                if (node->value() != handshake_content()) {
                    throw not_authorized("Component handshake failure");
                }

                std::string const & domain = m_stream.local_domain();
                m_stream.user(domain);
                METRE_LOG(Metre::Log::DEBUG, "Component registering session domain: domain=[" << domain << "] session=[" << m_stream.session().serial() << "]");
                Router::register_session_domain(domain, m_stream.session());
                auto session_ptr = Router::session_by_domain(m_stream.local_domain());
                RouteTable::routeTable(domain).route(domain)->set_to(session_ptr);
                {
                    xml_document<> doc;
                    doc.append_element("handshake");
                    m_stream.send(doc);
                }
                co_return true;
            } else {
                throw Metre::unsupported_stanza_type(std::string(node->name()));
            }
            try {
                try {
                    Jid const &from = s->from();
                    Jid const &to = s->to();
                    // Check auth state.
                    if (m_stream.s2s_auth_pair(to.domain(), from.domain(), INBOUND) != XMLStream::AUTHORIZED) {
                        throw not_authorized();
                    }
                    m_stream.logger().info("Applying stanza filters from [{}]", from.domain());
                    if (DROP == co_await Config::config().domain(from.domain()).filter(span->start_child("filter", "FROM"), FILTER_DIRECTION::FROM, *s)) {
                        m_stream.logger().info("Stanza discarded by FROM filters");
                        co_return true;
                    }
                    m_stream.logger().info("Applying stanza filters to [{}]", to.domain());
                    if (DROP == co_await Config::config().domain(to.domain()).filter(span->start_child("filter", "TO"), FILTER_DIRECTION::TO, *s)) {
                        m_stream.logger().info("Stanza discarded by TO filters");
                        co_return true;
                    }
                    m_stream.logger().info("Applied all stanza filters");
                    if (Config::config().domain(to.domain()).transport_type() == INTERNAL) {
                        Endpoint::endpoint(to).process(std::move(s));
                    } else {
                        METRE_LOG(Metre::Log::DEBUG, "Component creating route: from=[" << from.domain() << "] to=[" << to.domain() << "]");
                        std::shared_ptr<Route> route = RouteTable::routeTable(from).route(to);
                        route->transmit(std::move(s));
                    }
                } catch (Metre::base::xmpp_exception &) {
                    throw;
                } catch (Metre::base::stanza_exception &) {
                    throw;
                } catch (std::runtime_error &e) {
                    throw Metre::stanza_undefined_condition(e.what());
                }
            } catch (Metre::base::stanza_exception const &stanza_error) {
                std::unique_ptr<Stanza> st = s->create_bounce(stanza_error);
                std::shared_ptr<Route> route = RouteTable::routeTable(st->to()).route(st->to());
                route->transmit(std::move(st));
            }
            co_return true;
        }
    };

    DECLARE_FEATURE(Component, COMP);
}
