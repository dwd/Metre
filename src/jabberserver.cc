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
#include "config.h"
#include <memory>

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string sasl_ns = "jabber:server";

    class JabberServer : public Feature, public sigslot::has_slots<> {
    public:
        JabberServer(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<JabberServer> {
        public:
            Description() : Feature::Description<JabberServer>(sasl_ns, FEAT_POSTAUTH) {};

            virtual void offer(xml_node<> *, XMLStream &) {
                // No feature advertised.
            }
        };

        bool handle(rapidxml::xml_node<> *node) {
            xml_document<> *d = node->document();
            d->fixup<parse_default>(node, false); // Just terminate the header.
            std::string stanza = node->name();
            std::unique_ptr<Stanza> s;
            if (stanza == "message") {
                s = std::move(std::unique_ptr<Stanza>(new Message(node)));
            } else if (stanza == "iq") {
                s = std::move(std::unique_ptr<Stanza>(new Iq(node)));
            } else if (stanza == "presence") {
                s = std::move(std::unique_ptr<Stanza>(new Presence(node)));
            } else {
                throw Metre::unsupported_stanza_type(stanza);
            }
            handle(s);
            return true;
        }

        void handle(std::unique_ptr<Stanza> &s) {
            try {
                try {
                    Jid const &to = s->to();
                    Jid const &from = s->from();
                    // Check auth state.
                    if (m_stream.s2s_auth_pair(to.domain(), from.domain(), INBOUND) != XMLStream::AUTHORIZED) {
                        if (m_stream.x2x_mode()) {
                            if (m_stream.secured()) {
                                Stanza *holding = s.release();
                                holding->freeze();
                                auto r = RouteTable::routeTable(to.domain()).route(from.domain());
                                r->onNamesCollated.connect(this, [this, holding](Route &r) {
                                    std::unique_ptr<Stanza> s(holding);
                                    if (m_stream.tls_auth_ok(r)) {
                                        m_stream.s2s_auth_pair(s->to().domain(), s->from().domain(), INBOUND,
                                                               XMLStream::AUTHORIZED);
                                    }
                                    handle(s);
                                    m_stream.thaw();
                                }, true);
                                r->collateNames();
                                m_stream.freeze();
                                return;
                            }
                        } else {
                            throw Metre::not_authorized();
                        }
                    }
                    if (Config::config().domain(to.domain()).transport_type() == INT) {
                        // For now, bounce everything.
                        bool ping = false;
                        if (std::string(s->name()) == "iq" && to.full() == to.domain()) {
                            auto query = s->node()->first_node();
                            if (query) {
                                std::string xmlns{query->xmlns(), query->xmlns_size()};
                                if (xmlns == "urn:xmpp:ping") {
                                    ping = true;
                                }
                            }
                        }
                        if (ping) {
                            std::unique_ptr<Stanza> pong{new Iq(to, from, Iq::RESULT, s->id())};
                            std::shared_ptr<Route> route = RouteTable::routeTable(to).route(from);
                            route->transmit(std::move(pong));
                        } else {
                            throw stanza_service_unavailable();
                        }
                    } else {
                        std::shared_ptr<Route> route = RouteTable::routeTable(from).route(to);
                        route->transmit(std::move(s));
                    }
                    // Lookup endpoint.
                } catch (Metre::base::xmpp_exception) {
                    throw;
                } catch (Metre::base::stanza_exception) {
                    throw;
                } catch (std::runtime_error &e) {
                    throw Metre::stanza_undefined_condition(e.what());
                }
            } catch (Metre::base::stanza_exception const &stanza_error) {
                std::unique_ptr<Stanza> st = s->create_bounce(stanza_error);
                std::shared_ptr<Route> route = RouteTable::routeTable(st->from()).route(st->to());
                route->transmit(std::move(st));
            }
        }
    };

    bool declared = Feature::declare<JabberServer>(S2S);
}
