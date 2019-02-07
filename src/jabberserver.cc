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
#include <endpoint.h>
#include <log.h>

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string sasl_ns = "jabber:server";

    class JabberServer : public Feature, public sigslot::has_slots {
    public:
        explicit JabberServer(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<JabberServer> {
        public:
            Description() : Feature::Description<JabberServer>(sasl_ns, FEAT_POSTAUTH) {};
        };

        sigslot::tasklet<bool> handle(rapidxml::xml_node<> *node) override {
            xml_document<> *d = node->document();
            d->fixup<parse_default>(node, false); // Just terminate the header.
            std::string stanza = node->name();
            std::unique_ptr<Stanza> s;
            if (stanza == "message") {
                s = std::make_unique<Message>(node);
            } else if (stanza == "iq") {
                s = std::make_unique<Iq>(node);
            } else if (stanza == "presence") {
                s = std::make_unique<Presence>(node);
            } else {
                throw Metre::unsupported_stanza_type(stanza);
            }
            co_await m_stream.start_task(handle(s));
            co_return true;
        }

        sigslot::tasklet<bool> handle(std::unique_ptr<Stanza> &s) {
            try {
                try {
                    Jid const &to = s->to();
                    Jid const &from = s->from();
                    // Check auth state.
                    if (m_stream.s2s_auth_pair(to.domain(), from.domain(), INBOUND) != XMLStream::AUTHORIZED) {
                        if (m_stream.x2x_mode()) {
                            if (m_stream.secured()) {
                                s->freeze();
                                auto r = RouteTable::routeTable(to.domain()).route(from.domain());
                                auto task = m_stream.start_task(m_stream.tls_auth_ok(*r));
                                bool result = co_await task;
                                if (result) {
                                    m_stream.s2s_auth_pair(s->to().domain(), s->from().domain(), INBOUND,
                                                           XMLStream::AUTHORIZED);
                                } else {
                                    throw Metre::not_authorized();
                                }
                            }
                        } else {
                            throw Metre::not_authorized();
                        }
                    }
                    if (DROP == Config::config().domain(to.domain()).filter(INBOUND, *s)) {
                        METRE_LOG(Log::INFO, "Stanza discarded by filters");
                        co_return true;
                    }
                    if (Config::config().domain(to.domain()).transport_type() == INTERNAL) {
                        Endpoint::endpoint(to).process(std::move(s));
                    } else {
                        std::shared_ptr<Route> route = RouteTable::routeTable(from).route(to);
                        route->transmit(std::move(s));
                    }
                    // Lookup endpoint.
                } catch (Metre::base::xmpp_exception &) {
                    throw;
                } catch (Metre::base::stanza_exception &) {
                    throw;
                } catch (std::runtime_error &e) {
                    throw Metre::stanza_undefined_condition(e.what());
                }
            } catch (Metre::base::stanza_exception const &stanza_error) {
                std::unique_ptr<Stanza> st = s->create_bounce(stanza_error);
                std::shared_ptr<Route> route = RouteTable::routeTable(st->from()).route(st->to());
                route->transmit(std::move(st));
            }
            co_return true;
        }
    };

    DECLARE_FEATURE(JabberServer, S2S);
}
