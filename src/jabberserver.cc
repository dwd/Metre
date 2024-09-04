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
#include "sentry-wrap.h"
#include "send.h"
#include <memory>
#include <endpoint.h>
#include <log.h>

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string sasl_ns = "jabber:server";

    class JabberServer : public Feature {
    public:
        using Feature::Feature;

        class Description : public Feature::Description<JabberServer> {
        public:
            Description() : Feature::Description<JabberServer>(sasl_ns, Type::FEAT_POSTAUTH) {};
        };

        bool handle_iq(Iq const & iq) {
            if (iq.id().has_value() && iq.id().value().starts_with("::metre::handle::")) {
                Metre::Send::handle(iq);
                return false;
            }
            return true;
        }

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction> span, rapidxml::optional_ptr<rapidxml::xml_node<>> node) override {
            METRE_LOG(Metre::Log::DEBUG, "Handle JabberServer");
            std::unique_ptr<Stanza> s;
            if (node->name() == "message") {
                s = std::make_unique<Message>(node);
            } else if (node->name() == "iq") {
                auto iq = std::make_unique<Iq>(node);
                auto query = iq->node()->first_node();
                if (query) {
                    span->tag("query.xmlns", query->xmlns());
                    span->tag("query.name", query->name());
                }
                if (!handle_iq(*iq)) {
                    span->tag("from", iq->from().domain());
                    span->tag("to", iq->to().domain());
                    span->tag("mine", "yes");
                    span->tag("type", iq->type_str().has_value() ? iq->type_str().value() : "(null)");
                    co_return true;
                }
                s = std::move(iq);
            } else if (node->name() == "presence") {
                s = std::make_unique<Presence>(node);
            } else {
                throw Metre::unsupported_stanza_type(std::string(node->name()));
            }
            span->tag("from", s->from().domain());
            span->tag("to", s->to().domain());
            span->tag("mine", "no");
            span->tag("type", s->type_str().has_value() ? s->type_str().value() : "(null)");
            auto task = m_stream.start_task("jabber::server handle(Stanza)", handle(span->start_child("stanza", "handle"), s));
            co_await *task;
            co_return true;
        }

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::span> span, std::unique_ptr<Stanza> &s) {
            try {
                try {
                    Jid const &to = s->to();
                    Jid const &from = s->from();
                    // Check auth state.
                    if (m_stream.s2s_auth_pair(to.domain(), from.domain(), SESSION_DIRECTION::INBOUND) != XMLStream::AUTH_STATE::AUTHORIZED) {
                        if (m_stream.x2x_mode()) {
                            if (m_stream.secured()) {
                                s->freeze();
                                auto r = RouteTable::routeTable(to.domain()).route(from.domain());
                                auto task = m_stream.start_task("jabber::server tls_auth_ok", m_stream.tls_auth_ok(span->start_child("tls", from.domain()), *r));
                                bool result = co_await *task;
                                if (result) {
                                    m_stream.s2s_auth_pair(s->to().domain(), s->from().domain(), SESSION_DIRECTION::INBOUND,
                                                           XMLStream::AUTH_STATE::AUTHORIZED);
                                } else {
                                    throw Metre::not_authorized();
                                }
                            }
                        } else {
                            throw Metre::not_authorized();
                        }
                    }
                    m_stream.logger().info("Applying stanza filters from [{}]", from.domain());
                    if (FILTER_RESULT::DROP == co_await Config::config().domain(from.domain()).filter(span->start_child("filter", "FROM"), FILTER_DIRECTION::FROM, *s)) {
                        m_stream.logger().info("Stanza discarded by FROM filters");
                        co_return true;
                    }
                    m_stream.logger().info("Applying stanza filters to [{}]", to.domain());
                    if (FILTER_RESULT::DROP == co_await Config::config().domain(to.domain()).filter(span->start_child("filter", "TO"), FILTER_DIRECTION::TO, *s)) {
                        m_stream.logger().info("Stanza discarded by TO filters");
                        co_return true;
                    }
                    m_stream.logger().info("Applied all stanza filters");
                    if (Config::config().domain(to.domain()).transport_type() == SESSION_TYPE::INTERNAL) {
                        Endpoint::endpoint(to).process(std::move(s));
                    } else {
                        std::shared_ptr<Route> route = RouteTable::routeTable(from).route(to);
                        route->transmit(std::move(s));
                    }
                    // Lookup endpoint.
                } catch (Metre::base::xmpp_exception const &) {
                    throw;
                } catch (Metre::base::stanza_exception const &) {
                    throw;
                } catch (std::runtime_error const &e) {
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
