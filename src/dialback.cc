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
#include <memory>
#include "config.h"

#include <openssl/sha.h>
#include <openssl/sha.h>
#include <log.h>

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string db_ns = "jabber:server:dialback";
    const std::string db_feat_ns = "urn:xmpp:features:dialback";

    class NewDialback : public Feature {
    public:
        NewDialback(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<NewDialback> {
        public:
            Description() : Feature::Description<NewDialback>(db_feat_ns, FEAT_AUTH_FALLBACK) {};

            void offer(xml_node<> *node, XMLStream &s) override {
                if (!s.secured() && (Config::config().domain(s.local_domain()).require_tls() ||
                                     Config::config().domain(s.remote_domain()).require_tls())) {
                    return;
                }
                xml_document<> *d = node->document();
                auto feature = d->allocate_node(node_element, "dialback");
                feature->append_attribute(d->allocate_attribute("xmlns", db_feat_ns.c_str()));
                auto errors = d->allocate_node(node_element, "errors");
                feature->append_node(errors);
                node->append_node(feature);
            }
        };

        bool negotiate(rapidxml::xml_node<> *) override { // Note that this offer, unusually, can be nullptr.
            if (!m_stream.secured() && (Config::config().domain(m_stream.local_domain()).require_tls() ||
                                        Config::config().domain(m_stream.remote_domain()).require_tls())) {
                METRE_LOG(Metre::Log::DEBUG, "Supressed dialback due to missing required TLS");
                return false;
            }
            m_stream.set_auth_ready();
            return false;
        }

        bool handle(rapidxml::xml_node<> *) override {
            throw Metre::unsupported_stanza_type("Wrong namespace for dialback.");
        }
    };

    class Dialback : public Feature, public sigslot::has_slots<> {
    public:
        explicit Dialback(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<Dialback> {
        public:
            Description() : Feature::Description<Dialback>(db_ns, FEAT_AUTH) {};
        };

        /*
         * Temporary store for keys, because - bizarrely - a std::string doesn't
         * appear to be getting captured by value.
         */
        std::set<std::string> m_keys;

        /**
         * Inbound handling.
         */
        void result_step(Route &route, std::string const &key) {
            // Shortcuts here.
            if (m_stream.tls_auth_ok(route)) {
                std::unique_ptr<Stanza> d = std::make_unique<DB::Result>(route.domain(), route.local(), DB::VALID);
                m_stream.send(std::move(d));
                m_stream.s2s_auth_pair(route.local(), route.domain(), INBOUND, XMLStream::AUTHORIZED);
                return;
            }
            Config::Domain const &from_domain = Config::config().domain(route.domain());
            if (!from_domain.auth_dialback()) {
                std::unique_ptr<Stanza> d = std::make_unique<DB::Result>(route.domain(), route.local(),
                                                                         Stanza::not_authorized);
                m_stream.send(std::move(d));
                return;
            }
            m_stream.s2s_auth_pair(route.local(), route.domain(), INBOUND, XMLStream::REQUESTED);
            // With syntax done, we should send the key:
            route.transmit(std::make_unique<DB::Verify>(route.domain(), route.local(), m_stream.stream_id(), key));
            m_keys.erase(key);
        }

        void result(DB::Result const &result) {
            /*
             * This is a request to authenticate, using the current key.
             */
            Config::Domain const &from_domain = Config::config().domain(result.from().domain());
            if (from_domain.transport_type() == INT || from_domain.transport_type() == COMP) {
                std::unique_ptr<Stanza> d = std::make_unique<DB::Result>(result.from(), result.to(),
                                                                         Stanza::not_acceptable);
                m_stream.send(std::move(d));
                return;
            }
            m_stream.check_domain_pair(result.from().domain(), result.to().domain());
            if (!m_stream.secured() && Config::config().domain(result.to().domain()).require_tls()) {
                std::unique_ptr<Stanza> d = std::make_unique<DB::Result>(result.from(), result.to(),
                                                                         Stanza::policy_violation);
                m_stream.send(std::move(d));
                return;
            }
            // Need to perform name collation:
            std::shared_ptr<Route> &route = RouteTable::routeTable(result.to()).route(result.from());
            m_keys.insert(result.key());
            const char *keytmp = m_keys.find(result.key())->c_str();
            route->onNamesCollated.connect(this, [=](Route &r) {
                m_stream.in_context([&]() {
                    result_step(r, keytmp);
                });
            }, true);
            route->collateNames();
        }

        void result_valid(DB::Result const &result) {
            if (m_stream.s2s_auth_pair(result.to().domain(), result.from().domain(), OUTBOUND) >=
                XMLStream::REQUESTED) {
                m_stream.s2s_auth_pair(result.to().domain(), result.from().domain(), OUTBOUND, XMLStream::AUTHORIZED);
            }
        }

        void result_invalid(DB::Result const &result) {
            if (m_stream.s2s_auth_pair(result.to().domain(), result.from().domain(), OUTBOUND) ==
                XMLStream::REQUESTED) {
                m_stream.s2s_auth_pair(result.to().domain(), result.from().domain(), OUTBOUND, XMLStream::NONE);
            }
            // Risky, here - the remote server might close the stream on us.
        }

        void result_error(DB::Result const &result) {
            if (m_stream.s2s_auth_pair(result.to().domain(), result.from().domain(), OUTBOUND) ==
                XMLStream::REQUESTED) {
                m_stream.s2s_auth_pair(result.to().domain(), result.from().domain(), OUTBOUND, XMLStream::NONE);
            }
        }

        void verify(DB::Verify const &v) {
            std::shared_ptr<NetSession> session = Router::session_by_stream_id(v.id());
            DB::Type validity = DB::INVALID;
            METRE_LOG(Log::DEBUG, "Handling db:verify");
            if (session) {
                METRE_LOG(Log::DEBUG, "[NS" << session->serial() << "] session found.");
                if (session->xml_stream().s2s_auth_pair(v.to().domain(), v.from().domain(), OUTBOUND) >=
                    XMLStream::REQUESTED) {
                    METRE_LOG(Log::DEBUG, "[NS" << session->serial() << "] Auth State is correct.");
                    std::string expected = Config::config().dialback_key(v.id(), v.to().domain(), v.from().domain());
                    if (v.key() == expected) validity = DB::VALID;
                }
            }
            std::unique_ptr<Stanza> d = std::make_unique<DB::Verify>(v.from(), v.to(), v.id(), validity);
            m_stream.send(std::move(d));
        }

        void verify_valid(DB::Verify const &v) {
            if (m_stream.direction() != OUTBOUND)
                throw Metre::unsupported_stanza_type("db:verify response on inbound stream");
            std::shared_ptr<NetSession> session = Router::session_by_stream_id(v.id());
            if (!session) return; // Silently ignore this.
            XMLStream &stream = session->xml_stream();
            if (stream.s2s_auth_pair(v.to().domain(), v.from().domain(), INBOUND) == XMLStream::REQUESTED) {
                std::unique_ptr<Stanza> d = std::make_unique<DB::Result>(v.from(), v.to(), DB::VALID);
                stream.send(std::move(d));
                stream.s2s_auth_pair(v.to().domain(), v.from().domain(), INBOUND, XMLStream::AUTHORIZED);
            }
        }

        void verify_invalid(DB::Verify const &v) {
            if (m_stream.direction() != OUTBOUND)
                throw Metre::unsupported_stanza_type("db:verify response on inbound stream");
            std::shared_ptr<NetSession> session = Router::session_by_stream_id(v.id());
            if (!session) return; // Silently ignore this.
            XMLStream &stream = session->xml_stream();
            if (stream.s2s_auth_pair(v.to().domain(), v.from().domain(), INBOUND) == XMLStream::REQUESTED) {
                std::unique_ptr<Stanza> d = std::make_unique<DB::Result>(v.from(), v.to(), Stanza::forbidden);
                stream.send(std::move(d));
                stream.s2s_auth_pair(v.to().domain(), v.from().domain(), INBOUND, XMLStream::NONE);
            }
        }

        bool handle(rapidxml::xml_node<> *node) override {
            xml_document<> *d = node->document();
            d->fixup<parse_default>(node, true);
            std::string stanza = node->name();
            if (stanza == "result") {
                auto p = std::make_unique<DB::Result>(node);
                if (p->type_str()) {
                    if (*p->type_str() == "valid") {
                        result_valid(*p);
                    } else if (*p->type_str() == "invalid") {
                        result_invalid(*p);
                    } else if (*p->type_str() == "error") {
                        result_error(*p);
                    } else {
                        throw Metre::unsupported_stanza_type("Unknown type attribute to db:result");
                    }
                } else {
                    result(*p);
                }
            } else if (stanza == "verify") {
                auto p = std::make_unique<DB::Verify>(node);
                if (p->type_str()) {
                    if (*p->type_str() == "valid") {
                        verify_valid(*p);
                    } else if (*p->type_str() == "invalid") {
                        verify_invalid(*p);
                    } else {
                        throw Metre::unsupported_stanza_type("Unknown type attribute to db:verify");
                    }
                } else {
                    verify(*p);
                }
            } else {
                throw Metre::unsupported_stanza_type("Unknown dialback element");
            }
            return true;
        }
    };

    DECLARE_FEATURE(Dialback, S2S);
    DECLARE_FEATURE(NewDialback, S2S);
}
