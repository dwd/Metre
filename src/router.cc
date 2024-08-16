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

#include "sigslot.h"
#include "router.h"
#include "dns.h"
#include "xmlstream.h"
#include "netsession.h"
#include "log.h"
#include "config.h"

#include <unordered_map>
#include <algorithm>

using namespace Metre;

Route::Route(Jid const &from, Jid const &to) : m_local(from.domain_jid()), m_domain(to.domain_jid()) {
    if (m_domain.domain().empty() || m_local.domain().empty()) throw std::runtime_error("Cannot have route to/from empty domain");
    m_logger = Config::config().logger("Route from=[" + m_local.domain() + "] to=[" + m_domain.domain() + "]");
    m_logger->log(spdlog::level::info, "Route created");
}

sigslot::tasklet<bool> Route::init_session_vrfy(std::shared_ptr<sentry::span> span, bool multiplex) {
    span->containing_transaction().tag("to", m_domain.domain());
    span->containing_transaction().tag("from", m_local.domain());
    m_logger->debug("Verify session spin-up: domain=[{}]", m_domain);
    switch(Config::config().domain(m_domain.domain()).transport_type()) {
    case INTERNAL:
        m_logger->debug("Internal domain; won't connect to that.");
        co_return false;
    case COMP:
        m_logger->debug("XEP-0114 hosted domain; won't connect to that.");
        co_return false;
    default:
        break;
    }
    auto gathered = co_await Config::config().domain(m_domain.domain()).gather(span->start_child("gather", m_domain.domain()));

    if (gathered.gathered_connect.empty()) {
        m_logger->warn("DNS Lookup for [{}] failed", m_domain);
        co_return false;
    }
    if (multiplex && Config::config().domain(m_domain.domain()).multiplex()) {
        auto span_ = span->start_child("multiplex", "scan for existing sessions");
        for (auto &rr: gathered.gathered_connect) {
            m_logger->trace("Should look for [{}:{}]", rr.hostname, rr.port);
            auto session = Router::session_by_address(rr.hostname, rr.port);
            if (!session) continue;
            if (!session->xml_stream().multiplex(true)) {
                m_logger->trace("Session serial=[{}] found, but will not multiplex", session->serial());
                continue;
            }
            if (!session->xml_stream().auth_ready()) {
                if (session->xml_stream().closed()) continue;
                m_logger->trace("Awaiting auth ready on verify session serial=[{}]", session->serial());
                (void) co_await session->xml_stream().auth_state_changed;
                if (!session->xml_stream().auth_ready()) {
                    m_logger->trace("Auth was not ready on verify session serial=[{}]", session->serial());
                    continue;
                }
                span->containing_transaction().tag("multiplex", "target");
                set_vrfy(session);
                m_logger->trace("Reused existing outgoing verify session to [{}:{}]", rr.hostname, rr.port);
                co_return true;
            }
        }
    }
    span->containing_transaction().tag("multiplex", "none");
    for (auto &rr : gathered.gathered_connect) {
        auto span_ = span->start_child("connect", "Connection");
        try {
            auto s = span_->start_child("connect", rr.hostname);
            m_logger->trace("Connecting to address=[{}:{}]", rr.hostname, rr.port);
            span->containing_transaction().tag("tls_mode", rr.method == DNS::ConnectInfo::Method::DirectTLS ? "XEP-0368" : "starttls");
            auto session = Router::connect(m_local.domain(), m_domain.domain(), rr.hostname,
                                           reinterpret_cast<sockaddr *>(&rr.sockaddr),
                                           rr.port, Config::config().domain(m_domain.domain()).transport_type(),
                                           rr.method == DNS::ConnectInfo::Method::DirectTLS ? IMMEDIATE : STARTTLS);
            m_logger->trace("Connected verify session: address=[{}:{}] serial=[{}]", rr.hostname, rr.port,
                            session->serial());
            m_logger->trace("Awaiting auth ready on verify session: serial=[{}]", session->serial());
            while (!session->xml_stream().auth_ready()) {
                if (session->xml_stream().closed()) {
                    break;
                }
                (void) co_await session->xml_stream().auth_state_changed;
            }
            if (!session->xml_stream().auth_ready()) {
                m_logger->trace("Auth was not ready on verify session: serial=[{}]", session->serial());
            }
            set_vrfy(session);
            m_logger->debug("New outgoing verify session: address=[{}:{}]", rr.hostname, rr.port);
            co_return true;
        } catch (std::runtime_error &e) {
            m_logger->error("Verify session connection failed, reloop: error=[{}]", e.what());
        }
    }
    m_logger->error("New outgoing verify session failed: domain=[{}]", m_domain);
    co_return false;
}

sigslot::tasklet<bool> Route::init_session_to(std::shared_ptr<sentry::transaction> trans) {
    bool multiplex = true;
    trans->tag("to", m_domain.domain());
    trans->tag("from", m_local.domain());
restart:
    m_logger->debug("Stanza session spin-up");
    trans->tag("multiplex", "none");
    auto session = Router::session_by_domain(m_domain.domain());
    if (session) {
        if (!multiplex || session->xml_stream().multiplex(false)) {
            m_logger->debug("Will not do sender multiplexing");
        }
        trans->tag("multiplex", "sender");
    }
    if (!session) {
        m_logger->debug("No existing session for domain=[{}]", m_domain);
        do {
            session = m_vrfy.lock();
            m_logger->debug("Authenticating with verify session domain=[{}]", m_domain);
            if (!session) {
                m_logger->debug("No verify session found");
                if (!m_verify_task.has_value()) {
                    m_logger->debug("No verify session task found, starting");
                    m_verify_task = init_session_vrfy(trans->start_child("verify_session", m_domain.domain()), multiplex);
                    m_verify_task.value().start();
                }
                bool vrfy_success = co_await m_verify_task.value();
                m_verify_task.reset();
                if (!vrfy_success) {
                    m_logger->debug("Verify task failed");
                    trans->exception({});
                    co_return false;
                }
            }
        } while (!session);
        m_logger->trace("Got verify session domain=[{}]", m_domain);
    }
    auto span_ = trans->start_child("auth", "Authentication");
    trans->tag("auth", "sasl");
    switch (session->xml_stream().s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND)) {
        default: // NONE
            while (!session->xml_stream().auth_ready()) {
                if (session->xml_stream().closed()) goto restart;
                m_logger->trace("Awaiting authentication ready: domain=[{}]");
                (void) co_await session->xml_stream().auth_state_changed;
            }
            /// Send a dialback request.
            {
                trans->tag("auth", "dialback");
                m_logger->trace("Dialing back: domain=[{}]");
                std::string key = Config::config().dialback_key(session->xml_stream().stream_id(),
                                                                m_local.domain(),
                                                                m_domain.domain());
                rapidxml::xml_document<> d;
                auto dbr = d.allocate_node(rapidxml::node_element, "db:result");
                dbr->append_attribute(d.allocate_attribute("to", m_domain.domain()));
                dbr->append_attribute(d.allocate_attribute("from", m_local.domain()));
                dbr->value(key);
                d.append_node(dbr);
                session->xml_stream().send(d);
                session->xml_stream().s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND,
                                                    XMLStream::REQUESTED);
            }
            // Fallthrough
        case XMLStream::REQUESTED:
            m_logger->trace("Awaiting authentication: domain=[{}]");
            while (session->xml_stream().s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::REQUESTED) {
                m_logger->debug("Authenticating with verify session");
                if (session->xml_stream().closed()) {
                    if (multiplex) {
                        multiplex = false;
                        goto restart;
                    } else {
                        trans->exception({});
                        co_return false;
                    }
                }
                (void) co_await session->xml_stream().auth_state_changed;
            }
            if (session->xml_stream().s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::NONE) {
                // Rejected auth.
                if (multiplex) {
                    multiplex = false;
                    goto restart;
                } else {
                    trans->exception({});
                    co_return false;
                }
            }
        case XMLStream::AUTHORIZED:
            m_logger->trace("Authorized: domain=[{}]");
            break;
    }
    m_logger->trace("Setting 'to' session");
    set_to(session);
    co_return true;
}

void Route::set_to(std::shared_ptr<Metre::NetSession> &to) {
    m_to = to;
    to->onClosed.connect(this, &Route::SessionClosed);
    for (auto &s : m_stanzas) {
        to->xml_stream().send(std::move(s));
    }
    m_stanzas.clear();
}

void Route::set_vrfy(std::shared_ptr<Metre::NetSession> &vrfy) {
    m_vrfy = vrfy;
    vrfy->onClosed.connect(this, &Route::SessionClosed);
    for (auto &v : m_dialback) {
        vrfy->xml_stream().send(std::move(v));
    }
    m_dialback.clear();
}

/**
 * We have a bidi-capable session that has authenticated INBOUND, so we can use it OUTBOUND now.
 * We might have a session already, in which case we won't switch (it would make life complex for in-flight stanzas).
 * But if not, we'll discard any half-ready session and use this one.
 *
 * @param ns - NetSession of inbound session.
 */
void Route::outbound(NetSession *ns) {
    m_logger->debug("Outbound NetSession: serial=[{}]", ns->serial());
    auto to = m_to.lock();
    if (!ns) {
        return;
    }
    if (to && (to->serial() == ns->serial())) return;
    if (to) {
        to->close(); // Kill with fire.
    }
    auto p = Router::session_by_serial(ns->serial());
    set_to(p);
}

void Route::queue(std::unique_ptr<DB::Verify> &&s) {
    m_logger->trace("Queue verify: name=[{}] from=[{}] to=[{}]", s->Stanza::name(), s->from(), s->to());
    s->freeze();
    if (m_dialback.empty())
        Router::defer([this]() {
            bounce_dialback(true);
        }, Config::config().domain(m_domain.domain()).stanza_timeout());
    m_dialback.push_back(std::move(s));
    m_logger->debug("Route queued verify local=[{}] domain=[{}]", m_local, m_domain);
}

void Route::transmit(std::unique_ptr<DB::Verify> &&v) {
    m_logger->trace("Transmit verify: name=[{}] from=[{}] to=[{}]", v->Stanza::name(), v->from(), v->to());
    auto vrfy = m_vrfy.lock();
    if (vrfy) {
        vrfy->xml_stream().send(std::move(v));
    } else {
        queue(std::move(v));
        if (!m_verify_task.has_value()) {
            auto wrapper = [this](std::shared_ptr<sentry::transaction> && trans) -> sigslot::tasklet<bool> {
                bool result = co_await init_session_vrfy(trans->start_child("verify_session", m_domain.domain()), true);
                if (!result) trans->exception({});
                co_return result;
            };
            m_verify_task = wrapper(std::make_shared<sentry::transaction>("transmit", "Verify session spin-up"));
            m_verify_task->complete().connect(this, [this]() {Router::defer([this]() {m_verify_task.reset();}, {0,5000});});
            m_verify_task->start();
        }
    }
}

void Route::bounce_dialback(bool timeout) {
    if (m_stanzas.empty()) {
        return;
    }
    m_logger->warn("Timeout of verify sessions: timeout=[{}]", timeout);
    auto verify = m_vrfy.lock();
    if (verify) {
        verify->close();
        m_vrfy.reset();
    }
}

void Route::bounce_stanzas(Stanza::Error e) {
    if (m_stanzas.empty()) {
        return;
    }
    m_logger->warn("Timeout on stanzas error=[{}]", Stanza::error_name(e));
    for (auto &stanza : m_stanzas) {
        stanza->sent(*stanza, false);
        if (stanza->type_str() && *stanza->type_str() == "error") continue;
        auto bounce = stanza->create_bounce(e);
        RouteTable::routeTable(bounce->from()).route(bounce->to())->transmit(std::move(bounce));
    }
    m_stanzas.clear();
    auto to = m_to.lock();
    if (to) {
        to->close();
        m_to.reset();
    }
}

void Route::queue(std::unique_ptr<Stanza> &&s) {
    m_logger->trace("Queue stanza: name=[{}] from=[{}] to=[{}]", s->name(), s->from(), s->to());
    s->freeze();
    if (m_stanzas.empty())
        Router::defer([this]() {
            bounce_stanzas(Stanza::remote_server_timeout);
        }, Config::config().domain(m_domain.domain()).stanza_timeout());
    m_stanzas.push_back(std::move(s));
    m_logger->debug("Queued stanza");
}

void Route::transmit(std::unique_ptr<Stanza> &&s) {
    m_logger->trace("Transmit stanza: name=[{}] from=[{}] to=[{}]", s->name(), s->from(), s->to());
    auto to = m_to.lock();
    if (to) {
        m_logger->debug("Existing stanza session: serial=[{}]", to->serial());
        to->xml_stream().send(std::move(s));
    } else {
        m_logger->debug("No stanza session");
        queue(std::move(s));
        if (!m_to_task.has_value()) {
            m_logger->debug("No current task");
            m_to_task = init_session_to(std::make_shared<sentry::transaction>("transmit", "Stanza session spin-up"));
            m_to_task->complete().connect(this, [this]() {Router::defer([this]() {m_to_task.reset();});});
            m_to_task->start();
        }
    }
    m_logger->trace("Stanza accepted");
}

void Route::SessionClosed(NetSession &n) {
    m_logger->debug("Net Session closed");
    // One of my sessions has been closed. See what needs progressing.
    if (!m_dialback.empty() || !m_stanzas.empty()) {
        auto vrfy = m_vrfy.lock();
        if (vrfy && (vrfy.get() == &n)) {
            m_vrfy.reset();
            return;
        } else {
            auto to = m_to.lock();
            if (to.get() == &n) {
                m_to.reset();
            }
        }
    }
}

RouteTable &RouteTable::routeTable(std::string const &d) {
    static std::unordered_map<std::string, RouteTable> rt;
    auto it = rt.find(d);
    if (it != rt.end()) return (*it).second;
    auto itp = rt.emplace(d, d);
    return (*(itp.first)).second;
}

RouteTable &RouteTable::routeTable(Jid const &j) {
    return RouteTable::routeTable(j.domain());
}

std::shared_ptr<Route> &RouteTable::route(Jid const &to) {
    return route(to.domain());
}

std::shared_ptr<Route> &RouteTable::route(std::string const & to) {
    // TODO This needs to be more complex once we have clients.
    if (auto it = m_routes.find(to); it != m_routes.end()) {
        return (*it).second;
    }
    // No route: For components, see if there's a route against the component domain.
    if (m_local_domain != to && Config::config().domain(to).transport_type() == COMP) {
        auto [ it, success ] = m_routes.try_emplace(to, RouteTable::routeTable(to).route(to));
        return it->second;
    }
    auto [ it, success] = m_routes.try_emplace(to, std::make_shared<Route>(Jid(nullptr, m_local_domain), Jid(nullptr, to)));
    return it->second;
}

RouteTable::RouteTable(std::string const &d) : m_routes(), m_local_domain(d) {
}
