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

#include "router.h"
#include "dns.h"
#include "xmlstream.h"
#include "netsession.h"
#include "log.h"
#include "config.h"

#include <unordered_map>
#include <algorithm>

using namespace Metre;

Route::Route(Jid const &from, Jid const &to) : m_local(from), m_domain(to) {
    if (m_domain.domain().empty() || m_local.domain().empty()) throw std::runtime_error("Cannot have route to/from empty domain");
    auto sinks = Config::config().logger().sinks();
    m_logger = std::make_shared<spdlog::logger>("route " + m_local.domain() + "->" + m_domain.domain(), begin(sinks), end(sinks));
    m_logger->flush_on(spdlog::level::trace);
    m_logger->set_level(spdlog::level::trace);
    m_logger->log(spdlog::level::info, "Route created");
}

sigslot::tasklet<bool> Route::init_session_vrfy() {
    m_logger->log(spdlog::level::info, "Verify session spin-up");
    auto res = Config::config().domain(m_domain.domain()).resolver();
    auto srv = co_await
    res->SrvLookup(m_domain.domain());
    if (!srv.error.empty()) {
        m_logger->log(spdlog::level::warn, "SRV Lookup for [{}] failed: [{}]", m_domain.domain(), srv.error);
        co_return false;
    }
    for (auto &rr : srv.rrs) {
        m_logger->log(spdlog::level::debug, "Should look for [{}:{}]", rr.hostname, rr.port);
        auto session = Router::session_by_address(rr.hostname, rr.port);
        if (session && !session->xml_stream().auth_ready()) {
            (void) co_await session->xml_stream().onAuthReady;
            if (!session->xml_stream().auth_ready()) {
                continue;
            }
            set_vrfy(session);
            m_logger->log(spdlog::level::info, "Reused existing outgoing session (verify stage) to [{}:{}]", rr.hostname, rr.port);
            co_return true;
        }
    }
    for (auto &rr : srv.rrs) {
        auto addr = co_await
        res->AddressLookup(rr.hostname);
        if (!addr.error.empty()) {
            m_logger->log(spdlog::level::warn, "A/AAAA Lookup for [{}] failed: [{}]", rr.hostname, srv.error);
            continue;
        }
        for (auto &arr : addr.addr) {
            try {
                m_logger->log(spdlog::level::debug, "Trying [{}:{}]", rr.hostname, rr.port);
                auto session = Router::connect(m_local.domain(), m_domain.domain(), rr.hostname,
                                       const_cast<struct sockaddr *>(reinterpret_cast<const struct sockaddr *>(&arr)),
                                       rr.port, Config::config().domain(m_domain.domain()).transport_type(),
                                       rr.tls ? IMMEDIATE : STARTTLS);
                METRE_LOG(Metre::Log::DEBUG, "Connected, " << session.get());
                (void) co_await session->xml_stream().onAuthReady;
                if (!session->xml_stream().auth_ready()) {
                    continue;
                }
                set_vrfy(session);
                m_logger->log(spdlog::level::info, "New outgoing session (verify stage) to [{}:{}]", rr.hostname, rr.port);
                co_return true;
            } catch (std::runtime_error &e) {
                METRE_LOG(Log::DEBUG, "Connection failed, reloop: " << e.what());
            }
        }
    }
    co_return false;
}

sigslot::tasklet<bool> Route::init_session_to() {
    m_logger->log(spdlog::level::debug, "Stanza session spin-up");
    auto session = Router::session_by_domain(m_domain.domain());
    if (!session) {
        session = m_vrfy.lock();
        do {
            if (!session) {
                m_logger->log(spdlog::level::debug, "No verify session");
                if (!m_verify_task.running()) {
                    m_logger->log(spdlog::level::debug, "No verify session task.");
                    m_verify_task = init_session_vrfy();
                    m_verify_task.start();
                }
                if (!co_await m_verify_task) {
                    m_logger->log(spdlog::level::debug, "Verify task completed false");
                    co_return
                    false;
                }
            }
            m_logger->log(spdlog::level::debug, "Authenticating with Verify session");
        } while (!(session = m_vrfy.lock()));
    }
    switch (session->xml_stream().s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND)) {
        default:
            if (!session->xml_stream().auth_ready()) {
                (void) co_await session->xml_stream().onAuthReady;
            }
            /// Send a dialback request.
            {
                std::string key = Config::config().dialback_key(session->xml_stream().stream_id(),
                                                                m_local.domain(),
                                                                m_domain.domain());
                rapidxml::xml_document<> d;
                auto dbr = d.allocate_node(rapidxml::node_element, "db:result");
                dbr->append_attribute(d.allocate_attribute("to", m_domain.domain().c_str()));
                dbr->append_attribute(d.allocate_attribute("from", m_local.domain().c_str()));
                dbr->value(key.c_str(), key.length());
                d.append_node(dbr);
                session->xml_stream().send(d);
                session->xml_stream().s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND,
                                                    XMLStream::REQUESTED);
            }
            // Fallthrough
        case XMLStream::REQUESTED:
            (void) co_await session->xml_stream().onAuthenticated;
        case XMLStream::AUTHORIZED:
            break;
    }
    while (session->xml_stream().s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) != XMLStream::AUTHORIZED) {
        (void) co_await session->xml_stream().onAuthenticated;
    }
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
    auto to = m_to.lock();
    if (!ns) return;
    if (to && (to->serial() == ns->serial())) return;
    if (to) {
        to->close(); // Kill with fire.
    }
    auto p = Router::session_by_serial(ns->serial());
    set_to(p);
}

void Route::queue(std::unique_ptr<DB::Verify> &&s) {
    s->freeze();
    if (m_dialback.empty())
        Router::defer([this]() {
            bounce_dialback(true);
        }, Config::config().domain(m_domain.domain()).stanza_timeout());
    m_dialback.push_back(std::move(s));
    SPDLOG_DEBUG(m_logger, "Queued verify");
}

void Route::transmit(std::unique_ptr<DB::Verify> &&v) {
    auto vrfy = m_vrfy.lock();
    if (vrfy) {
        vrfy->xml_stream().send(std::move(v));
    } else {
        queue(std::move(v));
        if (!m_verify_task.running()) {
            m_verify_task = init_session_vrfy();
            m_verify_task.start();
        }
    }
}

void Route::bounce_dialback(bool timeout) {
    if (m_stanzas.empty()) return;
    METRE_LOG(Log::DEBUG, "Timeout on verify");
    auto verify = m_vrfy.lock();
    if (verify) {
        verify->close();
        m_vrfy.reset();
    }
}

void Route::bounce_stanzas(Stanza::Error e) {
    if (m_stanzas.empty()) return;
    METRE_LOG(Log::DEBUG, "Timeout on stanzas");
    for (auto &stanza : m_stanzas) {
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
    s->freeze();
    if (m_stanzas.empty())
        Router::defer([this]() {
            bounce_stanzas(Stanza::remote_server_timeout);
        }, Config::config().domain(m_domain.domain()).stanza_timeout());
    m_stanzas.push_back(std::move(s));
    SPDLOG_DEBUG(m_logger, "Queued stanza");
}

void Route::transmit(std::unique_ptr<Stanza> &&s) {
    SPDLOG_TRACE(m_logger, "Transmit stanza request");
    auto to = m_to.lock();
    if (to) {
        to->xml_stream().send(move(s));
    } else {
        SPDLOG_DEBUG(m_logger, "No stanza session, spin-up");
        queue(std::move(s));
        if (!m_to_task.running()) {
            SPDLOG_DEBUG(m_logger, "No current task");
            m_to_task = init_session_to();
            m_to_task.start();
        }
    }
    SPDLOG_DEBUG(m_logger, "Stanza accepted.");
}

void Route::SessionClosed(NetSession &n) {
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
    // TODO This needs to be more complex once we have clients.
    auto it = m_routes.find(to.domain());
    if (it != m_routes.end()) return (*it).second;
    auto itp = m_routes.emplace(to.domain(), std::make_shared<Route>(m_local_domain, to.domain()));
    return (*(itp.first)).second;
}

RouteTable::RouteTable(std::string const &d) : m_routes(), m_local_domain(d) {
}
