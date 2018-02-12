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

Route::Route(Jid const &from, Jid const &to) : m_local(from), m_domain(to), onNamesCollated() {
    METRE_LOG(Metre::Log::DEBUG, "Route created, local is " << m_local.domain() << " remote is " << m_domain.domain());
    if (m_domain.domain().empty() || m_local.domain().empty()) throw std::runtime_error("Cannot have route to/from empty domain");
}

namespace {
    bool check_verify(Route &r, std::shared_ptr<NetSession> const &vrfy) {
        if (vrfy) {
            if (vrfy->xml_stream().auth_ready()) {
                r.SessionDialback(vrfy->xml_stream());
                return true;
            } else {
                vrfy->xml_stream().onAuthReady.connect(&r, &Route::SessionDialback);
            }
        }
        return false;
    }


    bool check_to(Route &r, std::shared_ptr<NetSession> const &to) {
        if (to) {
            switch (to->xml_stream().s2s_auth_pair(r.local(), r.domain(), OUTBOUND)) {
                case XMLStream::AUTHORIZED:
                    r.SessionAuthenticated(to->xml_stream());
                    return true;
                default:
                    if (!to->xml_stream().auth_ready()) {
                        to->xml_stream().onAuthReady.connect(&r, &Route::SessionDialback);
                    } else {
                        /// Send a dialback request or something.
                        std::string key = Config::config().dialback_key(to->xml_stream().stream_id(), r.local(),
                                                                        r.domain());
                        rapidxml::xml_document<> d;
                        auto dbr = d.allocate_node(rapidxml::node_element, "db:result");
                        dbr->append_attribute(d.allocate_attribute("to", r.domain().c_str()));
                        dbr->append_attribute(d.allocate_attribute("from", r.local().c_str()));
                        dbr->value(key.c_str(), key.length());
                        d.append_node(dbr);
                        to->xml_stream().send(d);
                        to->xml_stream().s2s_auth_pair(r.local(), r.domain(), OUTBOUND, XMLStream::REQUESTED);
                    }
                    // Fallthrough
                case XMLStream::REQUESTED:
                    to->xml_stream().onAuthenticated.connect(&r, &Route::SessionAuthenticated);
            }
        }
        return false;
    }
}

void Route::queue(std::unique_ptr<DB::Verify> &&s) {
    s->freeze();
    if (m_dialback.empty())
        Router::defer([this]() {
            bounce_dialback(true);
        }, Config::config().domain(m_domain.domain()).stanza_timeout());
    m_dialback.push_back(std::move(s));
    METRE_LOG(Metre::Log::DEBUG, "Queued stanza for " << m_local.domain() << "=>" << m_domain.domain());
}

void Route::transmit(std::unique_ptr<DB::Verify> &&v) {
    auto vrfy = m_vrfy.lock();
    if (check_verify(*this, vrfy)) {
        if (!m_dialback.empty()) {
            queue(std::move(v));
            return;
        } else {
            vrfy->xml_stream().send(std::move(v));
        }
    } else {
        // TODO Look for an existing session and use that.
        // Otherwise, start SRV lookups.
        queue(std::move(v));
        Config::config().domain(m_domain.domain()).SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult, true);
    }

}

void Route::bounce_dialback(bool timeout) {
    if (m_stanzas.empty()) return;
    METRE_LOG(Log::DEBUG, "Timeout on verify");
    m_srv_valid = m_a_valid = false;
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
    m_srv_valid = m_a_valid = false;
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
    METRE_LOG(Metre::Log::DEBUG, "Queued stanza for " << m_local.domain() << "=>" << m_domain.domain());
}

void Route::transmit(std::unique_ptr<Stanza> &&s) {
    auto to = m_to.lock();
    if (check_to(*this, to)) {
        if (!m_stanzas.empty()) {
            METRE_LOG(Metre::Log::DEBUG,
                      "Queuing stanza (backlog) for " << m_local.domain() << "=>" << m_domain.domain());
            queue(std::move(s));
            return;
        } else {
            to->xml_stream().send(std::move(s));
        }
    } else if (!to) {
        if (!m_vrfy.expired()) {
            std::shared_ptr<NetSession> vrfy(m_vrfy);
            m_to = vrfy;
            transmit(std::move(s)); // Retry
            return;
        }
        std::shared_ptr<NetSession> dom = Router::session_by_domain(m_domain.domain());
        if (dom) {
            m_to = dom;
            transmit(std::move(s)); // Retry;
            return;
        }
        METRE_LOG(Metre::Log::DEBUG, "Queuing stanza (spinup) for " << m_local.domain() << "=>" << m_domain.domain());
        queue(std::move(s));
        Config::Domain const &conf = Config::config().domain(m_domain.domain());
        if (conf.transport_type() == S2S) {
            doSrvLookup();
        } else if (conf.transport_type() == X2X) {
            doSrvLookup();
        }
        // Otherwise wait.
    } else { // Got a to but it's not ready yet.
        METRE_LOG(Metre::Log::DEBUG, "Queuing stanza (waiting) for " << m_local.domain() << "=>" << m_domain.domain());
        queue(std::move(s));
    }
}

void Route::doSrvLookup() {
    if (m_srv.domain.empty() || !m_srv.error.empty() || !m_srv_valid || !m_a_valid) {
        Config::config().domain(m_domain.domain()).SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult, true);
    }
}

sigslot::signal<sigslot::thread::st, Route &> &Route::collateNames() {
    if (m_srv.domain.empty() || !m_srv.error.empty()) {
        // No SRV record yet, look it up.
        doSrvLookup();
    } else {
        if (!m_srv.dnssec) {
            // Have a SRV. Was it DNSSEC signed?
            Router::defer([this]() {
                onNamesCollated.emit(*this);
            });
        } else if (m_tlsa.size() == m_srv.rrs.size()) {
            // Do we have TLSAs yet?
            Router::defer([this]() {
                onNamesCollated.emit(*this);
            });
        }
    }
    return onNamesCollated;
}

void Route::SrvResult(DNS::Srv const *srv) {
    METRE_LOG(Metre::Log::DEBUG, "Got SRV " << m_local.domain() << "=>" << m_domain.domain() << " : " << srv->domain);
    if (!srv->error.empty()) {
        METRE_LOG(Metre::Log::WARNING, "Got an error during SRV: " << srv->error);
        onNamesCollated.emit(*this);
        return;
    }
    if (m_srv_valid) return;
    m_srv = *srv;
    // Scan through TLSA records if DNSSEC has been used.
    if (m_srv.dnssec) {
        for (auto &rr : m_srv.rrs) {
            Config::config().domain(m_domain.domain()).TlsaLookup(rr.port, rr.hostname).connect(this,
                                                                                                &Route::TlsaResult,
                                                                                                true);
        }
    } else {
        onNamesCollated.emit(*this);
    }
    auto vrfy = m_vrfy.lock();
    if (vrfy) {
        if (m_to.expired()) m_to = vrfy;
        check_to(*this, m_to.lock());
        return;
    }
    try_srv(true);
}

void Route::try_srv(bool init) {
    if (init) {
        m_rr = m_srv.rrs.begin();
        m_srv_valid = true;
    } else {
        ++m_rr;
    }
    if (!m_srv_valid || m_rr == m_srv.rrs.end()) {
        // Give up and go home.
        m_srv_valid = false;
        bounce_stanzas(Stanza::remote_server_not_found);
        bounce_dialback(false);
        return;
    }
    METRE_LOG(Metre::Log::DEBUG, "Should look for " << (*m_rr).hostname << ":" << (*m_rr).port);
    std::shared_ptr<NetSession> sesh = Router::session_by_address((*m_rr).hostname, (*m_rr).port);
    if (sesh) {
        if (m_vrfy.expired()) m_vrfy = sesh;
        check_verify(*this, sesh);
        if (m_to.expired()) m_to = sesh;
        check_to(*this, sesh);
        return;
    }
    Config::config().domain(m_domain.domain()).AddressLookup((*m_rr).hostname).connect(this, &Route::AddressResult,
                                                                                       true);
}

void Route::AddressResult(DNS::Address const *addr) {
    METRE_LOG(Log::DEBUG, "AddressResult for " << addr->hostname << " (" << m_domain.domain() << ")");
    if (m_a_valid) return;
    auto vrfy = m_vrfy.lock();
    if (vrfy) {
        return;
    }
    if (!addr->error.empty()) {
        METRE_LOG(Metre::Log::DEBUG, "Got an error during DNS: ");
        try_srv();
        return;
    }
    m_addr = *addr;
    try_addr(true);
}

void Route::try_addr(bool init) {
    if (init) {
        m_arr = m_addr.addr.begin();
        m_a_valid = true;
    }
    for (;;) {
        auto vrfy = m_vrfy.lock();
        if (vrfy) {
            return;
        }
        if (init) {
            init = false;
        } else {
            ++m_arr;
        }
        if (!m_srv_valid || m_rr == m_srv.rrs.end()) {
            // Give up and go home.
            m_srv_valid = false;
            bounce_stanzas(Stanza::remote_server_not_found);
            bounce_dialback(false);
            return;
        }
        if (!m_a_valid || m_arr == m_addr.addr.end()) {
            // RUn out of A/AAAA records to try.
            m_a_valid = false;
            try_srv();
            return;
        }
        try {
            vrfy = Router::connect(m_local.domain(), m_domain.domain(), (*m_rr).hostname,
                                   const_cast<struct sockaddr *>(reinterpret_cast<const struct sockaddr *>(&(*m_arr))),
                                   (*m_rr).port, Config::config().domain(m_domain.domain()).transport_type(),
                                   m_rr->tls ? IMMEDIATE : STARTTLS);
            METRE_LOG(Metre::Log::DEBUG, "Connected, " << &*vrfy);
            vrfy->xml_stream().onAuthReady.connect(this, &Route::SessionDialback);
            vrfy->onClosed.connect(this, &Route::SessionClosed);
            m_vrfy = vrfy;
            if (m_to.expired()) {
                m_to = vrfy;
                check_to(*this, vrfy);
            }
            // m_vrfy->connected.connect(...);
            return;
        } catch (std::runtime_error &e) {
            METRE_LOG(Log::DEBUG, "Connection failed, reloop: " << e.what());
        }
    }
}

void Route::SessionClosed(NetSession &n) {
    // One of my sessions has been closed. See what needs progressing.
    if (!m_dialback.empty() || !m_stanzas.empty()) {
        auto vrfy = m_vrfy.lock();
        if (vrfy.get() == &n) {
            m_vrfy.reset();
            try_addr();
            return;
        } else {
            auto to = m_to.lock();
            if (to.get() == &n) {
                m_to.reset();
                try_addr();
            }
        }
    } else {
        m_srv_valid = m_a_valid = false;
    }
}

void Route::TlsaResult(const DNS::Tlsa *tlsa) {
    METRE_LOG(Metre::Log::DEBUG, "TLSA for " << tlsa->domain << ", currently " << m_tlsa.size());
    m_tlsa.erase(
            std::remove_if(m_tlsa.begin(), m_tlsa.end(), [=](DNS::Tlsa const &r) { return r.domain == tlsa->domain; }),
            m_tlsa.end());
    m_tlsa.push_back(*tlsa);
    METRE_LOG(Metre::Log::DEBUG, "TLSA for " << tlsa->domain << ", now " << m_tlsa.size());
    collateNames();
}

void Route::SessionDialback(XMLStream &stream) {
    auto vrfy = m_vrfy.lock();
    METRE_LOG(Metre::Log::DEBUG, "Stream is ready for dialback.");
    if (vrfy && &stream.session() == &*vrfy) {
        METRE_LOG(Metre::Log::DEBUG, "Stream is verify.");
        for (auto &v : m_dialback) {
            vrfy->xml_stream().send(std::move(v));
        }
        m_dialback.clear();
        if (m_to.expired()) {
            m_to = vrfy;
            check_to(*this, vrfy);
        }
    }
    auto to = m_to.lock();
    if (to) {
        if (&stream.session() ==
            &*to) { //] && stream.s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::NONE) {
            METRE_LOG(Metre::Log::DEBUG, "Stream is to; needs dialback.");
            check_to(*this, to);
        }
    }
}

void Route::SessionAuthenticated(XMLStream &stream) {
    auto to = m_to.lock();
    if (stream.auth_ready()
        && &stream.session() == &*to
        && stream.s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::AUTHORIZED) {
        m_a_valid = m_srv_valid = false; // Any new lookups will restart, now.
        if (!m_stanzas.empty()) {
            METRE_LOG(Metre::Log::DEBUG, "Stream now ready for stanzas.");
            for (auto &s : m_stanzas) {
                to->xml_stream().send(std::move(s));
            }
            m_stanzas.clear();
        }
    } else {
        METRE_LOG(Metre::Log::DEBUG, m_local.domain() << "=>" << m_domain.domain() << " NS" << stream.session().serial()
                                                      << " Auth, but not ready: " << stream.auth_ready() << " "
                                                      << !m_stanzas.empty() << " "
                                                      << (&stream.session() == to.get()) << " "
                                                      << (stream.s2s_auth_pair(m_local.domain(),
                                                                                      m_domain.domain(),
                                                                                      OUTBOUND) ==
                                                                 XMLStream::AUTHORIZED));
    }
}

std::vector<DNS::Tlsa> const &Route::tlsa() const {
    if (m_tlsa.size()) return m_tlsa;
    return Config::config().domain(m_domain.domain()).tlsa();
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
    auto itp = m_routes.emplace(to.domain(), std::shared_ptr<Route>(new Route(m_local_domain, to.domain())));
    return (*(itp.first)).second;
}

RouteTable::RouteTable(std::string const &d) : m_routes(), m_local_domain(d) {
}
