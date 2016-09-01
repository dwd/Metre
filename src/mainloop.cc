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

#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include <sstream>
#include "rapidxml.hpp"
#include <optional> // Uses the supplied optional by default.
#include "xmppexcept.h"
#include "netsession.h"
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <memory>
#include "router.h"
#include <unbound.h>
#include <cerrno>
#include <cstring>
#include <atomic>
#include "sigslot/sigslot.h"
#include "dns.h"
#include <arpa/inet.h>
#include "config.h"
#include "log.h"
#include <functional>

namespace Metre {
    class Mainloop : public sigslot::has_slots<> {
    private:
        struct event_base *m_event_base;
        struct event *m_listen;
        std::map<unsigned long long, std::shared_ptr<NetSession>> m_sessions;
        std::map<std::string, std::weak_ptr<NetSession>> m_sessions_by_id;
        std::map<std::string, std::weak_ptr<NetSession>> m_sessions_by_domain;
        std::map<std::pair<std::string, unsigned short>, std::weak_ptr<NetSession>> m_sessions_by_address;
        struct event *m_ub_event;
        struct evconnlistener *m_server_listener;
        struct evconnlistener *m_component_listener;
        static std::atomic<unsigned long long> s_serial;
        std::list<std::shared_ptr<NetSession>> m_closed_sessions;
        std::list<std::function<void()>> m_pending_actions;
        bool m_shutdown = false;
        bool m_shutdown_now = false;
    public:
        static Mainloop *s_mainloop;

        Mainloop() : m_event_base(0), m_listen(0), m_sessions(), m_ub_event(0) {
            s_mainloop = this;
        }

        ~Mainloop() {
            event_del(m_ub_event);
            event_free(m_ub_event);
            event_base_free(m_event_base);
        }

        struct event_base * event_base() const {
            return m_event_base;
        }

        bool init() {
            if (m_event_base) throw std::runtime_error("I'm already initialized!");
            m_event_base = event_base_new();
            {
                sockaddr_in6 sin = {AF_INET6, htons(5269), 0, {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, 0};
                m_server_listener = evconnlistener_new_bind(m_event_base, Mainloop::new_server_session_cb, this,
                                                            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                                            reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
                if (!m_server_listener) {
                    throw std::runtime_error(std::string("Cannot bind to server port: ") + strerror(errno));
                }
                METRE_LOG(Metre::Log::INFO, "Listening to server.");
            }
            {
                sockaddr_in6 sin = {AF_INET6, htons(5347), 0, {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, 0};
                m_component_listener = evconnlistener_new_bind(m_event_base, Mainloop::new_comp_session_cb, this,
                                                               LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                                               reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
                if (!m_component_listener) {
                    throw std::runtime_error(std::string("Cannot bind to component port: ") + strerror(errno));
                }
                METRE_LOG(Metre::Log::INFO, "Listening to component.");
            }
            return true;
        }

        std::shared_ptr<NetSession> session_by_id(std::string const &id) {
            auto it = m_sessions_by_id.find(id);
            if (it != m_sessions_by_id.end()) {
                std::shared_ptr<NetSession> s((*it).second.lock());
                return s;
            }
            return nullptr;
        }

        std::shared_ptr<NetSession> session_by_domain(std::string const &id) {
            auto it = m_sessions_by_domain.find(id);
            if (it != m_sessions_by_domain.end()) {
                std::shared_ptr<NetSession> s((*it).second.lock());
                return s;
            }
            return nullptr;
        }

        std::shared_ptr<NetSession> session_by_address(std::string const &host, unsigned short port) {
            auto it = m_sessions_by_address.find(std::make_pair(host, port));
            if (it != m_sessions_by_address.end()) {
                std::shared_ptr<NetSession> s((*it).second.lock());
                return s;
            }
            return nullptr;
        }

        void register_stream_id(std::string const &id, unsigned long long serial) {
            auto it = m_sessions.find(serial);
            if (it == m_sessions.end()) {
                return;
            }
            auto it2 = m_sessions_by_id.find(id);
            if (it2 != m_sessions_by_id.end()) {
                std::shared_ptr<NetSession> old = it2->second.lock();
                if (!old) {
                    m_sessions_by_id.erase(it2);
                } else {
                    if (old->serial() == serial) return;
                    throw std::runtime_error("Duplicate session id - loopback?");
                }
            }
            m_sessions_by_id.insert(std::make_pair(id, (*it).second));
        }

        void unregister_stream_id(std::string const &id) {
            auto it2 = m_sessions_by_id.find(id);
            if (it2 != m_sessions_by_id.end()) {
                m_sessions_by_id.erase(it2);
            }
        }

        void register_session_domain(std::string const &dom, unsigned long long serial) {
            auto it = m_sessions.find(serial);
            if (it == m_sessions.end()) {
                return;
            }
            auto it2 = m_sessions_by_domain.find(dom);
            if (it2 != m_sessions_by_domain.end()) {
                m_sessions_by_domain.erase(it2);
            }
            m_sessions_by_domain.insert(std::make_pair(dom, (*it).second));
        }

        static void
        new_server_session_cb(struct evconnlistener *listener, evutil_socket_t newsock, struct sockaddr *addr, int len,
                              void *arg) {
            reinterpret_cast<Mainloop *>(arg)->new_session_inbound(newsock, addr, len, S2S);
        }

        static void
        new_comp_session_cb(struct evconnlistener *listener, evutil_socket_t newsock, struct sockaddr *addr, int len,
                            void *arg) {
            reinterpret_cast<Mainloop *>(arg)->new_session_inbound(newsock, addr, len, COMP);
        }

        void new_session_inbound(evutil_socket_t sock, struct sockaddr *sin, int sinlen, SESSION_TYPE stype) {
            if (m_shutdown || m_shutdown_now) {
                evutil_closesocket(sock);
                return;
            }
            struct bufferevent *bev = bufferevent_socket_new(m_event_base, sock, BEV_OPT_CLOSE_ON_FREE);
            std::shared_ptr<NetSession> session(new NetSession(std::atomic_fetch_add(&s_serial, 1ull), bev, stype));
            auto it = m_sessions.find(session->serial());
            if (it != m_sessions.end()) {
                // We already have one for this socket. This seems unlikely to be safe.
                METRE_LOG(Metre::Log::CRIT, "Session already in ownership table; corruption.");
                assert(false);
            }
            char addrbuf[1024];
            addrbuf[0] = '\0';
            if (sin->sa_family == AF_INET) {
                inet_ntop(AF_INET, reinterpret_cast<void *>(&reinterpret_cast<struct sockaddr_in *>(sin)->sin_addr),
                          addrbuf, 1024);
            } else if (sin->sa_family == AF_INET6) {
                inet_ntop(AF_INET6, reinterpret_cast<void *>(&reinterpret_cast<struct sockaddr_in6 *>(sin)->sin6_addr),
                          addrbuf, 1024);
            }
            METRE_LOG(Metre::Log::INFO,
                      "New session on " << (stype == S2S ? "S2S" : "COMP") << " port from " << addrbuf);
            m_sessions[session->serial()] = session;
            session->onClosed.connect(this, &Mainloop::session_closed);
        }

        std::shared_ptr<NetSession>
        connect(std::string const &fromd, std::string const &tod, std::string const &hostname, uint32_t addr,
                unsigned short port) {
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = addr;
            sin.sin_port = htons(port);
            char buf[25];
            METRE_LOG(Metre::Log::DEBUG,
                      "Connecting to " << inet_ntop(AF_INET, &sin.sin_addr, buf, 25) << ":" << ntohs(sin.sin_port)
                                       << ":" << port);
            std::shared_ptr<NetSession> sesh = connect(fromd, tod, hostname, reinterpret_cast<struct sockaddr *>(&sin),
                                                       sizeof(sin), port);
            m_sessions_by_address[std::make_pair(hostname, port)] = sesh;
            auto it = m_sessions_by_domain.find(tod);
            if (it == m_sessions_by_domain.end() ||
                (*it).second.expired()) {
                m_sessions_by_domain[tod] = sesh;
            }
            return sesh;
        }

        std::shared_ptr<NetSession>
        connect(std::string const &fromd, std::string const &tod, std::string const &hostname, struct sockaddr *sin,
                size_t addrlen, unsigned short port) {
            struct bufferevent *bev = bufferevent_socket_new(m_event_base, -1, BEV_OPT_CLOSE_ON_FREE);
            if (!bev) {
                METRE_LOG(Metre::Log::CRIT, "Error creating BEV");
                // TODO ARGH!
            }
            if (0 > bufferevent_socket_connect(bev, sin, addrlen)) {
                METRE_LOG(Metre::Log::ERR, "Error connecting BEV");
                // TODO Something bad happened.
                bufferevent_free(bev);
            }
            METRE_LOG(Metre::Log::DEBUG, "BEV fd is " << bufferevent_getfd(bev));
            std::shared_ptr<NetSession> session(
                    new NetSession(std::atomic_fetch_add(&s_serial, 1ull), bev, fromd, tod));
            auto it = m_sessions.find(session->serial());
            if (it != m_sessions.end()) {
                // We already have one for this socket. This seems unlikely to be safe.
                METRE_LOG(Metre::Log::CRIT, "Session already in ownership table; corruption.");
                assert(false);
            }
            m_sessions[session->serial()] = session;
            session->onClosed.connect(this, &Mainloop::session_closed);
            return session;
        }

        void run() {
            dns_setup();
            while (true) {
                event_base_dispatch(m_event_base);
                if (m_shutdown_now && m_sessions.empty()) {
                    return;
                }
                m_closed_sessions.clear();
                while (!m_pending_actions.empty()) {
                    std::list<std::function<void()>> pending;
                    std::swap(pending, m_pending_actions);
                    for (auto &f : pending) {
                        f();
                    }
                }
                if (m_shutdown) {
                    METRE_LOG(Metre::Log::INFO, "Closing sessions.");
                    evconnlistener_disable(m_component_listener);
                    evconnlistener_disable(m_server_listener);
                    evconnlistener_free(m_component_listener);
                    evconnlistener_free(m_server_listener);
                    for (auto &it : m_sessions) {
                        it.second->send(
                                "<stream:error><system-shutdown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:close>");
                        it.second->close();
                    }
                    m_shutdown_now = true;
                    event_base_loopexit(m_event_base, NULL);
                    METRE_LOG(Metre::Log::INFO, "Closed all sessions.");
                }
            }
        }

        void do_later(std::function<void()> &&fn) {
            m_pending_actions.emplace_back(std::move(fn));
            event_base_loopexit(m_event_base, NULL);
        }

        void shutdown() {
            m_shutdown = true;
            event_base_loopexit(m_event_base, NULL);
        }

        static void unbound_cb(evutil_socket_t, short, void *arg) {
            ub_process(reinterpret_cast<struct ub_ctx *>(arg));
        }

        void dns_setup() {
            if (!m_ub_event) {
                m_ub_event = event_new(m_event_base, ub_fd(Config::config().ub_ctx()), EV_READ | EV_PERSIST, unbound_cb,
                                       Config::config().ub_ctx());
                event_add(m_ub_event, NULL);
            }
        }

        void reload() {
            event_del(m_ub_event);
            event_free(m_ub_event);
            dns_setup();
        }

        void session_closed(NetSession &ns) {
            METRE_LOG(Log::DEBUG, "NS" << ns.serial() << " - Session closed.");
            auto it = m_sessions.find(ns.serial());
            if (it != m_sessions.end()) {
                m_closed_sessions.push_back((*it).second);
                event_base_loopexit(m_event_base, NULL);
                m_sessions.erase(it);
            }
        }
    };

    Mainloop *Mainloop::s_mainloop{nullptr};
    std::atomic<unsigned long long> Mainloop::s_serial{0};

    namespace Router {
        std::shared_ptr<NetSession>
        connect(std::string const &fromd, std::string const &tod, std::string const &hostname, uint32_t addr,
                unsigned short port) {
            return Mainloop::s_mainloop->connect(fromd, tod, hostname, addr, port);
        }

        void register_stream_id(std::string const &id, NetSession &session) {
            Mainloop::s_mainloop->register_stream_id(id, session.serial());
        }

        void unregister_stream_id(std::string const &id) {
            Mainloop::s_mainloop->unregister_stream_id(id);
        }

        void register_session_domain(std::string const &domain, NetSession &session) {
            Mainloop::s_mainloop->register_session_domain(domain, session.serial());
        }

        std::shared_ptr<NetSession> session_by_stream_id(std::string const &id) {
            return Mainloop::s_mainloop->session_by_id(id);
        }

        std::shared_ptr<NetSession> session_by_domain(std::string const &id) {
            return Mainloop::s_mainloop->session_by_domain(id);
        }

        std::shared_ptr<NetSession> session_by_address(std::string const &id, unsigned short p) {
            return Mainloop::s_mainloop->session_by_address(id, p);
        }

        void defer(std::function<void()> &&fn) {
            Mainloop::s_mainloop->do_later(std::move(fn));
        }

        void main() {
            Metre::Mainloop loop;
            if (!loop.init()) {
                METRE_LOG(Metre::Log::CRIT, "Loop initialization failure");
                return;
            }
            loop.run();
            METRE_LOG(Metre::Log::INFO, "Shutdown complete");
        }

        void quit() {
            METRE_LOG(Metre::Log::INFO, "Shutting down...");
            Mainloop::s_mainloop->shutdown();
        }

        void reload() {
            Mainloop::s_mainloop->reload();
        }

        struct event_base * event_base() {
            return Mainloop::s_mainloop->event_base();
        }
    }
}
