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

#ifdef METRE_UNIX
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

#else
#include <ws2tcpip.h>
#endif
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
#include "sigslot.h"
#include "dns.h"
#include "config.h"
#include "log.h"
#include <functional>
#include <vector>

namespace Metre {
    class Mainloop : public sigslot::has_slots {
    private:
        struct event_base *m_event_base = nullptr;
        std::map<unsigned long long, std::shared_ptr<NetSession>> m_sessions;
        std::map<std::string, std::weak_ptr<NetSession>> m_sessions_by_id;
        std::map<std::string, std::weak_ptr<NetSession>> m_sessions_by_domain;
        std::map<std::pair<std::string, unsigned short>, std::weak_ptr<NetSession>> m_sessions_by_address;
        struct event *m_ub_event = nullptr;
        std::list<struct evconnlistener *> m_listeners;
        static std::atomic<unsigned long long> s_serial;
        std::list<std::shared_ptr<NetSession>> m_closed_sessions;
        std::multimap<time_t, std::function<void()>> m_pending_actions;
        bool m_shutdown = false;
        bool m_shutdown_now = false;
        std::recursive_mutex m_scheduler_mutex;
    public:
        static Mainloop *s_mainloop;

        Mainloop() : m_sessions() {
            s_mainloop = this;
        }

        ~Mainloop() {
            if (m_ub_event) {
                event_del(m_ub_event);
                event_free(m_ub_event);
            }
            if (m_event_base) {
                event_base_free(m_event_base);
            }
        }

        struct event_base * event_base() const {
            return m_event_base;
        }

        bool init() {
            if (m_event_base) throw std::runtime_error("I'm already initialized!");
            m_event_base = event_base_new();
            for (auto &listen : Config::config().listeners()) {
                auto listener = evconnlistener_new_bind(m_event_base, new_session_cb,
                                                        const_cast<Config::Listener *>(&listen),
                                                        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                                        listen.sockaddr(), sizeof(struct sockaddr_storage));
                if (!listener) {
                    throw std::runtime_error("Cannot bind to " + listen.name + " service port: " + strerror(errno));
                }
                m_listeners.push_back(listener);
                METRE_LOG(Metre::Log::INFO, "Listening to " << listen.name << ".");
            }
            return true;
        }

        std::shared_ptr<NetSession> session_by_serial(long long int id) {
            auto it = m_sessions.find(id);
            if (it != m_sessions.end()) {
                return (*it).second;
            }
            return nullptr;
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
        new_session_cb(struct evconnlistener *listener, evutil_socket_t newsock, struct sockaddr *addr, int len,
                       void *arg) {
            Config::Listener const *listen = reinterpret_cast<Config::Listener *>(arg);
            Mainloop::s_mainloop->new_session_inbound(newsock, addr, len, listen);
        }

        void
        new_session_inbound(evutil_socket_t sock, struct sockaddr *sin, int sinlen, Config::Listener const *listen) {
            if (m_shutdown || m_shutdown_now) {
                evutil_closesocket(sock);
                return;
            }
            struct bufferevent *bev = bufferevent_socket_new(m_event_base, sock, BEV_OPT_CLOSE_ON_FREE);
            std::shared_ptr<NetSession> session(
                    new NetSession(std::atomic_fetch_add(&s_serial, 1ull), bev, listen));
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
                      "New session on " << listen->name << " port from " << addrbuf);
            m_sessions[session->serial()] = session;
            session->onClosed.connect(this, &Mainloop::session_closed);
        }

        std::shared_ptr<NetSession>
        connect(std::string const &fromd, std::string const &tod, std::string const &hostname, struct sockaddr *addr,
                unsigned short port, SESSION_TYPE stype, TLS_MODE tls_mode) {
            void *inx_addr;
            if (addr->sa_family == AF_INET) {
                auto sin = reinterpret_cast<struct sockaddr_in *>(addr);
                sin->sin_port = htons(port);
                inx_addr = &sin->sin_addr;
            } else {
                auto sin6 = reinterpret_cast<struct sockaddr_in6 *>(addr);
                sin6->sin6_port = htons(port);
                inx_addr = &sin6->sin6_addr;
            }
            char buf[INET6_ADDRSTRLEN + 1];
            METRE_LOG(Metre::Log::DEBUG,
                      "Connecting to " << inet_ntop(addr->sa_family, inx_addr, buf, INET6_ADDRSTRLEN) << ":" << port);
            auto sesh = connect(fromd, tod, hostname, addr,
                                sizeof(struct sockaddr_storage), port, stype, tls_mode);
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
                size_t addrlen, unsigned short port, SESSION_TYPE stype, TLS_MODE tls_mode) {
            struct bufferevent *bev = bufferevent_socket_new(m_event_base, -1, BEV_OPT_CLOSE_ON_FREE);
            if (!bev) {
                METRE_LOG(Metre::Log::CRIT, "Error creating BEV");
                throw std::runtime_error("Connection failed: cannot create BEV");
            }
            if (0 > bufferevent_socket_connect(bev, sin, static_cast<int>(addrlen))) {
                METRE_LOG(Metre::Log::ERR, "Error connecting BEV");
                // TODO Something bad happened.
                bufferevent_free(bev);
                throw std::runtime_error("Connection failed: Socket connect failed");
            }
            METRE_LOG(Metre::Log::DEBUG, "BEV fd is " << bufferevent_getfd(bev));
            struct timeval tv = {0, 0};
            tv.tv_sec = Config::config().domain(tod).connect_timeout();
            bufferevent_set_timeouts(bev, nullptr, &tv);
            auto session = std::make_shared<NetSession>(std::atomic_fetch_add(&s_serial, 1ull), bev, fromd, tod, stype,
                                                        tls_mode);
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

        void run(std::function<bool()> const &check_fn) {
            dns_setup();
            while (true) {
                event_base_dispatch(m_event_base);
                if (check_fn()) {
                    m_shutdown = true;
                }
                if (m_shutdown_now && m_sessions.empty()) {
                    return;
                }
                m_closed_sessions.clear();
                time_t now = std::time(nullptr);
                {
                    std::lock_guard<std::recursive_mutex> l__(m_scheduler_mutex);
                    while (!m_pending_actions.empty()) {
                        if (m_pending_actions.begin()->first <= now) {
                            m_pending_actions.begin()->second();
                            m_pending_actions.erase(m_pending_actions.begin());
                        } else {
                            break;
                        }
                    }
                }
                if (m_shutdown) {
                    METRE_LOG(Metre::Log::INFO, "Closing sessions.");
                    for (auto listener : m_listeners) {
                        evconnlistener_disable(listener);
                        evconnlistener_free(listener);
                    }
                    m_listeners.clear();
                    for (auto &it : m_sessions) {
                        it.second->send(
                                "<stream:error><system-shutdown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:close>");
                        it.second->close();
                    }
                    m_shutdown_now = true;
                    event_base_loopexit(m_event_base, NULL);
                    METRE_LOG(Metre::Log::INFO, "Closed all sessions.");
                } else {
                    std::lock_guard<std::recursive_mutex> l__(m_scheduler_mutex);
                    if (!m_pending_actions.empty()) {
                        struct timeval t = {0, 0};
                        t.tv_sec = m_pending_actions.begin()->first - now;
                        event_base_loopexit(m_event_base, &t);
                    }
                }
            }
        }

        void do_later(std::function<void()> &&fn, std::size_t seconds) {
            std::lock_guard<std::recursive_mutex> l__(m_scheduler_mutex);
            time_t now = time(nullptr);
            m_pending_actions.emplace(now + seconds, std::move(fn));
            struct timeval t = {0, 0};
            t.tv_sec = m_pending_actions.begin()->first - now;
            event_base_loopexit(m_event_base, &t);
        }

        void shutdown() {
            m_shutdown = true;
            event_base_loopexit(m_event_base, NULL);
        }

        static void unbound_cb(evutil_socket_t, short, void *arg) {
            while (ub_poll(reinterpret_cast<struct ub_ctx *>(arg))) {
                ub_process(reinterpret_cast<struct ub_ctx *>(arg));
            }
        }

        void dns_setup() {
            Config::config().dns_init();
            if (!m_ub_event) {
                m_ub_event = event_new(m_event_base, ub_fd(Config::config().ub_ctx()), EV_READ | EV_PERSIST, unbound_cb,
                                       Config::config().ub_ctx());
                event_add(m_ub_event, NULL);
            }
        }

        void reload() {
            if (m_ub_event) {
                event_del(m_ub_event);
                event_free(m_ub_event);
                m_ub_event = nullptr;
            }
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
        connect(std::string const &fromd, std::string const &tod, std::string const &hostname, struct sockaddr *addr,
                unsigned short port, SESSION_TYPE stype, TLS_MODE tls_mode) {
            return Mainloop::s_mainloop->connect(fromd, tod, hostname, addr, port, stype, tls_mode);
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

        std::shared_ptr<NetSession> session_by_serial(long long int serial) {
            return Mainloop::s_mainloop->session_by_serial(serial);
        }

        void defer(std::function<void()> &&fn) {
            Mainloop::s_mainloop->do_later(std::move(fn), 0);
        }

        void defer(std::function<void()> &&fn, std::size_t seconds) {
            Mainloop::s_mainloop->do_later(std::move(fn), seconds);
        }

        void main(std::function<bool()> const &check_fn) {
            Metre::Mainloop loop;
            if (!loop.init()) {
                METRE_LOG(Metre::Log::CRIT, "Loop initialization failure");
                return;
            }
            //Config::config().dns_init();
            loop.run(check_fn);
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

namespace sigslot {
    void resume(std::coroutine_handle<> coro) {
        Metre::Router::defer([=]() {
            std::coroutine_handle<> c = coro;
            c.resume();
        });
    }
}