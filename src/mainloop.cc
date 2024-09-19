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
#include <arpa/inet.h>
#include <fcntl.h>

#else
#include <ws2tcpip.h>
#endif
#include <map>
#include <sstream>
#include "rapidxml.hpp"
#include "xmppexcept.h"
#include "netsession.h"
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <memory>
#include <unbound.h>
#include <cerrno>
#include <cstring>
#include <atomic>
#include "sigslot.h"
#include "config.h"
#include "log.h"
#include "send.h"
#include "event2/thread.h"
#include "event2/http.h"
#include "event2/buffer.h"
#include "sockaddr-cast.h"

namespace {
    class task_sleep {
        std::coroutine_handle<> awaiting;
        bool ready = false;

    public:
        task_sleep() {
            Metre::Router::defer([this]() {
                wake();
            });
        }

        explicit task_sleep(long secs) {
            Metre::Router::defer([this]() {
                wake();
            }, secs);
        }

        explicit task_sleep(struct timeval secs) {
            Metre::Router::defer([this]() {
                wake();
            }, secs);
        }

        auto & operator co_await() {
            return *this;
        }


        bool await_ready() const {
            return ready;
        }

        void await_suspend(std::coroutine_handle<> h) {
            // The awaiting coroutine is already suspended.
            awaiting = h;
        }

        void await_resume() const {}

    private:
        void wake() {
            ready = true;
            ::sigslot::resume_switch(awaiting);
        }
    };
}

template<>
struct std::less<struct timeval> {
    constexpr bool operator()(struct timeval const & t1, struct timeval const & t2) const {
        if (t1.tv_sec == t2.tv_sec) return t1.tv_usec < t2.tv_usec;
        return t1.tv_sec < t2.tv_sec;
    }
};

namespace Metre {
    class Mainloop : public sigslot::has_slots {
    private:
        struct event_base *m_event_base = nullptr;
        struct evhttp * m_healthcheck_server = nullptr;
        std::map<unsigned long long, std::shared_ptr<NetSession>> m_sessions;
        std::map<std::string, std::weak_ptr<NetSession>, std::less<>> m_sessions_by_id;
        std::map<std::string, std::weak_ptr<NetSession>, std::less<>> m_sessions_by_domain;
        std::map<std::pair<std::string, unsigned short>, std::weak_ptr<NetSession>> m_sessions_by_address;
        struct event *m_ub_event = nullptr;
        std::list<struct evconnlistener *> m_listeners;
        static std::atomic<unsigned long long> s_serial;
        std::list<std::shared_ptr<NetSession>> m_closed_sessions;
        std::multimap<struct timeval, std::function<void()>> m_pending_actions;
        bool m_shutdown = false;
        bool m_shutdown_now = false;
        std::recursive_mutex m_scheduler_mutex;
        spdlog::logger m_logger;
        std::list<sigslot::tasklet<void>> m_coroutines;
    public:
        std::set<std::coroutine_handle<>> coro_handles;
        static Mainloop *s_mainloop;

        Mainloop():  m_logger("mainloop") {
            s_mainloop = this;
        }

        ~Mainloop() override {
            if (m_ub_event) {
                event_del(m_ub_event);
                event_free(m_ub_event);
            }
            if (m_event_base) {
                event_base_free(m_event_base);
            }
        }

        static void healthcheck_cb(struct evhttp_request *req, void *) {
            auto method = evhttp_request_get_command(req);
            const char * method_name = "UNKNOWN";
            switch (method) {
                case EVHTTP_REQ_GET:
                    method_name = "GET";
                    break;
                case EVHTTP_REQ_HEAD:
                    method_name = "HEAD";
                    break;
                case EVHTTP_REQ_POST:
                    method_name = "POST";
                    break;
                default:
                    break;
            }
            auto uri = evhttp_request_get_evhttp_uri(req);
            std::ostringstream transaction_name;
            transaction_name << method_name << " " << evhttp_uri_get_path(uri);
            auto headers = evhttp_request_get_input_headers(req);
            auto trace = evhttp_find_header(headers, "sentry-trace");
            if (trace) {
                s_mainloop->m_logger.trace("Found sentry-trace header, injecting {}", trace);
            }
            auto trans = std::make_shared<sentry::transaction>("http.server", transaction_name.str(), trace ? trace : std::optional<std::string>{});
            s_mainloop->m_coroutines.push_back(s_mainloop->healthcheck(trans, req));
            s_mainloop->m_coroutines.rbegin()->start();
        }

        sigslot::tasklet<void> healthcheck(std::shared_ptr<sentry::transaction> trans, struct evhttp_request *req) {
            switch (evhttp_request_get_command(req)) {
                case EVHTTP_REQ_GET:
                case EVHTTP_REQ_HEAD:
                    break;
                default:
                    evhttp_send_error(req, HTTP_BADMETHOD, "Method not supported");
                    co_return;
            }

            evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
            std::ostringstream body;
            body << R"({"status":"ok")";
            std::list<sigslot::tasklet<Iq const *>> pings;
            for (auto const & [from, to] : Config::config().healthchecks()) {
                std::string name = from + " -> ";
                name.append(to);
                pings.push_back(Send::ping(trans->start_child("xmpp.ping", name), Jid(from), Jid(to)));
                pings.rbegin()->set_name(name);
            }
            // Start them all in parallel
            for (auto & task : pings) {
                task.start();
            }
            auto start = time(nullptr);
            bool success = true;
            // Run them all with a timeout.
            while(!pings.empty()) {
                co_await task_sleep({0, 500}); // Pause until activity.
                auto it = pings.begin();
                while (it != pings.end()) {
                    auto const & task = *it;
                    if (!task.running()) {
                        try {
                            co_await task;
                            body << ",\"" << task.coro.promise().name << "\":true";
                        } catch(...) {
                            body << ",\"" << task.coro.promise().name << "\":false";
                            success = false;
                        }
                        it = pings.erase(it);
                    } else {
                        ++it;
                    }
                }
                if ((time(nullptr) - start) > 10) { // Arbitrary; needs configurable.
                    break;
                }
            }
            for (auto const & task : pings) {
                body << ",\"" << task.coro.promise().name << "\":false";
            }
            body << '}' << std::endl;
            auto final_body = body.str();
            std::ostringstream len;
            len << final_body.length();
            evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Length", len.str().c_str());
            auto reply = evbuffer_new();
            evbuffer_add_printf(reply, "%s", final_body.c_str());
            evhttp_send_reply(req, success ? HTTP_OK : HTTP_INTERNAL, nullptr, reply);
            evbuffer_free(reply);
            event_base_loopbreak(m_event_base); // Do this at the end for cleanup to happen.
        }

        [[nodiscard]] struct event_base * event_base() const {
            return m_event_base;
        }

        bool init() {
            if (m_event_base) {
                throw std::runtime_error("I'm already initialized!");
            }
            evthread_use_pthreads();
            m_event_base = event_base_new();
            m_logger = Config::config().logger("loop");
            bool ok = true;
            for (auto &listen : Config::config().listeners()) {
                auto listener = evconnlistener_new_bind(m_event_base, new_session_cb,
                                                        const_cast<Config::Listener *>(&listen),
                                                        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                                        listen.sockaddr(), sizeof(struct sockaddr_storage));
                if (!listener) {
                    m_logger.critical("Cannot bind to {} service port: {}", listen.name, strerror(errno));
                    continue;
                }
                m_listeners.push_back(listener);
                m_logger.info("Listening to {}", listen.name);
            }
            auto port = Config::config().healthcheck_port();
            auto address = Config::config().healthcheck_address();
            m_logger.info("Starting healthcheck service on {}:{}", address, port);
            m_healthcheck_server = evhttp_new(m_event_base);
            evhttp_bind_socket(m_healthcheck_server, address, port);
            evhttp_set_gencb(m_healthcheck_server, healthcheck_cb, nullptr);
            return ok;
        }

        std::shared_ptr<NetSession> session_by_serial(long long int id) {
            if (auto it = m_sessions.find(id);it != m_sessions.end()) {
                return (*it).second;
            }
            return nullptr;
        }

        std::shared_ptr<NetSession> session_by_id(std::string const &id) {
            if (auto it = m_sessions_by_id.find(id); it != m_sessions_by_id.end()) {
                std::shared_ptr<NetSession> s((*it).second.lock());
                return s;
            }
            return nullptr;
        }

        std::shared_ptr<NetSession> session_by_domain(std::string const &id) {
            if (auto it = m_sessions_by_domain.find(id); it != m_sessions_by_domain.end()) {
                std::shared_ptr<NetSession> s((*it).second.lock());
                return s;
            }
            return nullptr;
        }

        std::shared_ptr<NetSession> session_by_address(std::string const &host, unsigned short port) {
            if (auto it = m_sessions_by_address.find(std::make_pair(host, port)); it != m_sessions_by_address.end()) {
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
            if (auto it2 = m_sessions_by_id.find(id); it2 != m_sessions_by_id.end()) {
                std::shared_ptr<NetSession> old = it2->second.lock();
                if (!old) {
                    m_sessions_by_id.erase(it2);
                } else {
                    if (old->serial() == serial) return;
                    throw std::runtime_error("Duplicate session id - loopback?");
                }
            }
            m_sessions_by_id.try_emplace(id, (*it).second);
        }

        void unregister_stream_id(std::string const &id) {
            if (auto it2 = m_sessions_by_id.find(id); it2 != m_sessions_by_id.end()) {
                m_sessions_by_id.erase(it2);
            }
        }

        void register_session_domain(std::string const &dom, unsigned long long serial) {
            auto it = m_sessions.find(serial);
            if (it == m_sessions.end()) {
                return;
            }
            if (auto it2 = m_sessions_by_domain.find(dom); it2 != m_sessions_by_domain.end()) {
                m_sessions_by_domain.erase(it2);
            }
            m_sessions_by_domain.try_emplace(dom, (*it).second);
        }

        static void
        new_session_cb(struct evconnlistener *, evutil_socket_t newsock, struct sockaddr *addr, int len,
                       void *arg) {
            auto const *listen = static_cast<Config::Listener const *>(arg);
            Mainloop::s_mainloop->new_session_inbound(newsock, addr, len, listen);
        }

        void
        new_session_inbound(evutil_socket_t sock, struct sockaddr *sin, int, Config::Listener const *listen) {
            if (m_shutdown || m_shutdown_now) {
                evutil_closesocket(sock);
                return;
            }
            struct bufferevent *bev = bufferevent_socket_new(m_event_base, sock, BEV_OPT_CLOSE_ON_FREE);
            auto session = std::make_shared<NetSession>(std::atomic_fetch_add(&s_serial, 1ULL), bev, listen);
            if (m_sessions.contains(session->serial())) {
                // We already have one for this socket. This seems unlikely to be safe.
                m_logger.critical("Session already in ownership table; corruption.");
                assert(false);
            }
            m_logger.info("New session on {} port from {}", listen->name, address_tostring(sin));
            m_sessions[session->serial()] = session;
            session->onClosed.connect(this, &Mainloop::session_closed);
        }

        std::shared_ptr<NetSession>
        connect(std::string const &fromd, std::string const &tod, std::string const &hostname, struct sockaddr *addr,
                unsigned short port, SESSION_TYPE stype, TLS_MODE tls_mode) {
            if (addr->sa_family == AF_INET) {
                auto * sin = sockaddr_cast<AF_INET>(addr);
                sin->sin_port = htons(port);
            } else {
                auto * sin6 = sockaddr_cast<AF_INET6>(addr);
                sin6->sin6_port = htons(port);
            }
            m_logger.debug("Connecting to {}:{}", address_tostring(addr), port);
            auto sesh = connect(fromd, tod, hostname, addr,
                                sizeof(struct sockaddr_storage), port, stype, tls_mode);
            m_sessions_by_address[std::make_pair(hostname, port)] = sesh;
            if (auto it = m_sessions_by_domain.find(tod); it == m_sessions_by_domain.end() ||
                (*it).second.expired()) {
                m_sessions_by_domain[tod] = sesh;
            }
            return sesh;
        }

        std::shared_ptr<NetSession>
        connect(std::string const &fromd, std::string const &tod, std::string const &, const struct sockaddr *sin,
                size_t addrlen, unsigned short, SESSION_TYPE stype, TLS_MODE tls_mode) {
            struct bufferevent *bev = bufferevent_socket_new(m_event_base, -1, BEV_OPT_CLOSE_ON_FREE);
            if (!bev) {
                m_logger.critical("Error creating BEV");
                throw std::runtime_error("Connection failed: cannot create BEV");
            }
            if (0 > bufferevent_socket_connect(bev, sin, static_cast<int>(addrlen))) {
                m_logger.error("Error connecting BEV");
                // TODO Something bad happened.
                bufferevent_free(bev);
                throw std::runtime_error("Connection failed: Socket connect failed");
            }
            m_logger.debug("BEV fd is {}", bufferevent_getfd(bev));
            struct timeval tv = {0, 0};
            tv.tv_sec = Config::config().domain(tod).connect_timeout();
            bufferevent_set_timeouts(bev, nullptr, &tv);
            auto session = std::make_shared<NetSession>(std::atomic_fetch_add(&s_serial, 1ULL), bev, fromd, tod, stype,
                                                        tls_mode);
            if (m_sessions.contains(session->serial())) {
                // We already have one for this socket. This seems unlikely to be safe.
                m_logger.critical("Session already in ownership table; corruption.");
                assert(false);
            }
            m_sessions[session->serial()] = session;
            session->onClosed.connect(this, &Mainloop::session_closed);
            return session;
        }

        void next_break() {
            struct timeval now;
            gettimeofday(&now, nullptr);
            struct timeval t = m_pending_actions.begin()->first;
            if (t.tv_usec <= now.tv_usec) {
                if (t.tv_sec <= now.tv_sec) {
                    event_base_loopbreak(m_event_base);
                    return;
                }
                t.tv_sec -= 1;
                t.tv_usec += 1000000;
            }
            if (t.tv_sec < now.tv_sec) {
                event_base_loopbreak(m_event_base);
                return;
            }
            t.tv_sec -= now.tv_sec;
            t.tv_usec -= now.tv_usec;
            event_base_loopexit(m_event_base, &t);
        }

        void run(std::function<bool()> const &check_fn) {
            dns_setup();
            while (true) {
                if (m_shutdown) {
                    m_logger.info("Shutting down; closing listeners");
                    for (auto listener : m_listeners) {
                        evconnlistener_disable(listener);
                        evconnlistener_free(listener);
                    }
                    m_listeners.clear();
                    m_logger.info("Closing {} sessions", m_sessions.size());
                    for (auto const & [serial, session] : m_sessions) {
                        session->send(
                                "<stream:error><system-shutdown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:close>");
                        session->close();
                    }
                    m_shutdown_now = true;
                    event_base_loopexit(m_event_base, nullptr);
                    m_logger.info("Closed all sessions");
                } else {
                    std::scoped_lock l_(m_scheduler_mutex);
                    if (!m_pending_actions.empty()) {
                        next_break();
                    }
                }
                event_base_dispatch(m_event_base);
                if (check_fn()) {
                    m_shutdown = true;
                }
                for (;;) {
                    std::list<std::function<void()>> run_now;
                    {
                        std::scoped_lock l_(m_scheduler_mutex);
                        struct timeval now;
                        gettimeofday(&now, nullptr);
                        while (!m_pending_actions.empty()) {
                            auto & next = m_pending_actions.begin()->first;
                            if (std::less<struct timeval>{}.operator()(next, now)) {
                                run_now.emplace_back(std::move(m_pending_actions.begin()->second));
                                m_pending_actions.erase(m_pending_actions.begin());
                            } else {
                                break;
                            }
                        }
                    }
                    if (run_now.empty()) break;
                    for (auto const & fn : run_now) {
                        fn();
                    }
                }
                auto it = m_coroutines.begin();
                while (it != m_coroutines.end()) {
                    if (!it->running()) {
                        it->get();
                        it = m_coroutines.erase(it);
                    } else {
                        ++it;
                    }
                }
                if (m_shutdown_now && m_sessions.empty()) {
                    return;
                }
                m_closed_sessions.clear();
            }
        }

        void do_later(std::function<void()> &&fn, struct timeval seconds) {
            std::scoped_lock l_(m_scheduler_mutex);
            struct timeval now;
            gettimeofday(&now, nullptr);
            struct timeval when = now;
            when.tv_sec += seconds.tv_sec;
            when.tv_usec += seconds.tv_usec;
            if (when.tv_usec >= 1000000) {
                when.tv_sec += 1;
                when.tv_usec -= 1000000;
            }
            m_pending_actions.emplace(when, std::move(fn));
            if (seconds.tv_sec == 0 && seconds.tv_usec == 0) {
                event_base_loopbreak(m_event_base);
            } else {
                next_break();
            }
        }

        void shutdown() {
            m_shutdown = true;
            event_base_loopexit(m_event_base, nullptr);
        }

        static void unbound_cb(evutil_socket_t, short, void *arg) {
            while (ub_poll(static_cast<struct ub_ctx *>(arg))) {
                ub_process(static_cast<struct ub_ctx *>(arg));
            }
        }

        void dns_setup() {
            Config::config().dns_init();
            if (!m_ub_event) {
                m_ub_event = event_new(m_event_base, ub_fd(Config::config().ub_ctx()), EV_READ | EV_PERSIST, unbound_cb,
                                       Config::config().ub_ctx());
                event_add(m_ub_event, nullptr);
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
            m_logger.debug("NS{} - Session closed.", ns.serial());
            if (auto it = m_sessions.find(ns.serial()); it != m_sessions.end()) {
                m_closed_sessions.push_back((*it).second);
                event_base_loopexit(m_event_base, nullptr);
                m_sessions.erase(it);
            }
        }
    };

    Mainloop *Mainloop::s_mainloop{nullptr};
    std::atomic<unsigned long long> Mainloop::s_serial{0};

    namespace Router {
        std::shared_ptr<NetSession> connect(std::string const &fromd, std::string const &tod, std::string const &hostname, struct sockaddr *addr,
                unsigned short port, SESSION_TYPE stype, TLS_MODE tls_mode) {
            return Mainloop::s_mainloop->connect(fromd, tod, hostname, addr, port, stype, tls_mode);
        }

        void register_stream_id(std::string const &id, NetSession const &session) {
            Mainloop::s_mainloop->register_stream_id(id, session.serial());
        }

        void unregister_stream_id(std::string const &id) {
            Mainloop::s_mainloop->unregister_stream_id(id);
        }

        void register_session_domain(std::string const &domain, NetSession const &session) {
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

        namespace {
            std::list<std::tuple<std::function<void()>,struct timeval>> early_defer;
        }

        void defer(std::function<void()> &&fn, struct timeval seconds) {
            if (!Mainloop::s_mainloop) {
                early_defer.emplace_back(fn, seconds);
            } else {
                Mainloop::s_mainloop->do_later(std::move(fn), seconds);
            }
        }

        void defer(std::function<void()> &&fn) {
            defer(std::move(fn), {0, 0});
        }
        void defer(std::function<void()> &&fn, long seconds) {
            defer(std::move(fn), {seconds, 0});
        }

        void run(std::function<bool()> const &check_fn) {
            Metre::Mainloop loop;
            auto & logger = Config::config().logger();
            if (!loop.init()) {
                logger.critical("Loop initialization failure");
                return;
            }
            for (auto [fn, seconds] : early_defer) {
                loop.do_later(std::move(fn), seconds);
            }
            early_defer.clear();
            loop.run(check_fn);
            logger.info("Shutdown complete");
        }

        void quit() {
            Config::config().logger().info("Shutting down...");
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
        if (!Metre::Mainloop::s_mainloop->coro_handles.contains(coro)) {
            coro.resume();
            return;
        }
        Metre::Router::defer([coro]() {
            std::coroutine_handle<> c = coro;
            if (c && Metre::Mainloop::s_mainloop->coro_handles.contains(c) && !c.done()) {
                c.resume();
            }
        });
    }
    void register_coro(std::coroutine_handle<> coro) {
        Metre::Mainloop::s_mainloop->coro_handles.insert(coro);
    }
    void deregister_coro(std::coroutine_handle<> coro) {
        Metre::Mainloop::s_mainloop->coro_handles.erase(coro);
    }
}
