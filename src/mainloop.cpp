#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include "rapidxml.hpp"
#include <optional> // Uses the supplied optional by default.
#include "xmppexcept.hpp"
#include "server.hpp"
#include "netsession.hpp"
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <memory>
#include "router.hpp"
#include <unbound.h>
#include <cerrno>
#include <cstring>
#include <atomic>
#include "sigslot/sigslot.h"

namespace Metre {
	class Mainloop : public sigslot::has_slots<> {
	private:
		struct event_base * m_event_base;
		struct event * m_listen;
		Server & m_server;
		std::map<unsigned long long, std::shared_ptr<NetSession>> m_sessions;
		struct ub_ctx * m_ub_ctx;
		struct event * m_ub_event;
		struct evconnlistener * m_server_listener;
		static std::atomic<unsigned long long> s_serial;
	public:
		static Mainloop * s_mainloop;
		Mainloop(Server & server) : m_event_base(0), m_listen(0), m_server(server), m_sessions(), m_ub_event(0) {
			s_mainloop = this;
		}
		bool init() {
			if (m_event_base) throw std::runtime_error("I'm already initialized!");
			m_event_base = event_base_new();
			sockaddr_in6 sin = { AF_INET6, htons(5269), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
			m_server_listener = evconnlistener_new_bind(m_event_base, Mainloop::new_session_cb, this, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
			if (!m_server_listener) {
				throw std::runtime_error(std::string("Cannot bind to server port: ") + strerror(errno));
			}
			std::cout << "Listening." << std::endl;
			std::cout << "Setting up DNS" << std::endl;
			m_ub_ctx = ub_ctx_create();
			if (!m_ub_ctx) {
				throw std::runtime_error("DNS context creation failure.");
			}
			int retval;
			if ((retval = ub_ctx_resolvconf(m_ub_ctx, NULL)) != 0) {
				throw std::runtime_error(ub_strerror(retval));
			}
			if ((retval = ub_ctx_add_ta_file(m_ub_ctx, "keys")) != 0) {
				throw std::runtime_error(ub_strerror(retval));
			}
			return true;
		}

		static void new_session_cb(struct evconnlistener * listener, evutil_socket_t newsock, struct sockaddr * addr, int len, void * arg) {
			reinterpret_cast<Mainloop *>(arg)->new_session_inbound(newsock, addr, len);
		}

		void new_session_inbound(evutil_socket_t sock, struct sockaddr * sin, int sinlen) {
			struct bufferevent * bev = bufferevent_socket_new(m_event_base, sock, BEV_OPT_CLOSE_ON_FREE);
			std::shared_ptr<NetSession> session(new NetSession(std::atomic_fetch_add(&s_serial, 1ull), bev, S2S, &m_server));
			auto it = m_sessions.find(session->serial());
			if (it != m_sessions.end()) {
				// We already have one for this socket. This seems unlikely to be safe.
				std::cerr << "Session already in ownership table; corruption." << std::endl;
				assert(false);
			}
			m_sessions[session->serial()] = session;
			session->closed.connect(this, &Mainloop::session_closed);
		}

		void run() {
			event_base_dispatch(m_event_base);
		}

		void new_session_vrfy(std::string const & domain) {

		}

		void srv_lookup_done(int err, struct ub_result * result) {
			std::cout << "Done SRV lookup" << std::endl;
			if (err != 0) {
				std::cout << "Resolve error for SRV: " << ub_strerror(err) << std::endl;
				return;
			} else if (!result->havedata) {
				std::cout << "No SRV records." << std::endl;
			} else if (result->bogus) {
				std::cout << "Forged result; ignoring." << std::endl;
			} else {
				if (result->secure) {
					std::cout << "DNSSEC secured; add reference names" << std::endl;
				}
				std::string domain = result->qname;
				for (int i = 0; result->data[i]; ++i) {
					short priority = ntohs(*reinterpret_cast<short*>(result->data[i]));
					short weight = ntohs(*reinterpret_cast<short*>(result->data[i]+2));
					short port = ntohs(*reinterpret_cast<short*>(result->data[i]+4));
					std::string hostname;
					for (int x = 6; result->data[i][x]; x += result->data[i][x] + 1) {
						hostname.append(result->data[i]+x+1, result->data[i][x]);
						hostname += ".";
					}
					std::cout << "Data[" << i << "]: (" << result->len[i] << " bytes) "
						<< priority << ":"
						<< weight << ":"
						<< port << "::"
						<< hostname << std::endl;
				}
			}
		}

		class UBResult {
			/* Quick guard class. */
		public:
			struct ub_result * result;
			UBResult(struct ub_result * r) : result(r) {}
			~UBResult() { ub_resolve_free(result); }
		};

		static void srv_lookup_done_cb(void * x, int err, struct ub_result * result) {
			UBResult r{result};
			reinterpret_cast<Mainloop *>(x)->srv_lookup_done(err, result);
		}

		static void unbound_cb(evutil_socket_t, short, void * arg) {
			ub_process(reinterpret_cast<struct ub_ctx *>(arg));
		}

		void check_dns_setup() {
			if (!m_ub_event) {
				m_ub_event = event_new(m_event_base, ub_fd(m_ub_ctx), EV_READ|EV_PERSIST, unbound_cb, m_ub_ctx);
				event_add(m_ub_event, NULL);
			}
		}

		void srv_lookup(std::string const & domain) {
			std::cout << "SRV lookup for _xmpp-server._tcp." << domain << std::endl;
			int retval = ub_resolve_async(m_ub_ctx,
				("_xmpp-server._tcp." + domain).c_str(),
				33, /* SRV */
				1,  /* IN */
				this,
				srv_lookup_done_cb,
				NULL); /* int * async_id */
			check_dns_setup();
		}

		void session_closed(NetSession & ns) {
			auto it = m_sessions.find(ns.serial());
			assert(it != m_sessions.end());
			if (it != m_sessions.end()) {
				m_sessions.erase(it);
			}
		}
	};

	Mainloop * Mainloop::s_mainloop{nullptr};
	std::atomic<unsigned long long> Mainloop::s_serial{0};
}

int main(int argc, char *argv[]) {
	Metre::Server server;
	Metre::Mainloop loop(server);

	if (!loop.init()) {
		return 1;
	}
	loop.run();

	return 0;
}
