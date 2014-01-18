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
#include <memory>
#include "router.hpp"
#include <unbound.h>
#include <cerrno>
#include <cstring>

namespace Metre {
	class Mainloop {
	private:
		struct event_base * m_event_base;
		struct event * m_listen;
		Server & m_server;
		std::map<evutil_socket_t, std::shared_ptr<NetSession>> m_sessions;
		std::map<std::string, std::weak_ptr<NetSession>> m_sessions_bydomain;
		struct ub_ctx * m_ub_ctx;
		struct event * m_ub_event;
	public:
		static Mainloop * s_mainloop;
		Mainloop(Server & server) : m_event_base(0), m_listen(0), m_server(server), m_sessions(), m_ub_event(0) {
			s_mainloop = this;
		}
		bool init() {
			if (m_event_base) throw std::runtime_error("I'm already initialized!");
			m_event_base = event_base_new();
			auto lsock = socket(AF_INET6, SOCK_STREAM, 0);
			sockaddr_in6 sin = { AF_INET6, htons(5269), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
			if (0 > bind(lsock, (sockaddr *)&sin, sizeof(sin))) {
				throw std::runtime_error(std::string("Cannot bind to server port: ") + strerror(errno));
			}
			int opt = 1;
			setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
			if (0 > listen(lsock, 5)) {
				throw std::runtime_error("Cannot listen!");
			}
			std::cout << "Listening." << std::endl;
			m_listen = event_new(m_event_base, lsock, EV_READ|EV_PERSIST, Mainloop::new_session_cb, this);
			event_add(m_listen, NULL);
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
		
		void netsession_event(evutil_socket_t sock, NetSession * s) {
			if (!s->drain()) {
				event_free(reinterpret_cast<struct event *>(s->loop_read));
				event_free(reinterpret_cast<struct event *>(s->loop_write));
				auto it = m_sessions.find(sock);
				if (it != m_sessions.end()) {
					m_sessions.erase(it);
				} else {
					// So we're dealing with a session that's not in the table.
					// We're inside a C callback; the best thing to do here is exit hard.
					std::cerr << "Session not in ownership table; corruption." << std::endl;
					assert(false);
				}
				return;
			}
			if (s->need_push()) {
				s->push();
			}
			if (s->need_push()) {
				event_add(reinterpret_cast<struct event *>(s->loop_write), NULL);
			}
		}
		
		static void event_callback(evutil_socket_t sock, short what, void * ptr) {
			NetSession * s = reinterpret_cast<NetSession *>(ptr);
			s_mainloop->netsession_event(sock, s);
		}
		
		static void new_session_cb(evutil_socket_t sock, short, void * arg) {
			reinterpret_cast<Mainloop *>(arg)->new_session_inbound(sock);
		}
		
		void new_session_inbound(evutil_socket_t lsock) {
			auto sock = accept(lsock, NULL, NULL);
			int fl = O_NONBLOCK;
			fcntl(sock, F_SETFL, fl); 
			std::shared_ptr<NetSession> session(new NetSession(sock, INBOUND, S2S, &m_server));
			auto it = m_sessions.find(sock);
			if (it != m_sessions.end()) {
				// We already have one for this socket. This seems unlikely to be safe.
				std::cerr << "Session already in ownership table; corruption." << std::endl;
				assert(false);
			}
			m_sessions[sock] = session;
			struct event * ev = event_new(m_event_base, sock, EV_READ|EV_PERSIST, event_callback, &*session);
			session->loop_read = ev;
			event_add(ev, NULL);
			ev = event_new(m_event_base, sock, EV_WRITE, event_callback, &*session);
			session->loop_write = ev;
		}
		
		void run() {
			event_base_dispatch(m_event_base);
		}
		
		void new_session_vrfy(std::string const & domain) {
			
		}
		
		void srv_lookup_done(int err, struct ub_result * result) {
			try {
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
				ub_resolve_free(result);
			} catch(...) {
				ub_resolve_free(result);
				throw;
			}
		}
		
		static void srv_lookup_done_cb(void * x, int err, struct ub_result * result) {
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
		
		std::shared_ptr<NetSession> session_vrfy(std::string const & domain) {
			srv_lookup(domain);
			return 0;
		}
	};

	Mainloop * Mainloop::s_mainloop = 0;
	std::shared_ptr<NetSession> Router::session_vrfy(std::string const & domain) {
		return Mainloop::s_mainloop->session_vrfy(domain);
	}
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
