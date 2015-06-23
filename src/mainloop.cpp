#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include <sstream>
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
#include "dns.hpp"
#include <arpa/inet.h>
#include "config.h"
#include "log.h"

namespace Metre {
	class Mainloop : public sigslot::has_slots<> {
	private:
		struct event_base * m_event_base;
		struct event * m_listen;
		Server & m_server;
		std::map<unsigned long long, std::shared_ptr<NetSession>> m_sessions;
		std::map<std::string, std::weak_ptr<NetSession>> m_sessions_by_id;
		std::map<std::string, std::weak_ptr<NetSession>> m_sessions_by_domain;
		std::map<std::pair<std::string,unsigned short>, std::weak_ptr<NetSession>> m_sessions_by_address;
		struct ub_ctx * m_ub_ctx;
		struct event * m_ub_event;
		struct evconnlistener * m_server_listener;
		struct evconnlistener * m_component_listener;
		static std::atomic<unsigned long long> s_serial;
		std::list<std::shared_ptr<NetSession>> m_closed_sessions;
	public:
		static Mainloop * s_mainloop;
		Mainloop(Server & server) : m_event_base(0), m_listen(0), m_server(server), m_sessions(), m_ub_event(0) {
			s_mainloop = this;
		}
		struct ub_ctx * ub_ctx() {
			return m_ub_ctx;
		}
		bool init() {
			if (m_event_base) throw std::runtime_error("I'm already initialized!");
			m_event_base = event_base_new();
			{
				sockaddr_in6 sin = { AF_INET6, htons(5269), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
				m_server_listener = evconnlistener_new_bind(m_event_base, Mainloop::new_server_session_cb, this, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
				if (!m_server_listener) {
					throw std::runtime_error(std::string("Cannot bind to server port: ") + strerror(errno));
				}
				METRE_LOG("Listening to server.");
			}
			{
				sockaddr_in6 sin = { AF_INET6, htons(5347), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
				m_component_listener = evconnlistener_new_bind(m_event_base, Mainloop::new_comp_session_cb, this, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
				if (!m_component_listener) {
					throw std::runtime_error(std::string("Cannot bind to component port: ") + strerror(errno));
				}
				METRE_LOG("Listening to component.");
			}
			METRE_LOG("Setting up DNS");
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

		std::shared_ptr<NetSession> session_by_id(std::string const & id) {
			auto it = m_sessions_by_id.find(id);
			if (it != m_sessions_by_id.end()) {
				std::shared_ptr<NetSession> s((*it).second.lock());
				return s;
			}
			return nullptr;
		}
		std::shared_ptr<NetSession> session_by_domain(std::string const & id) {
			auto it = m_sessions_by_domain.find(id);
			if (it != m_sessions_by_domain.end()) {
				std::shared_ptr<NetSession> s((*it).second.lock());
				return s;
			}
			return nullptr;
		}
		std::shared_ptr<NetSession> session_by_address(std::string const & host, unsigned short port) {
			auto it = m_sessions_by_address.find(std::make_pair(host,port));
			if (it != m_sessions_by_address.end()) {
				std::shared_ptr<NetSession> s((*it).second.lock());
				return s;
			}
			return nullptr;
		}

		void register_stream_id(std::string const & id, unsigned long long serial) {
			auto it = m_sessions.find(serial);
			if (it == m_sessions.end()) {
				return;
			}
			auto it2 = m_sessions_by_id.find(id);
			if (it2 != m_sessions_by_id.end()) {
				m_sessions_by_id.erase(it2);
			}
			m_sessions_by_id.insert(std::make_pair(id, (*it).second));
		}
		void unregister_stream_id(std::string const & id) {
			auto it2 = m_sessions_by_id.find(id);
			if (it2 != m_sessions_by_id.end()) {
				m_sessions_by_id.erase(it2);
			}
		}

		void register_session_domain(std::string const & dom, unsigned long long serial) {
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

		static void new_server_session_cb(struct evconnlistener * listener, evutil_socket_t newsock, struct sockaddr * addr, int len, void * arg) {
			reinterpret_cast<Mainloop *>(arg)->new_session_inbound(newsock, addr, len, S2S);
		}

		static void new_comp_session_cb(struct evconnlistener * listener, evutil_socket_t newsock, struct sockaddr * addr, int len, void * arg) {
			reinterpret_cast<Mainloop *>(arg)->new_session_inbound(newsock, addr, len, COMP);
		}

		void new_session_inbound(evutil_socket_t sock, struct sockaddr * sin, int sinlen, SESSION_TYPE stype) {
			struct bufferevent * bev = bufferevent_socket_new(m_event_base, sock, BEV_OPT_CLOSE_ON_FREE);
			std::shared_ptr<NetSession> session(new NetSession(std::atomic_fetch_add(&s_serial, 1ull), bev, stype, &m_server));
			auto it = m_sessions.find(session->serial());
			if (it != m_sessions.end()) {
				// We already have one for this socket. This seems unlikely to be safe.
				METRE_LOG("Session already in ownership table; corruption.");
				assert(false);
			}
			m_sessions[session->serial()] = session;
			session->onClosed.connect(this, &Mainloop::session_closed);
		}

		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, uint32_t addr, unsigned short port) {
			struct sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = addr;
			sin.sin_port = htons(port);
			char buf[25];
			METRE_LOG("Connecting to " << inet_ntop(AF_INET, &sin.sin_addr, buf, 25) << ":" << ntohs(sin.sin_port)  << ":" << port);
			std::shared_ptr<NetSession> sesh = connect(fromd, tod, hostname, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin), port);
			m_sessions_by_address[std::make_pair(hostname,port)] = sesh;
			auto it = m_sessions_by_domain.find(tod);
			if (it == m_sessions_by_domain.end() ||
					(*it).second.expired()) {
				m_sessions_by_domain[tod] = sesh;
			}
			return sesh;
		}

		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, struct sockaddr * sin, size_t addrlen, unsigned short port) {
			struct bufferevent * bev = bufferevent_socket_new(m_event_base, -1, BEV_OPT_CLOSE_ON_FREE);
			if (!bev) {
				METRE_LOG("Error creating BEV");
				// TODO ARGH!
			}
			if(0 > bufferevent_socket_connect(bev, sin, addrlen)) {
				METRE_LOG("Error connecting BEV");
				// TODO Something bad happened.
				bufferevent_free(bev);
			}
			METRE_LOG("BEV fd is " << bufferevent_getfd(bev));
			std::shared_ptr<NetSession> session(new NetSession(std::atomic_fetch_add(&s_serial, 1ull), bev, fromd, tod, &m_server));
			auto it = m_sessions.find(session->serial());
			if (it != m_sessions.end()) {
				// We already have one for this socket. This seems unlikely to be safe.
				METRE_LOG("Session already in ownership table; corruption.");
				assert(false);
			}
			m_sessions[session->serial()] = session;
			session->onClosed.connect(this, &Mainloop::session_closed);
			return session;
		}

		void run() {
			while(true) {
				event_base_dispatch(m_event_base);
				m_closed_sessions.clear();
			}
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

		void session_closed(NetSession & ns) {
			auto it = m_sessions.find(ns.serial());
			if (it != m_sessions.end()) {
				m_closed_sessions.push_back((*it).second);
				event_base_loopexit(m_event_base, NULL);
				m_sessions.erase(it);
			}
		}
	};

	class ResolverImpl : public Metre::DNS::Resolver {
	private:
		std::map<std::string, DNS::Resolver::srv_callback_t> m_srv_pending;
		std::map<std::string, DNS::Resolver::addr_callback_t> m_a_pending;
		std::map<std::string, DNS::Resolver::tlsa_callback_t> m_tlsa_pending;
	public:
		void tlsa_lookup_done(int err, struct ub_result * result) {
			std::string error;
			if (err != 0) {
				error = ub_strerror(err);
				return;
			} else if (!result->havedata) {
				error = "No TLSA records present";
			} else if (result->bogus) {
				error = std::string("Bogus: ") + result->why_bogus;
			} else {
				DNS::Tlsa tlsa;
				tlsa.dnssec = result->secure;
				tlsa.domain = result->qname;
				for (int i = 0; result->data[i]; ++i) {
					DNS::TlsaRR rr;
					rr.certUsage = static_cast<DNS::TlsaRR::CertUsage>(result->data[i][0]);
					rr.selector = static_cast<DNS::TlsaRR::Selector>(result->data[i][1]);
					rr.matchType = static_cast<DNS::TlsaRR::MatchType>(result->data[i][2]);
					rr.matchData.assign(result->data[i] + 3, result->len[i] - 3);
					tlsa.rrs.push_back(rr);
					METRE_LOG("Data[" << i << "]: (" << result->len[i] << " bytes) "
						<< rr.certUsage << ":"
						<< rr.selector << ":"
						<< rr.matchType << "::"
						<< rr.matchData);
				}
				auto it = m_tlsa_pending.find(tlsa.domain);
				if (it != m_tlsa_pending.end()) {
					(*it).second.emit(&tlsa);
					m_tlsa_pending.erase(it);
				}
				return;
			}
			METRE_LOG("DNS Error: " << error);
			auto it = m_tlsa_pending.find(result->qname);
			if (it != m_tlsa_pending.end()) {
				DNS::Tlsa tlsa;
				tlsa.error = error;
				tlsa.domain = result->qname;
				(*it).second.emit(&tlsa);
				m_tlsa_pending.erase(it);
			}
		}
		void srv_lookup_done(int err, struct ub_result * result) {
			std::string error;
			if (err != 0) {
				error = ub_strerror(err);
				return;
			} else if (!result->havedata) {
				error = "No SRV records present";
			} else if (result->bogus) {
				error = std::string("Bogus: ") + result->why_bogus;
			} else {
				DNS::Srv srv;
				srv.dnssec = result->secure;
				srv.domain = result->qname;
				for (int i = 0; result->data[i]; ++i) {
					DNS::SrvRR rr;
					rr.priority = ntohs(*reinterpret_cast<short*>(result->data[i]));
					rr.weight = ntohs(*reinterpret_cast<short*>(result->data[i]+2));
					rr.port = ntohs(*reinterpret_cast<short*>(result->data[i]+4));
					for (int x = 6; result->data[i][x]; x += result->data[i][x] + 1) {
						rr.hostname.append(result->data[i]+x+1, result->data[i][x]);
						rr.hostname += ".";
					}
					srv.rrs.push_back(rr);
					METRE_LOG("Data[" << i << "]: (" << result->len[i] << " bytes) "
						<< rr.priority << ":"
						<< rr.weight << ":"
						<< rr.port << "::"
						<< rr.hostname);
				}
				auto it = m_srv_pending.find(srv.domain);
				if (it != m_srv_pending.end()) {
					(*it).second.emit(&srv);
					m_srv_pending.erase(it);
				}
				return;
			}
			METRE_LOG("DNS Error: " << error);
			auto it = m_srv_pending.find(result->qname);
			if (it != m_srv_pending.end()) {
				DNS::Srv srv;
				srv.error = error;
				srv.domain = result->qname;
				(*it).second.emit(&srv);
				m_srv_pending.erase(it);
			}
		}
		void a_lookup_done(int err, struct ub_result * result) {
			std::string error;
			if (err != 0) {
				error = ub_strerror(err);
				return;
			} else if (!result->havedata) {
				error = "No A records present";
			} else if (result->bogus) {
				error = std::string("Bogus: ") + result->why_bogus;
			} else {
				DNS::Address a;
				a.dnssec = result->secure;
				a.hostname = result->qname;
				for (int i = 0; result->data[i]; ++i) {
					a.addr4.push_back(*reinterpret_cast<uint32_t *>(result->data[0]));
				}
				auto it = m_a_pending.find(a.hostname);
				if (it != m_a_pending.end()) {
					(*it).second.emit(&a);
					m_a_pending.erase(it);
				}
				return;
			}
			auto it = m_a_pending.find(result->qname);
			if (it != m_a_pending.end()) {
				DNS::Address a;
				a.error = error;
				a.hostname = result->qname;
				(*it).second.emit(&a);
				m_a_pending.erase(it);
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
			reinterpret_cast<ResolverImpl *>(x)->srv_lookup_done(err, result);
		}

		static void a_lookup_done_cb(void * x, int err, struct ub_result * result) {
			UBResult r{result};
			reinterpret_cast<ResolverImpl *>(x)->a_lookup_done(err, result);
		}

		static void tlsa_lookup_done_cb(void * x, int err, struct ub_result * result) {
			UBResult r{result};
			reinterpret_cast<ResolverImpl *>(x)->tlsa_lookup_done(err, result);
		}

		virtual Resolver::srv_callback_t & SrvLookup(std::string const & base_domain) {
			std::string domain = "_xmpp-server._tcp." + base_domain;
			METRE_LOG("SRV lookup for " << domain);
			auto it = m_srv_pending.find(domain);
			if (it != m_srv_pending.end()) {
				return (*it).second;
			}
			int retval = ub_resolve_async(Mainloop::s_mainloop->ub_ctx(),
				domain.c_str(),
				33, /* SRV */
				1,  /* IN */
				this,
				srv_lookup_done_cb,
				NULL); /* int * async_id */
			Mainloop::s_mainloop->check_dns_setup();
			return m_srv_pending[domain];
		}

		virtual Resolver::tlsa_callback_t & TlsaLookup(std::string const & fordomain, unsigned short port, std::string const & base_domain) {
			std::ostringstream out;
			out << "_" << port << "._tcp." << base_domain;
			std::string domain = out.str();
			METRE_LOG("SRV lookup for " << domain);
			auto it = m_tlsa_pending.find(domain);
			if (it != m_tlsa_pending.end()) {
				return (*it).second;
			}
			int retval = ub_resolve_async(Mainloop::s_mainloop->ub_ctx(),
				domain.c_str(),
				52, /* TLSA */
				1,  /* IN */
				this,
				tlsa_lookup_done_cb,
				NULL); /* int * async_id */
			Mainloop::s_mainloop->check_dns_setup();
			return m_tlsa_pending[domain];
		}

		virtual Resolver::addr_callback_t & AddressLookup(std::string const & domain, std::string const & hostname) {
			METRE_LOG("A/AAAA lookup for " << hostname);
			auto it = m_a_pending.find(hostname);
			if (it != m_a_pending.end()) {
				return (*it).second;
			}
			int retval = ub_resolve_async(Mainloop::s_mainloop->ub_ctx(),
				hostname.c_str(),
				1, /* A */
				1,  /* IN */
				this,
				a_lookup_done_cb,
				NULL); /* int * async_id */
			Mainloop::s_mainloop->check_dns_setup();
			return m_a_pending[hostname];
		}
	};

	Mainloop * Mainloop::s_mainloop{nullptr};
	std::atomic<unsigned long long> Mainloop::s_serial{0};
	ResolverImpl * s_resolver{nullptr};

	namespace DNS {
		Resolver & Resolver::resolver() {
			if (!s_resolver) s_resolver = new ResolverImpl;
			return *s_resolver;
		}
	}

	namespace Router {
		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, uint32_t addr, unsigned short port) {
			return Mainloop::s_mainloop->connect(fromd, tod, hostname, addr, port);
		}

		void register_stream_id(std::string const & id, NetSession & session) {
			Mainloop::s_mainloop->register_stream_id(id, session.serial());
		}
		void unregister_stream_id(std::string const & id) {
			Mainloop::s_mainloop->unregister_stream_id(id);
		}
		void register_session_domain(std::string const & domain, NetSession & session) {
			Mainloop::s_mainloop->register_session_domain(domain, session.serial());
		}
		std::shared_ptr<NetSession> session_by_stream_id(std::string const & id) {
			return Mainloop::s_mainloop->session_by_id(id);
		}
		std::shared_ptr<NetSession> session_by_domain(std::string const & id) {
			return Mainloop::s_mainloop->session_by_domain(id);
		}
		std::shared_ptr<NetSession> session_by_address(std::string const & id, unsigned short p) {
			return Mainloop::s_mainloop->session_by_address(id, p);
		}
	}
}

int main(int argc, char *argv[]) {
	Metre::Server server;
	Metre::Mainloop loop(server);
	new Metre::Config("./metre.conf.xml");
	new Metre::Log("./metre.log");

	if (!loop.init()) {
		return 1;
	}
	loop.run();

	return 0;
}
