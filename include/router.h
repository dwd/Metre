#ifndef ROUTER__H
#define ROUTER__H

#include "jid.h"
#include "stanza.h"
#include "dns.h"

#include <string>
#include <memory>
#include <queue>
#include <map>

namespace Metre {
	class NetSession;

	class Route : public sigslot::has_slots<> {
	private:
		std::weak_ptr<NetSession> m_to;
		std::weak_ptr<NetSession> m_from;
		std::weak_ptr<NetSession> m_vrfy;
		std::list<std::unique_ptr<Stanza>> m_stanzas;
		std::list<std::unique_ptr<Verify>> m_dialback;
		Jid const m_local;
		Jid const m_domain;
		DNS::Srv m_srv;
		std::vector<DNS::SrvRR>::const_iterator m_rr;
		DNS::Address m_addr;
		std::vector<uint32_t>::const_iterator m_arr;
		std::vector<DNS::Tlsa> m_tlsa;
	public:
		Route(Jid const & from, Jid const & to);
		std::string const & domain() {
			return m_domain.domain();
		}
		std::string const & local() {
			return m_local.domain();
		}
		void transmit(std::unique_ptr<Stanza>);
		void transmit(std::unique_ptr<Verify>);

		void doSrvLookup();

	// Callbacks:
		void SrvResult(DNS::Srv const *);
		void AddressResult(DNS::Address const *);
		void TlsaResult(DNS::Tlsa const *);

	// Slots
		void SessionDialback(XMLStream &);
		void SessionAuthenticated(XMLStream &);

		void collateNames();
		sigslot::signal<sigslot::thread::st, Route &> onNamesCollated;
		std::vector<DNS::Tlsa> const & tlsa() const {
			return m_tlsa;
		}
		DNS::Srv const & srv() const {
			return m_srv;
		}
	};

	class RouteTable {
	private:
		std::map<std::string,std::shared_ptr<Route>> m_routes;
		std::string m_local_domain;
	public:
		RouteTable(std::string const &);
		std::shared_ptr<Route> & route(Jid const &to);
		void addRoute(XMLStream const & stream);
		static RouteTable & routeTable(std::string const &);
		static RouteTable & routeTable(Jid const &);
	};

	namespace Router {
		std::shared_ptr<NetSession> session_by_address(std::string const & remote_addr, unsigned short port);
		std::shared_ptr<NetSession> session_by_domain(std::string const & remote_addr);
		void register_session_domain(std::string const & dom, NetSession &);
		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, uint32_t addr, unsigned short port);
		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, char addr[], unsigned short port);
		void session_closed(NetSession &);

		std::shared_ptr<NetSession> session_by_stream_id(std::string const & stream_id);
		void register_stream_id(std::string const &, NetSession &);
		void unregister_stream_id(std::string const &);

		void defer(std::function<void()> &&);
	}
}

#endif
