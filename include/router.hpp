#ifndef ROUTER__H
#define ROUTER__H

#include "jid.hpp"
#include "stanza.hpp"
#include "dns.hpp"

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
		Jid const m_domain;
		DNS::Srv m_srv;
		std::vector<DNS::SrvRR>::const_iterator m_rr;
		DNS::Address m_addr;
		std::vector<uint32_t>::const_iterator m_arr;
	public:
		Route(Jid const & to);
		void transmit(std::unique_ptr<Stanza>);
		void transmit(std::unique_ptr<Verify>);

	// Callbacks:
		void SrvResult(DNS::Srv const *);
		void AddressResult(DNS::Address const *);

	// Slots
		void SessionDialback(XMLStream &);
		void SessionAuthenticated(XMLStream &);
	};

	class RouteTable {
	private:
		std::map<std::string,std::shared_ptr<Route>> m_routes;
	public:
		std::shared_ptr<Route> & route(Jid const &to);
		static RouteTable & routeTable();
	};

	namespace Router {
		std::shared_ptr<NetSession> session_by_remote_addr(std::string const & remote_addr);
		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, uint32_t addr, unsigned short port);
		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, char addr[], unsigned short port);
		void session_closed(NetSession &);

		std::shared_ptr<NetSession> session_by_stream_id(std::string const & stream_id);
		void register_stream_id(std::string const &, NetSession &);
		void unregister_stream_id(std::string const &);
	}
}

#endif
