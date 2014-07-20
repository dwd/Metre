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
		std::shared_ptr<NetSession> m_to;
		std::shared_ptr<NetSession> m_from;
		std::shared_ptr<NetSession> m_vrfy;
		std::vector<Stanza> m_queue;
		std::vector<Verify> m_dialback;
		Jid const m_domain;
		DNS::Srv m_srv;
		std::vector<DNS::SrvRR>::const_iterator m_rr;
		DNS::Address m_addr;
		std::vector<unsigned long>::const_iterator m_arr;
	public:
		Route(Jid const & to);
		void transmit(Stanza const &);
		void transmit(Verify const &);

	// Callbacks:
		void SrvResult(DNS::Srv);
		void AddressResult(DNS::Address);
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
		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, unsigned long addr, unsigned short port);
		std::shared_ptr<NetSession> connect(std::string const & fromd, std::string const & tod, std::string const & hostname, char addr[], unsigned short port);
		void session_closed(NetSession &);
	}
}

#endif
