#ifndef ROUTER__H
#define ROUTER__H

#include "jid.hpp"
#include "stanza.hpp"

#include <string>
#include <memory>
#include <queue>

namespace Metre {
	class NetSession;

	class Route {
	private:
		std::shared_ptr<NetSession> m_to;
		std::shared_ptr<NetSession> m_from;
		std::shared_ptr<NetSession> m_vrfy;
		std::queue<std::shared_ptr<Stanza>> m_queue;
		Jid const m_domain;
	public:
		Route(Jid const & to);

	};

	class RouteTable {
	private:
		std::map<std::string,std::shared_ptr<Route>> m_routes;
	public:
		RouteTable();
		std::shared_ptr<Route> to(Jid const &to) const;
	};

	namespace Router {
		std::shared_ptr<NetSession> session_by_domain(std::string const & domain);
		std::shared_ptr<NetSession> session_by_remote_addr(std::string const & remote_addr);
		std::shared_ptr<NetSession> session_vrfy(std::string const & domain);
		int connect(NetSession *, void * addr, short port);
		void session_closed(NetSession &);
	}
}

#endif
