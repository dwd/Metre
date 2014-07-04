#ifndef ROUTER__H
#define ROUTER__H

#include <string>
#include <memory>

namespace Metre {
	class NetSession;

	namespace Router {
		std::shared_ptr<NetSession> session_by_domain(std::string const & domain);
		std::shared_ptr<NetSession> session_by_remote_addr(std::string const & remote_addr);
		std::shared_ptr<NetSession> session_vrfy(std::string const & domain);
		int connect(NetSession *, void * addr, short port);
		void session_closed(NetSession &);
	}
}

#endif
