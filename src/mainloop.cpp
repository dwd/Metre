#include <zmq.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include "rapidxml.hpp"
#include <optional> // Uses the supplied optional by default.
#include "jid.hpp"
#include "xmppexcept.hpp"
#include "stanza.hpp"
#include "server.hpp"
#include "netsession.hpp"

using namespace Metre;

int main(int argc, char *argv[]) {
	zmq::context_t context(1);
	auto lsock = socket(AF_INET6, SOCK_STREAM, 0);
	sockaddr_in6 sin = { AF_INET6, htons(5222), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
	if (0 > bind(lsock, (sockaddr *)&sin, sizeof(sin))) {
		std::cout << "Cannot bind!" << std::endl;
		return 1;
	}
	int opt = 1;
	setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (0 > listen(lsock, 5)) {
		std::cout << "Cannot listen!" << std::endl;
		return 2;
	}
	std::cout << "Listening." << std::endl;
	std::vector<zmq::pollitem_t> pollitems;
	zmq::pollitem_t pollitem;
	pollitem.socket = NULL;
	pollitem.fd = lsock;
	pollitem.events = ZMQ_POLLIN;
	pollitems.push_back(pollitem);
	std::map<int, NetSession *> sockets;
	Server server;
	while (true) {
		zmq::poll(&pollitems[0], pollitems.size());
		if (pollitems[0].revents & ZMQ_POLLIN) {
			auto sock = accept(pollitems[0].fd, NULL, NULL);
			int fl = O_NONBLOCK;
			fcntl(sock, F_SETFL, fl); 
			zmq::pollitem_t pollitem;
			pollitem.socket = NULL;
			pollitem.fd = sock;
			pollitem.events = ZMQ_POLLIN;
			pollitems.push_back(pollitem);
			sockets[sock] = new NetSession(sock, C2S, &server);
		}
		for (auto & pollitem : pollitems) {
			if (pollitem.fd == lsock) continue;
			std::cout << "Activity on " << pollitem.fd << std::endl;
			if (!sockets[pollitem.fd]->drain()) {
				std::cout << "Close on drain of " << pollitem.fd << std::endl;
				delete sockets[pollitem.fd];
				sockets[pollitem.fd] = 0;
				pollitem.fd = -1;
				continue;
			}
			if (sockets[pollitem.fd]->need_push()) {
				sockets[pollitem.fd]->push();
			}
			if (sockets[pollitem.fd]->need_push()) {
				pollitem.events = ZMQ_POLLIN|ZMQ_POLLOUT;
			} else {
				pollitem.events = ZMQ_POLLIN;
			}
		}
		pollitems.erase(std::remove_if(pollitems.begin(), pollitems.end(), [] (zmq::pollitem_t pollitem) {
			std::cout << "Considering " << pollitem.fd << std::endl;
			return pollitem.fd < 0;
		}), pollitems.end());
	}
	return 0;
}
