#include <zmq.hpp>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include "rapidxml.hpp"

typedef enum {
	C2S,
	S2S,
	COMP
} SESSION_TYPE;

class NetSession {
	std::string m_buf;
	int m_fd;
	static const size_t buflen = 4096;
	std::string m_stream_buf;
	rapidxml::xml_document<> m_stream;
	rapidxml::xml_document<> m_stanza; // Not, in fact, always a stanza per-se.
	SESSION_TYPE m_type;
public:
	NetSession(int fd, SESSION_TYPE type) : m_fd(fd), m_type(type) {}
	void drain() {
		while (true) {
			auto oldsz = m_buf.length();
			m_buf.resize(oldsz + buflen);
			auto count = ::read(m_fd, &m_buf[oldsz], buflen);
			if (count < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					m_buf.resize(oldsz);
					break;
				} else {
					// Some more serious thing.
					::close(m_fd);
					m_fd = -1;
					m_buf.resize(oldsz);
					break;
				}
			} else if (count == 0) {
				::close(m_fd);
				m_fd = -1;
				m_buf.resize(oldsz);
				break;
			} else {
				m_buf.resize(oldsz + count);
			}
		}
		std::cout << "Drained buffer, now: \n" << m_buf << "\n!!!" << std::endl;
		process();
	}
	void process() {
		using namespace rapidxml;
		if (m_buf.empty()) return;
		if (m_stream.first_node() == NULL) {
			/**
			 * We need to grab the stream open. Do so by parsing the main buffer to find where the open
			 * finishes, and copy that segment over to another buffer. Then reparse, this time properly.
			 */
			char * end = m_stream.parse<parse_open_only|parse_fastest>(const_cast<char *>(m_buf.c_str()));
			auto test = m_stream.first_node();
			if (!test || !test->name()) {
				std::cout << "Cannot parse an element, yet." << std::endl;
				return;
			}
			m_stream_buf.assign(m_buf.data(), end - m_buf.data());
			m_buf.erase(0, end - m_buf.data());
			m_stream.parse<parse_open_only>(const_cast<char *>(m_stream_buf.c_str()));
			stream_open();
			auto stream_open = m_stream.first_node();
			std::cout << "Stream open with {" << stream_open->xmlns() << "}" << stream_open->name() << std::endl;
		}
		while(!m_buf.empty()) {
			char * end = m_stanza.parse<parse_fastest|parse_parse_one>(const_cast<char *>(m_buf.c_str()), m_stream);
			auto element = m_stanza.first_node();
			if (!element || !element->name()) return;
			std::cout << "TLE {" << element->xmlns() << "}" << element->name() << std::endl;
			m_buf.erase(0, end - m_buf.data());
		}
	}
	
	void stream_open() {
		/**
		 * We may be able to change our minds on what stream type this is, here,
		 * by looking at the default namespace.
		 */
		auto stream = m_stream.first_node();
		auto xmlns = stream->first_attribute("xmlns");
		if (xmlns && xmlns->value()) {
			std::string default_xmlns(xmlns->value(), xmlns->value_size());
			if (default_xmlns == "jabber:client") {
				m_type = C2S;
			} else if (default_xmlns == "jabber:server") {
				m_type = S2S;
			} else {
				std::cout << "Unidentified connection." << std::endl;
			}
		}
		auto domain = stream->first_attribute("to");
		if (domain && domain->value()) {
			std::string to_domain(domain->value(), domain->value_size());
			std::cout << "Requested contact domain {" << to_domain << "}" << std::endl;
		}
		if (!stream->xmlns()) {
			std::cout << "Ooops! No xmlns for stream?" << std::endl;
		}
		if (stream->name() != std::string("stream") ||
			stream->xmlns() != std::string("http://etherx.jabber.org/streams")) {
			std::cout << "Ooops! Wrong name or invalid namespace." << std::endl;
		}
	}
};

int  main(int argc, char *argv[]) {
	zmq::context_t context(1);
	auto lsock = socket(AF_INET6, SOCK_STREAM, 0);
	sockaddr_in6 sin = { AF_INET6, htons(5222), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
	if (0 < bind(lsock, (sockaddr *)&sin, sizeof(sin))) {
		std::cout << "Cannot bind!" << std::endl;
		return 1;
	}
	int opt = 1;
	setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	listen(lsock, 5);
	
	std::vector<zmq::pollitem_t> pollitems;
	zmq::pollitem_t pollitem;
	pollitem.socket = NULL;
	pollitem.fd = lsock;
	pollitem.events = ZMQ_POLLIN;
	pollitems.push_back(pollitem);
	std::map<int, NetSession *> sockets;
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
			sockets[sock] = new NetSession(sock, C2S);
		}
		for (auto pollitem : pollitems) {
			if (pollitem.fd == lsock) continue;
			std::cout << "Activity on " << pollitem.fd << std::endl;
			sockets[pollitem.fd]->drain();
		}
	}
	return 0;
}
