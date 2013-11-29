#ifndef NETSESSION__HPP
#define NETSESSION__HPP

#include <string>
#include "defs.hpp"
#include "rapidxml.hpp"

namespace Metre {
	class XMLStream;
	class Server;
	
	class NetSession {
		std::string m_buf;
		int m_fd;
		static const size_t buflen = 4096;
		std::string m_outbuf;
		XMLStream * m_xml_stream;
		Server * m_server;
	public:
		NetSession(int fd, SESSION_TYPE type, Server * server);
		bool drain();
		bool need_push();
		bool push();
		void send(rapidxml::xml_document<> & d);
		void send(std::string const & s);
		void send(const char * p);
	};
}

#endif
