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
		std::string const m_domain;
		short m_port;
		std::string m_hostname;
		bool m_secure;
	public:
		NetSession(int fd, SESSION_TYPE type, Server * server); /* Inbound */
		NetSession(std::string const & domain, Server * server); /* Outbound S2S */
		bool drain();
		bool need_push();
		bool push();
		int fd() { return m_fd; }
		void fd(int f) { m_fd = f; }
		void send(rapidxml::xml_document<> & d);
		void send(std::string const & s);
		void send(const char * p);
		
		XMLStream & xml_stream() {
			return *m_xml_stream;
		}
		
		void new_srv(std::string const & domain, short prio, short weight, short port, std::string const & hostname, bool secure);
		void srv_done();
		void new_addr(std::string const & hostname, void * addr);
		
		void * loop_read;
		void * loop_write;
	};
}

#endif
