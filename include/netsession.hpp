#ifndef NETSESSION__HPP
#define NETSESSION__HPP

#include <string>
#include "defs.hpp"
#include "rapidxml.hpp"
#include "sigslot/sigslot.h"

// fwd:
struct bufferevent;

namespace Metre {
	class XMLStream;
	class Server;

	class NetSession {
		std::string m_buf;
		static const size_t buflen = 4096;
		std::string m_outbuf;
		XMLStream * m_xml_stream;
		Server * m_server;
		std::string const m_domain;
		short m_port;
		std::string m_hostname;
		bool m_secure;
		struct bufferevent * m_bev;
		unsigned long long m_serial;
	public:
		NetSession(unsigned long long serial, struct bufferevent * bev, SESSION_TYPE type, Server * server); /* Inbound */
		NetSession(unsigned long long serial, std::string const & domain, Server * server); /* Outbound S2S */

		// Signals:
		mutable sigslot::signal<sigslot::thread::mt, NetSession &> closed;

		bool drain();
		bool need_push();
		bool push();
		void send(rapidxml::xml_document<> & d);
		void send(std::string const & s);
		void send(const char * p);

		unsigned long long serial() const {
			return m_serial;
		}

		static void read_cb(struct bufferevent * bev, void * arg);
		static void error_cb(struct bufferevent * bev, short flags, void * arg);

		XMLStream & xml_stream() {
			return *m_xml_stream;
		}

		~NetSession();
	};
}

#endif
