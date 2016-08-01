#ifndef NETSESSION__HPP
#define NETSESSION__HPP

#include <string>
#include "defs.h"
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
		std::string const m_domain;
		short m_port;
		std::string m_hostname;
		bool m_secure;
		unsigned long long m_serial;
		struct bufferevent * m_bev;
		XMLStream * m_xml_stream;
	public:
		NetSession(unsigned long long serial, struct bufferevent * bev, SESSION_TYPE type); /* Inbound */
		NetSession(unsigned long long serial, struct bufferevent * bev, std::string const & stream_from, std::string const & stream_to); /* Outbound S2S */

		// Scary stuff only used for buffer juggling.
		struct bufferevent * bufferevent() {
			return m_bev;
		}
		void bufferevent(struct bufferevent * bev);
		// Stuff for XMLStream to indicate it's used octets.
		void used(size_t n);

		// Signals:
		mutable sigslot::signal<sigslot::thread::st, NetSession &> onClosed;
		mutable sigslot::signal<sigslot::thread::st, NetSession &> onConnected;

		bool drain();
		bool need_push();
		bool push();
		void send(rapidxml::xml_document<> & d);
		void send(std::string const & s);
		void send(const char * p);

		void close();

		unsigned long long serial() const {
			return m_serial;
		}

		static void read_cb(struct bufferevent * bev, void * arg);
		static void event_cb(struct bufferevent * bev, short flags, void * arg);

		XMLStream & xml_stream() {
			return *m_xml_stream;
		}

		~NetSession();
	private:
		void bev_closed();
		void bev_connected();
	};
}

#endif
