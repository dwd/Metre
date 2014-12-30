#ifndef XMLSTREAM__H
#define XMLSTREAM__H

#include "defs.hpp"
#include <map>
#include <optional>
#include <memory>
#include "sigslot/sigslot.h"

namespace Metre {
	class NetSession;
	class Server;
	class Feature;
	class Verify;
	class Stanza;

	class XMLStream {
		rapidxml::xml_document<> m_stream;
		rapidxml::xml_document<> m_stanza; // Not, in fact, always a stanza per-se. //
		SESSION_TYPE m_type;
		SESSION_DIRECTION m_dir;
		bool m_opened;
		bool m_closed;
		bool m_seen_open;
		std::string m_stream_buf; // Sort-of-temporary buffer //
		Server * m_server;
		NetSession * m_session;
		std::map<std::string,Feature *> m_features;
		std::optional<std::string> m_user;
		std::string m_stream_id;
		std::string m_stream_from;
		std::string m_stream_to;
		bool m_secured; // Channel has been secured, usually by TLS //
		bool m_compressed; // Channel has compression enabled, by TLS or XEP-0138 //
		bool m_authenticated; // Channel has been authenticated, by SASL or Dialback. //
	public:
		XMLStream(NetSession * owner, Server * server, SESSION_DIRECTION dir, SESSION_TYPE type);
		XMLStream(NetSession * owner, Server * server, SESSION_DIRECTION dir, SESSION_TYPE type, std::string const & stream_from, std::string const & stream_to);
		size_t process(unsigned char *, size_t);
		const char * content_namespace() const;
		SESSION_TYPE type() const {
			return m_type;
		}
		SESSION_DIRECTION direction() const {
			return m_dir;
		}
		bool closed() const {
			return m_closed;
		}
		std::optional<std::string> const & user() const {
			return m_user;
		}
		void user(std::string const & u) {
			m_user = u;
		}
		void send(rapidxml::xml_document<> & d);
		void send(std::unique_ptr<Verify> v);
		void send(std::unique_ptr<Stanza> v);
		void restart();
		void secured() {m_secured = true;}
		void compressed() {m_compressed = true;}
		void authenticated() {m_authenticated = true;}

		std::string const & to() const {
			return m_stream_to;
		}

		NetSession & session() {
			return *m_session;
		}
		std::string const & stream_id() {
			return m_stream_id;
		}
		~XMLStream();

		void generate_stream_id();
		void connected(NetSession &);

		// Signals:
		sigslot::signal<sigslot::thread::mt, XMLStream &> onSecured;
		sigslot::signal<sigslot::thread::mt, XMLStream &> onAuthenticated;

	private:
		void handle(rapidxml::xml_node<> *);
		void stream_open();
		void send_stream_open(bool, bool);
	};
}

#endif
