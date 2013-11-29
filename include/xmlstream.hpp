#ifndef XMLSTREAM__H
#define XMLSTREAM__H

#include "defs.hpp"
#include <map>
#include <optional>

namespace Metre {
	class NetSession;
	class Server;
	class Feature;

	class XMLStream {
		rapidxml::xml_document<> m_stream;
		rapidxml::xml_document<> m_stanza; // Not, in fact, always a stanza per-se. //
		SESSION_TYPE m_type;
		bool m_opened;
		bool m_closed;
		std::string m_stream_buf; // Sort-of-temporary buffer //
		Server * m_server;
		NetSession * m_session;
		std::map<std::string,Feature *> m_features;
		std::optional<std::string> m_user;
	public:
		XMLStream(NetSession * owner, Server * server, SESSION_TYPE type);
		void process(std::string & buf);
		const char * content_namespace() const;
		SESSION_TYPE type() const {
			return m_type;
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
		void restart();
		~XMLStream();
	private:
		void handle(rapidxml::xml_node<> *);
		void stream_open();
	};
}

#endif
