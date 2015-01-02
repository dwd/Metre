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
	public:
		typedef enum { NONE, REQUESTED, AUTHORIZED } AUTH_STATE;

	private:
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
		std::string m_stream_local;
		std::string m_stream_remote;
		bool m_authready; // Channel is ready for dialback/SASL //
		bool m_compressed; // Channel has compression enabled, by TLS or XEP-0138 //
		bool m_secured; // Crypto in place via TLS. //
		std::map<std::pair<std::string,std::string>,AUTH_STATE> m_auth_pairs_rx;
		std::map<std::pair<std::string,std::string>,AUTH_STATE> m_auth_pairs_tx;
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
		//void send(std::unique_ptr<Verify> v);
		void send(std::unique_ptr<Stanza> v);
		void restart();
		void set_auth_ready() {m_authready = true; onAuthReady.emit(*this); }
		void set_compressed() {m_compressed = true;}
		void set_secured() {m_secured = true;}
		bool auth_ready() { return m_authready; }

		AUTH_STATE s2s_auth_pair(std::string const & local, std::string const & remote, SESSION_DIRECTION) const;
		AUTH_STATE s2s_auth_pair(std::string const & local, std::string const & remote, SESSION_DIRECTION, AUTH_STATE auth);

		std::string const & stream_local() const {
			return m_stream_local;
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
		sigslot::signal<sigslot::thread::mt, XMLStream &> onAuthReady;
		sigslot::signal<sigslot::thread::mt, XMLStream &> onAuthenticated;

	private:
		void handle(rapidxml::xml_node<> *);
		void stream_open();
		void send_stream_open(bool, bool);
	};
}

#endif
