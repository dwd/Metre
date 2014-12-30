#ifndef STANZA__H
#define STANZA__H

#include "jid.hpp"
#include "rapidxml.hpp"

namespace Metre {
	class XMLStream;
	class Stanza {
	protected:
		const char * m_name;
		std::optional<Jid> m_from;
		std::optional<Jid> m_to;
		std::string m_type_str;
		std::string m_id;
		std::string m_lang;
		const char * m_payload;
		size_t m_payload_l;
		std::string const m_stream_id;
	public:
		Stanza(rapidxml::xml_node<> const * node, XMLStream & s);
		Stanza(const char * name, XMLStream & s);

		Jid const & to() const {
			//if (!m_to) return m_stream.to();
			return *m_to;
		}

		Jid const & from() const {
			//if (!m_from) return m_stream.from();
			return *m_from;
		}

		std::string const & type_str() const {
			return m_type_str;
		}

		std::string const & id() const {
			return m_id;
		}

		std::string const & lang() const {
			return m_lang;
		}

		void render(rapidxml::xml_document<> & d);
	};


	class Message : public Stanza {
	public:
		typedef enum { UNCHECKED, NORMAL, CHAT, HEADLINE, GROUPCHAT, ERROR } Type;
	private:
		mutable Type m_type;
	public:
		Message(rapidxml::xml_node<> const * node, XMLStream & s) : Stanza(node, s), m_type(UNCHECKED) {
		}
		Type type() const {
			if (m_type != UNCHECKED) return m_type;
			std::string const & t = type_str();
			if (t.empty()) return m_type = NORMAL;
			switch(t[0]) {
			case 'n':
				if (t == "normal") return m_type = NORMAL;
				break;
			case 'c':
				if (t == "chat") return m_type = CHAT;
				break;
			case 'h':
				if (t == "headline") return m_type = HEADLINE;
				break;
			case 'g':
				if (t == "groupchat") return m_type = GROUPCHAT;
				break;
			case 'e':
				if (t == "error") return m_type = ERROR;
				break;
			}
		}
	};


	class Iq : public Stanza {
	public:
		typedef enum { UNCHECKED, GET, SET, RESULT, ERROR } Type;
	private:
		mutable Type m_type;
	public:
		Iq(rapidxml::xml_node<> const * node, XMLStream & s) : Stanza(node, s) {
		}
	};


	class Presence : public Stanza {
	public:
		Presence(rapidxml::xml_node<> const * node, XMLStream & s) : Stanza(node, s) {
		}
	};

	/*
		* Slightly hacky; used for building outbound Verify elements.
		*/
	class Verify : public Stanza {
		std::string m_key;
	public:
		Verify(Jid const & to, Jid const & from, std::string const & stream_id, std::string const & key, XMLStream & s) : Stanza("db:verify", s), m_key(key) {
			m_to = to;
			m_from = from;
			m_id = stream_id;
			m_payload = m_key.data();
			m_payload_l = m_key.length();
		}
	};
}

#endif
