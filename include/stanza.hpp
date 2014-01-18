#ifndef STANZA__H
#define STANZA__H

#include "jid.hpp"
#include "rapidxml.hpp"

namespace Metre {
	class XMLStream;
	class Stanza {
		std::optional<Jid> m_from;
		std::optional<Jid> m_to;
		std::string m_type_str;
		std::string m_id;
		std::string m_lang;
		char * m_payload;
		size_t m_payload_l;
		XMLStream & m_stream;
	public:
		Stanza(rapidxml::xml_node<> const * node, XMLStream & s) : m_stream(s)  {
			auto to = node->first_attribute("to");
		}
		
		XMLStream & originator() const {
			m_stream;
		}
		
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
}

#endif
