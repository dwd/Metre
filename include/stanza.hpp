#ifndef STANZA__H
#define STANZA__H

#include "jid.hpp"
#include "rapidxml.hpp"

namespace Metre {
	class Stanza {
		std::optional<Jid> m_from;
		std::optional<Jid> m_to;
		std::string m_type_str;
		std::string m_lang;
		char * m_payload;
		size_t m_payload_l;
	public:
		Stanza(rapidxml::xml_node<> const & node) {
		}
	};


	class Message : public Stanza {
	public:
		Message(rapidxml::xml_node<> const & node) : Stanza(node) {
		}
	};


	class Iq : public Stanza {
	public:
		Iq(rapidxml::xml_node<> const & node) : Stanza(node) {
		}
	};


	class Presence : public Stanza {
	public:
		Presence(rapidxml::xml_node<> const & node) : Stanza(node) {
		}
	};
}

#endif
