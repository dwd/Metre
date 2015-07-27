#ifndef STANZA__H
#define STANZA__H

#include "jid.h"
#include "xmppexcept.h"
#include "rapidxml.hpp"

#include <memory>

namespace Metre {
	class XMLStream;
	class Stanza {
	public:
		typedef enum {
			bad_request,
			conflict,
			feature_not_implemented,
			forbidden,
			gone,
			internal_server_error,
			item_not_found,
			jid_malformed,
			not_acceptable,
			not_allowed,
			not_authorized,
			policy_violation,
			recipient_unavailable,
			redirect,
			registration_required,
			remote_server_not_found,
			remote_server_timeout,
			resource_constraint,
			service_unavailable,
			subscription_required,
			undefined_condition,
			unexpected_request
		} Error;
	protected:
		const char * m_name;
		std::optional<Jid> m_from;
		std::optional<Jid> m_to;
		std::string m_type_str;
		std::string m_id;
		std::string m_lang;
		std::string m_payload_str;
		const char * m_payload;
		size_t m_payload_l;
		std::string const m_stream_id;
		rapidxml::xml_node<> const * m_node;
	public:
		Stanza(const char * name, rapidxml::xml_node<> const * node, XMLStream & s);
		Stanza(const char * name, XMLStream & s);
		Stanza(const char * name, Jid const & from, Jid const & to, std::string const & type, std::string const & id, XMLStream & s);

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

		rapidxml::xml_node<> const * node() const {
			return m_node;
		}

		void render(rapidxml::xml_document<> & d);

		std::unique_ptr<Stanza> create_bounce(Metre::base::stanza_exception const & e, XMLStream & s);
		std::unique_ptr<Stanza> create_forward(XMLStream & s);
	};


	class Message : public Stanza {
	public:
		typedef enum { UNCHECKED, NORMAL, CHAT, HEADLINE, GROUPCHAT, ERROR } Type;
		static const char * name;
	private:
		mutable Type m_type;
	public:
		Message(rapidxml::xml_node<> const * node, XMLStream & s) : Stanza(name, node, s), m_type(UNCHECKED) {
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
		static const char * name;
	private:
		mutable Type m_type;
	public:
		Iq(rapidxml::xml_node<> const * node, XMLStream & s) : Stanza(name, node, s) {}
		Iq(Jid const & from, Jid const & to, Type t, std::string const & id, XMLStream & s);
		static const char * type_toString(Type t) {
			switch(t) {
			case GET: return "get";
			case SET: return "set";
			case RESULT: return "result";
			case ERROR: return "error";
			default: return "error";
			}
		}
	};


	class Presence : public Stanza {
	public:
		static const char * name;
		Presence(rapidxml::xml_node<> const * node, XMLStream & s) : Stanza(name, node, s) {
		}
	};

	/*
		* Slightly hacky; used for building outbound Verify elements.
		*/
	class Verify : public Stanza {
		std::string m_key;
	public:
		static const char * name;
		Verify(Jid const & to, Jid const & from, std::string const & stream_id, std::string const & key, XMLStream & s) : Stanza(name, s), m_key(key) {
			m_to = to;
			m_from = from;
			m_id = stream_id;
			m_payload = m_key.data();
			m_payload_l = m_key.length();
		}
	};
}

#endif
