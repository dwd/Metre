#ifndef SERVER__HPP
#define SERVER__HPP

#include "jid.h"
#include "stanza.h"
#include <map>

namespace Metre {
	class Endpoint {
	public:
		Jid m_jid;
		Endpoint(Jid const & jid) : m_jid(jid) {}
		virtual void push(Message &);
		virtual void push(Iq &);
		virtual void push(Presence &);
	};


	class Account : public Endpoint {
	public:
		Account(Jid const & jid) : Endpoint(m_jid) {}
		bool test_password(std::string const & password) {
			return password == "yes"; // TODO : Maybe make this more secure? //
		}
	};


	class Domain {
		std::string m_domain;
		std::map<std::string, Account *> m_accounts;
	public:
		Domain(std::string const & domain) : m_domain(domain) {}
		Account & account(Jid const & jid) {
			auto acciter = m_accounts.find(jid.bare());
			if (acciter != m_accounts.end()) {
				return *acciter->second;
			}
			if (jid.bare() != "dave@cridland.im") {
				throw std::runtime_error("No such account");
			}
			auto acc = m_accounts[jid.bare()] = new Account(jid);
			return *acc;
		}
		std::string domain() const {
			return m_domain;
		}
	};


	class Server {
		std::map<std::string, Domain *> m_domains;
	public:
		Server() {}
		Domain & domain(std::string const & domain) {
			auto domiter = m_domains.find(domain);
			if (domiter != m_domains.end()) {
				return *domiter->second;
			}
			if (domain != "cridland.im" &&
					domain != "channels.cridland.im" &&
					domain != "topics.cridland.im") {
				throw std::runtime_error("No such domain");
			}
			auto dom = m_domains[domain] = new Domain(domain);
			return *dom;
		}
	};
}

#endif
