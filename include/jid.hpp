#ifndef JID__H
#define JID__H

#include <string>
#include <optional>

namespace elq {
	class Jid {
		std::optional<std::string> m_local;
		std::string m_domain;
		std::optional<std::string> m_resource;
		
		mutable std::optional<std::string> m_full;
		mutable std::optional<std::string> m_bare;
	public:
		Jid(std::string const & jid) {
			// TODO : Parse out //
		}
		Jid(std::string const & local, std::string const & domain)
			: m_local(local), m_domain(domain) {
		}
		Jid(std::string const & local, std::string const & domain, std::string const & resource)
			: m_local(local), m_domain(domain), m_resource(resource) {
		}
		std::string const & full() const;
		std::string const & bare() const;
	};

}

#endif
