#include "jid.hpp"

using namespace Metre;

std::string const & Jid::full() const {
	if (!m_full) {
		m_full.emplace();
		if (m_local) {
			*m_full += *m_local;
			*m_full += "@";
		}
		*m_full += m_domain;
		if (m_resource) {
			*m_full += "/";
			*m_full += *m_resource;
		}
	}
	return *m_full;
}

std::string const & Jid::bare() const {
	if (!m_bare) {
		m_bare.emplace();
		if (m_local) {
			*m_bare += *m_local;
			*m_bare += "@";
		}
		m_bare.value() += m_domain;
	}
	return *m_bare;
}
