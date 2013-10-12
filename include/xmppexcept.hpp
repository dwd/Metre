#ifndef ELOQUENCE_EXCEPT_HH
#define ELOQUENCE_EXCEPT_HH

#include <exception>

namespace elq {
	namespace base {
		class xmpp_exception : public std::runtime_error {
		private:
			const char * m_elname; // Always used with string constant
		public:
			xmpp_exception(std::string const & w, const char * elname) : std::runtime_error(w), m_elname(elname) {}
			xmpp_exception(const char * w, const char * elname) : std::runtime_error(w), m_elname(elname) {}
			
			const char * element_name() const {
				return m_elname;
			}
		};
	}
	
	// Following macro generates exception classes.
#   define ELQ_XMPP_EXCEPT(clsname, def_text, elname) \
	class clsname : public base::xmpp_exception {  \
	public:  \
		clsname() : base::xmpp_exception(def_text, elname) {}  \
		clsname(std::string const & w) : base::xmpp_exception(w, elname) {}  \
		clsname(const char * w) : base::xmpp_exception(w, elname) {}  \
	}

	ELQ_XMPP_EXCEPT(bad_format, "Sorry, I cannot process that XML", "bad-format");
	ELQ_XMPP_EXCEPT(bad_namespace_prefix, "Required prefix missing", "bad-namespace-prefix");
	ELQ_XMPP_EXCEPT(host_unknown, "FQDN not serviced by this entity", "host-unknown");
	ELQ_XMPP_EXCEPT(undefined_condition, "Very sorry - unhandled internal error", "undefined-condition");
}

#endif
