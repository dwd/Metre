#ifndef ELOQUENCE_EXCEPT_HH
#define ELOQUENCE_EXCEPT_HH

#include <exception>

namespace Metre {
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
#   define METRE_XMPP_EXCEPT(clsname, def_text, elname) \
	class clsname : public base::xmpp_exception {  \
	public:  \
		clsname() : base::xmpp_exception(def_text, elname) {}  \
		clsname(std::string const & w) : base::xmpp_exception(w, elname) {}  \
		clsname(const char * w) : base::xmpp_exception(w, elname) {}  \
	}

	METRE_XMPP_EXCEPT(bad_format, "Sorry, I cannot process that XML", "bad-format");
	METRE_XMPP_EXCEPT(bad_namespace_prefix, "Required prefix missing", "bad-namespace-prefix");
	METRE_XMPP_EXCEPT(host_unknown, "FQDN not serviced by this entity", "host-unknown");
	METRE_XMPP_EXCEPT(not_authorized, "Not authorized to perform that action", "not-authorized");
	METRE_XMPP_EXCEPT(unsupported_stanza_type, "Couldn't understand that element", "unsupported-stanza-type");
	METRE_XMPP_EXCEPT(undefined_condition, "Very sorry - unhandled internal error", "undefined-condition");
}

#endif
