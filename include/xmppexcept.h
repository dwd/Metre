/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/

#ifndef METRE_EXCEPT_HH
#define METRE_EXCEPT_HH

#include <exception>

namespace Metre {
    namespace base {
        class xmpp_exception : public std::runtime_error {
        private:
            const char *m_elname; // Always used with string constant
        public:
            xmpp_exception(std::string const &w, const char *elname) : std::runtime_error(w), m_elname(elname) {}

            xmpp_exception(const char *w, const char *elname) : std::runtime_error(w), m_elname(elname) {}

            const char *element_name() const {
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

    METRE_XMPP_EXCEPT(not_well_formed, "XML parse error", "not-well-formed");

    METRE_XMPP_EXCEPT(undefined_condition, "Very sorry - unhandled internal error", "undefined-condition");

    namespace base {
        class stanza_exception : public std::runtime_error {
        private:
            const char *m_elname;
            const char *m_error_type;
        public:
            stanza_exception(std::string const &w, const char *elname, const char *error_type) : std::runtime_error(w),
                                                                                                 m_elname(elname),
                                                                                                 m_error_type(
                                                                                                         error_type) {}

            stanza_exception(const char *w, const char *elname, const char *error_type) : std::runtime_error(w),
                                                                                          m_elname(elname),
                                                                                          m_error_type(error_type) {}

            const char *element_name() const {
                return m_elname;
            }

            const char *error_type() const {
                return m_error_type;
            }
        };
    }

    // Another Macro for Stanza errors.
#		define METRE_STANZA_EXCEPT(errname, def_text, def_type, elname) \
    class stanza_##errname : public base::stanza_exception { \
    public: \
        stanza_##errname() : base::stanza_exception(def_text, elname, def_type) {} \
        stanza_##errname(std::string const & w) : base::stanza_exception(w, elname, def_type) {} \
        stanza_##errname(std::string const & w, const char * err_type) : base::stanza_exception(w, elname, err_type) {} \
        stanza_##errname(const char * w) : base::stanza_exception(w, elname, def_type) {} \
        stanza_##errname(const char * w, const char * err_type) : base::stanza_exception(w, elname, err_type) {} \
    }

    METRE_STANZA_EXCEPT(service_unavailable, "This service is not available at this jid", "cancel",
                        "service-unavailable");

    METRE_STANZA_EXCEPT(undefined_condition, "An internal server error occured processing this stanza", "cancel",
                        "undefined-condition");

    METRE_STANZA_EXCEPT(remote_server_timeout, "The remote server could not be reached within the required time",
                        "cancel", "remote-server-timeout");

    METRE_STANZA_EXCEPT(remote_server_not_found, "The remote server discovery or connection failed", "cancel",
                        "remote-server-not-found");

    METRE_STANZA_EXCEPT(bad_format, "Request rejected due to missing parameter etc", "modify", "bad-format");

    METRE_STANZA_EXCEPT(policy_violation, "Request rejected due to policy violation", "cancel", "policy-violation");
}

#endif
