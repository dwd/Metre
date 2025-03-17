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

#ifndef METRE_CONFIG__HPP
#define METRE_CONFIG__HPP

#include <string>
#include <map>
#include <unordered_set>
#include <optional>
#include <memory>
#include <list>
#include <rapidxml.hpp>

#include "defs.h"
#include <covent/covent.h>
#include <covent/dns.h>
#include <covent/http.h>
#include "spdlog/spdlog.h"
#include "pkix.h"
#include "jwt.h"
#include <sigslot/sigslot.h>

namespace Metre {
    class Config {
    public:
        class Domain {
        public:
            [[nodiscard]] auto & entry() const {
                return m_entry;
            }
            [[nodiscard]] auto & entry() {
                return m_entry;
            }
            [[nodiscard]] bool tls_enabled() const {
                return tls_context().enabled();
            }

            [[nodiscard]] std::string const &domain() const {
                return m_domain;
            }

            [[nodiscard]] SESSION_TYPE transport_type() const {
                return m_type;
            }

            [[nodiscard]] bool forward() const {
                return m_forward;
            }

            [[nodiscard]] bool require_tls() const {
                return m_require_tls;
            }

            [[nodiscard]] bool block() const {
                return m_block;
            }

            [[nodiscard]] auto multiplex() const {
                return m_multiplex;
            }

            [[nodiscard]] bool auth_pkix() const {
                return m_auth_pkix;
            }

            [[nodiscard]] bool auth_dialback() const {
                return m_auth_dialback;
            }

            [[nodiscard]] auto stanza_timeout() const {
                return m_stanza_timeout;
            }

            auto stanza_timeout(long stanza_timeout) {
                return m_stanza_timeout = stanza_timeout;
            }

            [[nodiscard]] auto connect_timeout() const {
                return m_connect_timeout;
            }

            auto connect_timeout(long connect_timeout) {
                return m_connect_timeout = connect_timeout;
            }

            [[nodiscard]] bool xmpp_ver() const {
                return m_xmpp_ver;
            }

            [[nodiscard]] TLS_PREFERENCE tls_preference() const {
                return m_tls_preference;
            }

            TLS_PREFERENCE tls_preference(TLS_PREFERENCE p) {
                m_tls_preference = p;
                return p;
            }

            [[nodiscard]] std::optional<std::string> const &auth_secret() const {
                return m_auth_secret;
            }

            Domain(std::string domain, SESSION_TYPE transport_type, bool xmpp_ver, bool forward, bool require_tls, bool block, bool multiplex,
                   bool auth_pkix, bool auth_dialback, bool auth_host, std::optional<std::string> &&m_auth_secret);

            Domain(Domain const &, std::string domain);

            Domain(Domain const &) = delete;

            Domain(Domain &&) = delete;

            ~Domain();

            covent::task<FILTER_RESULT> filter(FILTER_DIRECTION dir, Stanza &s) const;

            [[nodiscard]] covent::pkix::TLSContext & tls_context() const {
                return m_entry.tls_context();
            }

            [[nodiscard]] covent::pkix::PKIXValidator & pkix_validator() const {
                return m_entry.validator();
            }

            [[nodiscard]] auto & resolver() const {
                return m_entry.resolver();
            }

            std::list<std::unique_ptr<Filter>> &filters() {
                return m_filters;
            }

            [[nodiscard]] std::list<std::unique_ptr<Filter>> const &filters() const {
                if (m_parent) return m_parent->filters();
                return m_filters;
            }

            [[nodiscard]] Filter * filter_by_name(std::string const & name) const;

            [[nodiscard]] bool auth_endpoint(std::string const &ip, unsigned short port) const;

            [[nodiscard]] bool auth_host() const {
                return m_auth_host;
            }

            [[nodiscard]] spdlog::logger &logger() const {
                return m_logger;
            }

            [[nodiscard]] Domain const *parent() const {
                return m_parent;
            }

        private:
            covent::Service::Entry & m_entry;
            std::string m_domain;
            SESSION_TYPE m_type;
            bool m_xmpp_ver;
            bool m_forward = false;
            bool m_require_tls = true;
            bool m_block = false;
            bool m_multiplex = true;
            bool m_auth_pkix = true;
            bool m_auth_dialback = false;
            bool m_auth_host = false;
            bool m_dnssec_required = false;
            TLS_PREFERENCE m_tls_preference = TLS_PREFERENCE::PREFER_ANY;
            long m_stanza_timeout = 20;
            long m_connect_timeout = 10;
            std::optional<std::string> m_auth_secret;
            std::list<std::unique_ptr<Filter>> m_filters;
            std::list<struct sockaddr_storage> m_auth_endpoint;
            Domain const *m_parent = nullptr;
            mutable spdlog::logger m_logger;
        };

        explicit Config(std::string const &filename, bool lite=false);

        ~Config();

        void write_runtime_config() const;

        [[nodiscard]] std::string asString() const;

        [[nodiscard]] auto const &default_domain() const {
            return m_default_domain;
        }

        [[nodiscard]] auto const &runtime_dir() const {
            return m_runtime_dir;
        }

        [[nodiscard]] auto const &pidfile() const {
            return m_pidfile;
        }

        std::string boot_method() const {
            return m_boot;
        }

        void log_init(bool systemd = false);

        void docker_setup();

        void dns_init() const;

        [[nodiscard]] Domain const &domain(std::string const &domain) const;

        void load(std::string const &filename, bool lite);

        static Config const &config();

        [[nodiscard]] std::string random_identifier() const;

        [[nodiscard]] auto const &dialback_secret() const {
            return m_dialback_secret;
        }

        [[nodiscard]] std::string dialback_key(std::string const &id, std::string const &local_domain, std::string const &remote_domain) const;

        [[nodiscard]] bool fetch_pkix_status() const {
            return m_fetch_crls;
        }

        [[nodiscard]] auto const & dns_ta_file() const {
            return m_dns_keys;
        }

        class Listener : public covent::Listener<XMLStream> {
            public:
                SESSION_TYPE session_type;
                TLS_MODE tls_mode;
                std::string const name;
                std::string const local_domain;
                std::string const remote_domain;
                std::set<std::string, std::less<>> allowed_domains;
            public:
                Listener(std::string const &local_domain, std::string const &remote_domain, std::string const &name,
                         std::string const &address, unsigned short port, TLS_MODE tls, SESSION_TYPE sess);
        };

        [[nodiscard]] std::list<Listener> const &listeners() const {
            return m_listeners;
        }

        [[nodiscard]] covent::http::Server http_server();

        [[nodiscard]] spdlog::logger &logger() const {
            return *m_root_logger;
        }

        template<typename ...Args>
        [[nodiscard]] spdlog::logger constexpr logger(fmt::format_string<Args...> fmt_str, Args... args) const {
            std::string logger_name = fmt::vformat(fmt_str, fmt::make_format_args(args...));
            auto const & sinks = m_root_logger->sinks();
            spdlog::logger logger{logger_name, begin(sinks), end(sinks)};
            logger.flush_on(spdlog::level::from_str(m_log_flush));
            logger.set_level(spdlog::level::from_str(m_log_level));
            return logger;
        }

        [[nodiscard]] std::string const &database() const {
            return m_database;
        }

        [[nodiscard]] std::string const &data_dir() const {
            return m_data_dir;
        }

        [[nodiscard]] const char * healthcheck_address() const {
            return m_healthcheck_address.c_str();
        }

        [[nodiscard]] unsigned short int healthcheck_port() const {
            return m_healthcheck_port;
        }

        [[nodiscard]] covent::pkix::TLSContext & healthcheck_tls() const {
            return *m_healthcheck_tls;
        }

        [[nodiscard]] auto const & healthchecks() const {
            return m_healthchecks;
        }

        static bool run_healthcheck(unsigned short port, bool tls);
        auto const & healthcheck_auth() const {
            return m_healthcheck_verifier;
        }

        [[nodiscard]] auto & xmpp_service() const {
            return *m_xmpp_service;
        }

    private:
        void create_domain(std::string const &dom);

        bool m_fetch_crls = true;
        std::string m_default_domain;
        std::string m_runtime_dir;
        std::string m_data_dir;
        std::string m_dns_keys;
        std::string m_pidfile;
        std::string m_dialback_secret;
        std::string m_logfile;
        std::string m_boot;
        std::string m_database;
        std::map<std::string, std::unique_ptr<Domain>, std::less<>> m_domains;
        std::list<Listener> m_listeners;
        std::shared_ptr<spdlog::logger> m_root_logger;
        std::shared_ptr<spdlog::logger> m_logger;
        std::string m_log_level;
        std::string m_log_flush;
        std::string m_healthcheck_address;
        std::unique_ptr<covent::pkix::TLSContext> m_healthcheck_tls;
        unsigned short int m_healthcheck_port;
        std::set<std::pair<std::string, std::string>> m_healthchecks;
        std::unique_ptr<JWTVerifier> m_healthcheck_verifier;
        std::unique_ptr<covent::Service> m_xmpp_service;
    };
}

#endif
