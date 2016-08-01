#ifndef METRE_CONFIG__HPP
#define METRE_CONFIG__HPP

#include <string>
#include <map>
#include <optional>
#include <memory>
#include <list>

#include "defs.h"
#include "dns.h"
#include "log.h"

/**
 * OpenSSL forward declarations.
*/

struct ssl_ctx_st; // SSL_CTX
struct x509_store_ctx_st; // X509_STORE_CTX;

/**
 * Lib unbound.
 */

struct ub_ctx;
struct ub_result;

namespace Metre {
  class Config {
  public:
      /* DNS */
      typedef sigslot::signal<sigslot::thread::st, DNS::Srv const*> srv_callback_t;
      typedef sigslot::signal<sigslot::thread::st, DNS::Address const*> addr_callback_t;
      typedef sigslot::signal<sigslot::thread::st, DNS::Tlsa const*> tlsa_callback_t;

      class Domain {
    public:
      std::string const & domain() const {
        return m_domain;
      }
      SESSION_TYPE transport_type() const {
        return m_type;
      }
      bool forward() const {
        return m_forward;
      }
      bool require_tls() const {
        return m_require_tls;
      }
      bool block() const {
        return m_block;
      }
      bool auth_pkix() const {
        return m_auth_pkix;
      }
      bool auth_dialback() const {
        return m_auth_dialback;
      }
      bool dnssec_required() const {
          return m_dnssec_required;
      }
      bool dnssec_required(bool d) {
          m_dnssec_required = d;
          return d;
      }
      std::string const & dhparam() const {
        return m_dhparam;
      }
      std::string const & dhparam(std::string const & d) {
        return m_dhparam = d;
      }
      std::string const & cipherlist() const {
        return m_cipherlist;
      }
      std::string const & cipherlist(std::string const & c) {
        return m_cipherlist = c;
      }
      std::optional<std::string> const & auth_secret() const {
        return m_auth_secret;
      }
      struct ssl_ctx_st * ssl_ctx() const {
        return m_ssl_ctx;
      }

      /* Loading functions */
      void x509(std::string const & chain, std::string const & key);
      void host(std::string const & hostname, uint32_t inaddr);
      void srv(std::string const &, unsigned short, unsigned short, unsigned short);
      void tlsa(std::string const & hostname, unsigned short port, DNS::TlsaRR::CertUsage certUsage, DNS::TlsaRR::Selector selector, DNS::TlsaRR::MatchType matchType, std::string const & value);
      std::vector<DNS::Tlsa> const & tlsa() const;

        /* DNS */
        srv_callback_t & SrvLookup(std::string const & domain) const;
        addr_callback_t & AddressLookup(std::string const & hostname) const;
        tlsa_callback_t & TlsaLookup(short unsigned int port, std::string const & hostname) const;

          /* DNS callbacks */
          void a_lookup_done(int err, struct ub_result * result);
          void srv_lookup_done(int err, struct ub_result * result);
          void tlsa_lookup_done(int err, struct ub_result * result);

        Domain(std::string const & domain, SESSION_TYPE transport_type, bool forward, bool require_tls, bool block, bool auth_pkix, bool auth_dialback, std::optional<std::string> && m_auth_secret);
      Domain(Domain const &) = delete;
      Domain(Domain &&) = delete;
      ~Domain();
    private:
      static int verify_callback_cb(int preverify_ok, struct x509_store_ctx_st *);
      std::string m_domain;
      SESSION_TYPE m_type;
      bool m_forward;
      bool m_require_tls;
      bool m_block;
      bool m_auth_pkix;
      bool m_auth_dialback;
      bool m_dnssec_required = false;
      std::string m_dhparam;
      std::string m_cipherlist;
      std::optional<std::string> m_auth_secret;
      struct ssl_ctx_st * m_ssl_ctx = nullptr;
      std::map<std::string, std::unique_ptr<DNS::Address>> m_host_arecs;
      std::map<std::string, std::unique_ptr<DNS::Srv>> m_srvrecs;
      std::map<std::string, std::unique_ptr<DNS::Tlsa>> m_tlsarecs;
      mutable std::vector<DNS::Tlsa> m_tlsa_all;
          mutable srv_callback_t m_srv_pending;
          mutable addr_callback_t m_a_pending;
          mutable tlsa_callback_t m_tlsa_pending;
    };
    Config(std::string const & filename);
    ~Config();

    std::string asString();

    std::string const & default_domain() const {
      return m_default_domain;
    }
    std::string const & runtime_dir() const {
      return m_runtime_dir;
    }
    std::string const & pidfile() const {
        return m_pidfile;
    }
    std::string boot_method() const {
        return m_boot;
    }
    void log_init(bool systemd=false);
    Domain const & domain(std::string const & domain) const;
    Domain const & domain(int domain) const;

    void load(std::string const & filename);

    static Config const & config();
    std::string random_identifier() const;
    std::string const & dialback_secret() const {
      return m_dialback_secret;
    }
    std::string dialback_key(std::string const & id, std::string const & local_domain, std::string const & remote_domain) const;
      struct ub_ctx * ub_ctx() const {
          return m_ub_ctx;
      }

  private:
    std::string m_config_str;
    std::string m_default_domain;
    std::string m_runtime_dir;
    std::string m_pidfile;
    std::string m_dialback_secret;
    std::string m_logfile;
    std::string m_boot;
    std::map<std::string, std::unique_ptr<Domain>> m_domains;
    struct ub_ctx * m_ub_ctx = nullptr;
    std::unique_ptr<Metre::Log> m_log;
  };
}

#endif
