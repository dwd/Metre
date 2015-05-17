#ifndef METRE_CONFIG__HPP
#define METRE_CONFIG__HPP

#include <string>
#include <map>
#include <optional>
#include <memory>
#include <list>

#include "defs.hpp"

/**
 * OpenSSL forward declarations.
*/

struct ssl_ctx_st; // SSL_CTX
struct x509_store_ctx_st; // X509_STORE_CTX;

namespace Metre {
  class Config {
  public:
    class Auth {
    public:
      typedef enum {
        DANE,
        PKIX,
        SECRET,
        DIALBACK,
        TORU
      } AUTH_TYPE;
      AUTH_TYPE type();
      std::optional<std::string> const & secret() const;

      Auth(AUTH_TYPE type);
      Auth(AUTH_TYPE type, std::string const & secret);
      Auth(Auth &&);
    private:
      AUTH_TYPE m_type;
      std::optional<std::string> m_secret;
    };
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
      struct ssl_ctx_st * ssl_ctx() const {
        return m_ssl_ctx;
      }
      std::list<std::unique_ptr<Auth>> const & auth() const {
        return m_auth;
      }

      /* Loading functions */
      void x509(std::string const & chain, std::string const &);
      void auth(Auth &&);

      Domain(std::string const & domain, SESSION_TYPE transport_type, bool forward, bool require_tls, bool block);
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
      std::list<std::unique_ptr<Auth>> m_auth;
      struct ssl_ctx_st * m_ssl_ctx;
    };
    Config(std::string const & filename);

    std::string asString();

    std::string const & default_domain() const {
      return m_default_domain;
    }
    std::string const & runtime_dir() const;
    Domain const & domain(std::string const & domain) const;

    void load(std::string const & filename);

    static Config const & config();

  private:
    std::string m_config_str;
    std::string m_default_domain;
    std::string m_runtime_dir;
    std::map<std::string, std::unique_ptr<Domain>> m_domains;
  };
}

#endif
