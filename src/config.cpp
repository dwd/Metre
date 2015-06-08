#include "config.h"

#include <fstream>
#include <rapidxml.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

using namespace Metre;
using namespace rapidxml;

namespace {
  std::string const any_element = "any";
  std::string const xmlns = "http://surevine.com/xmlns/metre/config";
  std::string const root_name = "config";

  bool xmlbool(const char * val) {
    if (!val) return false;
    switch (val[0]) {
    case 't':
    case 'T':
    case 'y':
    case 'Y':
    case '1':
      return true;
    }
    return false;
  }

  std::unique_ptr<Config::Domain> parse_domain(xml_node<> * domain, SESSION_TYPE def) {
    std::string name;
    bool forward = (def == INT || def == COMP);
    SESSION_TYPE sess = def;
    bool tls_required = true;
    bool block = false;
    if (any_element == domain->name()) {
      name = "";
    } else {
      auto name_a = domain->first_attribute("name");
      if (!name_a) {
        throw std::runtime_error("Missing name for domain element");
      }
      name = name_a->value();
    }
    auto forward_a = domain->first_attribute("forward");
    if (forward_a) {
      forward = xmlbool(forward_a->value());
    }
    auto block_a = domain->first_attribute("block");
    if (block_a) {
      block = xmlbool(block_a->value());
    }
    auto transport = domain->first_node("transport");
    if (transport) {
      auto type_a = transport->first_attribute("type");
      if (type_a) {
        std::string type = type_a->value();
        if (type == "s2s") {
          sess = S2S;
        } else if (type == "114") {
          sess = COMP;
        }
      }
      auto tls_a = transport->first_attribute("sec");
      if (tls_a) {
        tls_required = xmlbool(tls_a->value());
      }
    }
    std::unique_ptr<Config::Domain> dom(new Config::Domain(name, sess, forward, tls_required, block));
    auto x509t = domain->first_node("x509");
    if (x509t) {
      auto chain_a = x509t->first_attribute("chain");
      if (chain_a) {
        std::string chain = chain_a->value();
        auto pkey_a = x509t->first_attribute("pkey");
        if (pkey_a) {
          std::string pkey = pkey_a->value();
          dom->x509(chain, pkey);
        }
      }
    }
    return dom;
  }

  Config * s_config = nullptr;

  bool openssl_init = false;
}

Config::Domain::Domain(std::string const & domain, SESSION_TYPE transport_type, bool forward, bool require_tls, bool block)
  : m_domain(domain), m_type(transport_type), m_forward(forward), m_require_tls(require_tls), m_block(block), m_auth(), m_ssl_ctx(nullptr) {
}

Config::Domain::~Domain() {
  if (m_ssl_ctx) {
    SSL_CTX_free(m_ssl_ctx);
    m_ssl_ctx = nullptr;
  }
}

int Config::Domain::verify_callback_cb(int preverify_ok, X509_STORE_CTX *store) {
  return 1;
}

void Config::Domain::x509(std::string const & chain, std::string const & pkey) {
  if (!openssl_init) {
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    if (RAND_poll() == 0) {
      throw std::runtime_error("OpenSSL init failed");
    }
    openssl_init = true;
  }
  if (m_ssl_ctx) {
    SSL_CTX_free(m_ssl_ctx);
    m_ssl_ctx = nullptr;
  }
  m_ssl_ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_ALL);
  SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, Config::Domain::verify_callback_cb);
  if (SSL_CTX_use_certificate_chain_file(m_ssl_ctx, chain.c_str()) != 1) {
    throw std::runtime_error("Couldn't load chain file");
  }
  if (SSL_CTX_use_PrivateKey_file(m_ssl_ctx, pkey.c_str(), SSL_FILETYPE_PEM) != 1) {
    throw std::runtime_error("Couldn't load keyfile");
  }
  if (SSL_CTX_check_private_key(m_ssl_ctx)) {
    throw std::runtime_error("Private key mismatch");
  }
  SSL_CTX_set_purpose(m_ssl_ctx, X509_PURPOSE_SSL_SERVER);
}

Config::Config(std::string const & filename) : m_config_str() {
  load(filename);
  s_config = this;
}

void Config::load(std::string const & filename) {
  std::ifstream file(filename);
  std::string str{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
  m_config_str = std::move(str);
  rapidxml::xml_document<> doc;
  doc.parse<parse_full>(const_cast<char *>(m_config_str.c_str()));
  auto root_node = doc.first_node();
  if (xmlns != root_node->xmlns()) {
    throw std::runtime_error("Wrong namespace for config");
  }
  if (root_name != root_node->name()) {
    throw std::runtime_error("Wrong name for config");
  }
  auto globals = root_node->first_node("globals");
  if (globals) {
    auto default_domain = globals->first_node("domain");
    if (default_domain) {
      auto name_a = default_domain->first_attribute("name");
      if (name_a) {
        m_default_domain = name_a->value();
      }
    }
  }
  auto internal = root_node->first_node("local");
  if (internal) {
    for (auto domain = internal->first_node("domain"); domain; domain = domain->next_sibling("domain")) {
      std::unique_ptr<Config::Domain> dom = std::move(parse_domain(domain, INT));
      m_domains[dom->domain()] = std::move(dom);
    }
  }
  auto external = root_node->first_node("remote");
  if (external) {
    for (auto domain = external->first_node(); domain; domain = domain->next_sibling()) {
      if (domain->type() == rapidxml::node_comment) continue;
      std::unique_ptr<Config::Domain> dom = std::move(parse_domain(domain, INT));
      m_domains[dom->domain()] = std::move(dom);
    }
  }
  auto it = m_domains.find("");
  if (it == m_domains.end()) {
    m_domains[""] = std::unique_ptr<Config::Domain>(new Config::Domain("", INT, false, true, true));
  }
}

Config::Domain const & Config::domain(std::string const & dom) const {
  auto it = m_domains.find(dom);
  if (it == m_domains.end()) {
    it = m_domains.find("");
  }
  return *(*it).second;
}

Config const & Config::config() {
  return *s_config;
}
