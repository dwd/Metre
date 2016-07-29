#include "config.h"

#include <fstream>
#include <random>
#include <algorithm>

#include <rapidxml.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dns.h>
#include <dhparams.h>

#include "log.h"

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

  std::unique_ptr<Config::Domain> parse_domain(Config::Domain const * any, xml_node<> * domain, SESSION_TYPE def) {
    std::string name;
    bool forward = (def == INT || def == COMP);
    SESSION_TYPE sess = def;
    bool tls_required = true;
    bool block = false;
    bool auth_pkix = (def == S2S);
    bool auth_dialback = false;
    bool dnssec_required = false;
    std::string dhparam = "4096";
    std::string cipherlist = "HIGH:!3DES:!eNULL:!aNULL:@STRENGTH"; // Apparently 3DES qualifies for HIGH, but is 112 bits, which the IM Observatory marks down for.
    std::optional<std::string> auth_secret;
    if (any) {
      auth_pkix = any->auth_pkix();
      auth_dialback = any->auth_dialback();
      tls_required = any->require_tls();
      dnssec_required = any->dnssec_required();
      dhparam = any->dhparam();
      cipherlist = any->cipherlist();
    }
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
          tls_required = false;
        }
      }
      auto tls_a = transport->first_attribute("sec");
      if (tls_a) {
        tls_required = xmlbool(tls_a->value());
      }

      for (auto auth = transport->first_node("auth"); auth; auth = auth->next_sibling("auth")) {
        auto type_a = auth->first_attribute("type");
        if (type_a) {
          std::string type = type_a->value();
          if (type == "pkix") {
            auth_pkix = true;
          } else if (type == "dialback") {
            auth_dialback = true;
          } else if (type == "secret") {
            auth_secret.emplace(auth->value(), auth->value_size());
          }
        }
      }
    }
    std::unique_ptr<Config::Domain> dom(new Config::Domain(name, sess, forward, tls_required, block, auth_pkix, auth_dialback, std::move(auth_secret)));
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
    auto dhparama = domain->first_node("dhparam");
    if (dhparama) {
      auto sza = dhparama->first_attribute("size");
      if (sza && sza->value()) dhparam = sza->value();
    }
    dom->dhparam(dhparam);
    auto ciphersa = domain->first_node("ciphers");
    if (ciphersa) {
      if (ciphersa->value()) cipherlist = ciphersa->value();
    }
    dom->cipherlist(cipherlist);
    auto dnst = domain->first_node("dns");
    if (dnst) {
      auto dnssec = dnst->first_attribute("dnssec");
      if (dnssec && dnssec->value()) {
        dnssec_required = (dnssec->value()[0] == 't');
      }
      for (auto hostt = dnst->first_node("host"); hostt; hostt = hostt->next_sibling("host")) {
        auto hosta = hostt->first_attribute("name");
        if (!hosta) continue;
        std::string host = hosta->value();
        auto aa = hostt->first_attribute("a");
        if (!aa) continue;
        struct in_addr ina;
        if (inet_aton(aa->value(), &ina)) {
          dom->host(host, ina.s_addr);
        }
      }
    }
    dom->dnssec_required(dnssec_required);
    return dom;
  }

  Config * s_config = nullptr;

  bool openssl_init = false;
}

Config::Domain::Domain(std::string const & domain, SESSION_TYPE transport_type, bool forward, bool require_tls, bool block, bool auth_pkix, bool auth_dialback, std::optional<std::string> && auth_secret)
  : m_domain(domain), m_type(transport_type), m_forward(forward), m_require_tls(require_tls), m_block(block), m_auth_pkix(auth_pkix), m_auth_dialback(auth_dialback), m_auth_secret(auth_secret), m_ssl_ctx(nullptr) {
}

Config::Domain::~Domain() {
  if (m_ssl_ctx) {
    SSL_CTX_free(m_ssl_ctx);
    m_ssl_ctx = nullptr;
  }
}

void Config::Domain::host(std::string const &hostname, uint32_t inaddr) {
  std::unique_ptr<DNS::Address> address(new DNS::Address);
  address->dnssec = true;
  address->hostname = hostname;
  address->addr4.push_back(inaddr);
  m_host_arecs[hostname] = std::move(address);
}

DNS::Address * Config::Domain::host_lookup(std::string const &hostname) const {
  auto i = m_host_arecs.find(hostname);
  if (i == m_host_arecs.end()) return 0;
  return &*((*i).second);
}

int Config::Domain::verify_callback_cb(int preverify_ok, struct x509_store_ctx_st * st) {
  if (!preverify_ok) {
    const int name_sz = 256;
    std::string cert_name;
    cert_name.resize(name_sz);
    X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)), const_cast<char *>(cert_name.data()), name_sz);
    METRE_LOG("Cert failed basic verification: " + cert_name);
    METRE_LOG(std::string("Error is ") + X509_verify_cert_error_string(X509_STORE_CTX_get_error(st)));
  } else {
    const int name_sz = 256;
    std::string cert_name;
    cert_name.resize(name_sz);
    X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)), const_cast<char *>(cert_name.data()), name_sz);
    METRE_LOG("Cert passed basic verification: " + cert_name);
  }
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
  if (SSL_CTX_check_private_key(m_ssl_ctx) != 1) {
    throw std::runtime_error("Private key mismatch");
  }
  SSL_CTX_set_purpose(m_ssl_ctx, X509_PURPOSE_SSL_SERVER);
  SSL_CTX_set_default_verify_paths(m_ssl_ctx);
}

Config::Config(std::string const & filename) : m_config_str(), m_dialback_secret(random_identifier()) {
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
  Config::Domain * any_domain = nullptr;
  auto external = root_node->first_node("remote");
  if (external) {
    auto any = external->first_node("any");
    if (any) {
      std::unique_ptr<Config::Domain> dom = std::move(parse_domain(nullptr, any, S2S));
      any_domain = &*dom; // Save this pointer.
      m_domains[dom->domain()] = std::move(dom);
    }
    for (auto domain = external->first_node("domain"); domain; domain = domain->next_sibling("domain")) {
      std::unique_ptr<Config::Domain> dom = std::move(parse_domain(any_domain, domain, S2S));
      m_domains[dom->domain()] = std::move(dom);
    }
  }
  auto internal = root_node->first_node("local");
  if (internal) {
    for (auto domain = internal->first_node("domain"); domain; domain = domain->next_sibling("domain")) {
      std::unique_ptr<Config::Domain> dom = std::move(parse_domain(any_domain, domain, INT));
      m_domains[dom->domain()] = std::move(dom);
    }
  }
  auto it = m_domains.find("");
  if (it == m_domains.end()) {
    m_domains[""] = std::unique_ptr<Config::Domain>(new Config::Domain("", INT, false, true, true, true, true, std::optional<std::string>()));
  }
}

Config::Domain const & Config::domain(std::string const & dom) const {
  auto it = m_domains.find(dom);
  if (it == m_domains.end()) {
    it = m_domains.find("");
  }
  return *(*it).second;
}

std::string Config::random_identifier() const {
  const size_t id_len = 16;
  char characters[] = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ@";
  std::default_random_engine random(std::random_device{}());
  std::uniform_int_distribution<> dist(0, sizeof(characters) - 2);
  std::string id(id_len, char{});
  std::generate_n(id.begin(), id_len, [&characters,&random,&dist](){return characters[dist(random)];});
  return std::move(id);
}

std::string Config::dialback_key(std::string const & id, std::string const & local_domain, std::string const & remote_domain) const {
  std::string binoutput;
  binoutput.resize(20);
  std::string const & key = dialback_secret();
  std::string concat = id + '|' + local_domain + '|' + remote_domain;
  HMAC(EVP_sha1(), reinterpret_cast<const unsigned char *>(key.data()), key.length(), reinterpret_cast<const unsigned char *>(concat.data()), concat.length(), const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(binoutput.data())), nullptr);
  std::string hexoutput;
  for (unsigned char c : binoutput) {
    int low = c & 0x0F;
    int high = (c & 0xF0) >> 4;
    hexoutput += ((high < 0x0A) ? '0' : ('a' - 10)) + high;
    hexoutput += ((low < 0x0A) ? '0' : ('a' - 10)) + low;
  }
  assert(hexoutput.length() == 40);
  METRE_LOG("Dialback key id " << id << " ::  " << local_domain << " | " << remote_domain);
  return hexoutput;
}

Config const & Config::config() {
  return *s_config;
}
