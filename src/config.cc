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

#include "config.h"

#include "spdlog/sinks/daily_file_sink.h"
#include "spdlog/sinks/stdout_sinks.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <fstream>
#include <memory>
#include <random>
#include <algorithm>

#include <rapidxml.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#ifdef METRE_UNIX
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif
#include <dns.h>
#include <router.h>
#include <unbound.h>
#include <sstream>
#include <base64.h>

#include "log.h"
#include <rapidxml_print.hpp>
#include <http.h>
#include <iomanip>
#if defined(HAVE_ICU) || defined(HAVE_ICU2)
#include <unicode/uidna.h>
#endif
#include <filter.h>
#include <cstring>
#include <unbound-event.h>
#include <yaml-cpp/yaml.h>

using namespace Metre;
using namespace rapidxml;

namespace {
    int yaml_to_tls(YAML::Node const & tls_version_node) {
        auto version_string = tls_version_node.as<std::string>();
        int version = 0;
        std::ranges::transform(version_string, version_string.begin(), [](unsigned char c) {
            return static_cast<unsigned char>(std::tolower(c));
        });
        std::erase(version_string, 'v');
        std::erase(version_string, '.');
        if (version_string == "ssl2") {
            version = SSL2_VERSION;
        } else if (version_string == "ssl3") {
            version = SSL3_VERSION;
        } else if (version_string == "tls1" || version_string == "tls10") {
            version = TLS1_VERSION;
        } else if (version_string == "tls11") {
            version = TLS1_1_VERSION;
        } else if (version_string == "tls12") {
            version = TLS1_2_VERSION;
        } else if (version_string == "tls13") {
            version = TLS1_3_VERSION;
        }
        return version;
    }

    std::unique_ptr<Config::Domain> parse_domain(Config::Domain const *any, std::string const & domain_name, YAML::Node const & domain, bool external) {
        std::string name;
        bool forward = !external;
        SESSION_TYPE sess = S2S;
        bool tls_required = external;
        bool xmpp_ver = true;
        bool block = false;
        bool multiplex = true;
        bool auth_pkix = true;
        bool auth_dialback = !external;
        bool dnssec_required = false;
        bool auth_pkix_crls = Config::config().fetch_pkix_status();
        bool auth_host = false;
        TLS_PREFERENCE tls_preference = PREFER_ANY;
        unsigned int stanza_timeout = 20;
        unsigned int connect_timeout = 10;
        std::string dhparam = "auto";
        std::string cipherlist = "HIGH:!3DES:!eNULL:!aNULL:@STRENGTH"; // Apparently 3DES qualifies for HIGH, but is 112 bits, which the IM Observatory marks down for.
        std::optional<std::string> auth_secret;
        int min_tls_version = TLS1_2_VERSION;
        int max_tls_version = 0;
        if (any) {
            auth_pkix = any->auth_pkix();
            auth_dialback = any->auth_dialback();
            tls_required = tls_required && any->require_tls();
            tls_preference = any->tls_preference();
            xmpp_ver = any->xmpp_ver();
            dnssec_required = any->dnssec_required();
            dhparam = any->dhparam();
            cipherlist = any->cipherlist();
            auth_pkix_crls = any->auth_pkix_status();
            stanza_timeout = any->stanza_timeout();
            connect_timeout = any->connect_timeout();
            min_tls_version = any->min_tls_version();
            max_tls_version = any->max_tls_version();
        }
        if (domain_name == "any") {
            name = "";
        } else {
            name = Jid(domain_name).domain(); // This stringpreps.
        }
        block = domain["block"].as<bool>(block);
        if (domain["transport"]) {
            auto type = domain["transport"]["type"].as<std::string>("s2s");
            if (type == "s2s") {
                sess = S2S;
            } else if (type == "x2x") {
                sess = X2X;
            } else if (type == "114") {
                sess = COMP;
                tls_required = false;
                forward = true;
            } else if (type == "internal") {
                sess = INTERNAL;
                tls_required = true;
                forward = true;
            } else {
                throw std::runtime_error("Unknown transport type");
            }
            multiplex = domain["transport"]["multiplex"].as<bool>(multiplex);
            auto tls_sec = domain["transport"]["tls_required"] ? domain["transport"]["tls_required"] : domain["transport"]["sec"];
            tls_required = tls_sec.as<bool>(tls_required);
            xmpp_ver = domain["transport"]["xmpp_ver"].as<bool>(xmpp_ver);
            if (domain["transport"]["prefer"]) {
                std::string tls_pref_str = domain["transport"]["prefer"].as<std::string>();
                if (tls_pref_str == "immediate" || tls_pref_str == "direct") {
                    tls_preference = PREFER_IMMEDIATE;
                } else if (tls_pref_str == "starttls") {
                    tls_preference = PREFER_STARTTLS;
                }
            }
            connect_timeout = domain["transport"]["connect-timeout"].as<int>(connect_timeout);
        }
        stanza_timeout = domain["stanza-timeout"].as<int>(stanza_timeout);
        forward = domain["forward"].as<bool>(forward);

        if(domain["auth"]) {
            auth_pkix = domain["auth"]["pkix"].as<bool>(auth_pkix);
            auth_pkix_crls = domain["auth"]["check-status"].as<bool>(auth_pkix_crls);
            if (auth_pkix_crls && !Config::config().fetch_pkix_status()) {
                throw std::runtime_error("Cannot check status without fetching status.");
            }
            auth_dialback = domain["auth"]["dialback"].as<bool>(auth_dialback);
            if (domain["auth"]["secret"]) {
                auth_secret = domain["auth"]["secret"].as<std::string>();
            }
            auth_host = domain["auth"]["host"].as<bool>(auth_host);
            if (auth_host && sess == X2X) {
                dnssec_required = true;
            }
            if (!(block || auth_pkix || auth_dialback || auth_secret || auth_host)) {
                throw std::runtime_error("Cannot authenticate domain, but not blocked.");
            }
        }
        auto dom = std::make_unique<Config::Domain>(name, sess, xmpp_ver, forward, tls_required, block, multiplex, auth_pkix, auth_dialback,
                                                    auth_host, std::move(auth_secret));
        dom->auth_pkix_status(auth_pkix_crls);
        dom->stanza_timeout(stanza_timeout);
        dom->connect_timeout(connect_timeout);
        dom->tls_preference(tls_preference);
        if (auto tls = domain["tls"]; tls) {
            if (tls["x509"]) {
                if (auto chain_a = tls["x509"]["chain"]; chain_a) {
                    auto chain = chain_a.as<std::string>();
                    auto pkey_a = tls["x509"]["pkey"];
                    if (pkey_a) {
                        auto pkey = pkey_a.as<std::string>();
                        dom->x509(chain, pkey);
                    } else {
                        throw std::runtime_error("Missing pkey for x509");
                    }
                } else {
                    throw std::runtime_error("Missing chain for x509");
                }
            }
            dhparam = tls["dhparam"].as<std::string>(dhparam);
            cipherlist = tls["ciphers"].as<std::string>(cipherlist);
            if (tls["min_version"]) {
                min_tls_version = yaml_to_tls(tls["min_version"]);
            }
            if (tls["max_version"]) {
                max_tls_version = yaml_to_tls(tls["max_version"]);
            }
        }
        dom->dhparam(dhparam);
        dom->cipherlist(cipherlist);
        dom->min_tls_version(min_tls_version);
        dom->max_tls_version(max_tls_version);

        if (auto dnst = domain["dns"]; dnst) {
            auto dnssec = dnst["dnssec_required"] ? dnst["dnssec_required"] : dnst["dnssec"];
            dnssec_required = dnssec.as<bool>(dnssec_required);
            for (auto hostt : dnst["host"]) {
                auto hosta = hostt["name"];
                if (!hosta) throw std::runtime_error("Missing name in host DNS override");
                std::string host = hosta.as<std::string>();
                auto aa = hostt["a"];
                if (!aa) throw std::runtime_error("Missing a in host DNS override");
                struct in_addr ina;
                auto addr = aa.as<std::string>();
                if (inet_pton(AF_INET, addr.c_str(), &ina)) {
                    dom->host(host, ina.s_addr);
                }
            }
            for (auto srvt : dnst["srv"]) {
                auto hosta = srvt["host"];
                if (!hosta) throw std::runtime_error("Missing host in SRV DNS override");
                std::string host = hosta.as<std::string>();
                auto tls = srvt["tls"].as<bool>(false);
                unsigned short port = srvt["port"].as<unsigned short>(tls ? 5270 : 5269);
                unsigned short weight = srvt["weight"].as<unsigned short>(0);
                unsigned short prio = srvt["priority"].as<unsigned short>(0);
                dom->srv(host, prio, weight, port, tls);
            }
            for (auto tlsa : dnst["tlsa"]) {
                auto hosta = tlsa["hostname"];
                if (!hosta) throw std::runtime_error("Missing hostname in TLSA DNS override");
                std::string host = hosta.as<std::string>();
                auto port = tlsa["port"].as<unsigned short>(5269);
                auto certusagea = tlsa["certusage"];
                if (!certusagea) throw std::runtime_error("Missing certusage in TLSA DNS override");
                DNS::TlsaRR::CertUsage certUsage;
                std::string certusages = certusagea.as<std::string>();
                if (certusages == "CAConstraint") {
                    certUsage = DNS::TlsaRR::CAConstraint;
                } else if (certusages == "CertConstraint") {
                    certUsage = DNS::TlsaRR::CertConstraint;
                } else if (certusages == "TrustAnchorAssertion") {
                    certUsage = DNS::TlsaRR::TrustAnchorAssertion;
                } else if (certusages == "DomainCert") {
                    certUsage = DNS::TlsaRR::DomainCert;
                } else {
                    throw std::runtime_error("Unknown certusage in TLSA DNS override");
                }
                auto matchtypes = tlsa["matchtype"].as<std::string>("Full");
                DNS::TlsaRR::MatchType matchType = DNS::TlsaRR::Full;
                if (matchtypes == "Full") {
                    matchType = DNS::TlsaRR::Full;
                } else if (matchtypes == "Sha256") {
                    matchType = DNS::TlsaRR::Sha256;
                } else if (matchtypes == "Sha512") {
                    matchType = DNS::TlsaRR::Sha512;
                } else {
                    throw std::runtime_error("Unknown matchtype in TLSA DNS override");
                }
                auto sel = tlsa["selector"].as<std::string>("FullCert");
                DNS::TlsaRR::Selector selector = DNS::TlsaRR::FullCert;
                if (sel == "FullCert") {
                    selector = DNS::TlsaRR::FullCert;
                } else if (sel == "SubjectPublicKeyInfo") {
                    selector = DNS::TlsaRR::SubjectPublicKeyInfo;
                } else {
                    throw std::runtime_error("Unknown selector in TLSA DNS override");
                }
                dom->tlsa(host, port, certUsage, selector, matchType, tlsa["matchdata"].as<std::string>());
            }
        }
        dom->dnssec_required(dnssec_required);
        for (auto const & filter : domain["filter-in"]) {
            std::string filter_name = filter.first.as<std::string>();
            auto it = Filter::all_filters().find(filter_name);
            if (it == Filter::all_filters().end()) {
                throw std::runtime_error("Unknown filter " + filter_name);
            }
            auto &filter_desc = (*it).second;
            dom->filters().emplace_back(filter_desc->create(*dom, filter.second));
        }
        return dom;
    }

    Config *s_config = nullptr;

    bool openssl_init = false;
}

Config::Domain::Domain(std::string const &domain, SESSION_TYPE transport_type, bool xmpp_ver, bool forward, bool require_tls,
                       bool block, bool multiplex, bool auth_pkix, bool auth_dialback, bool auth_host,
                       std::optional<std::string> &&auth_secret)
        : m_domain(domain), m_type(transport_type), m_xmpp_ver(xmpp_ver), m_forward(forward), m_require_tls(require_tls), m_block(block), m_multiplex(multiplex),
          m_auth_pkix(auth_pkix), m_auth_dialback(auth_dialback), m_auth_host(auth_host), m_auth_secret(auth_secret),
          m_ssl_ctx(nullptr) {
    m_logger = Config::config().logger("domain <" + m_domain + ">");
}

Config::Domain::Domain(Config::Domain const &any, std::string const &domain)
        : m_domain(domain), m_type(any.m_type), m_xmpp_ver(any.m_xmpp_ver), m_forward(any.m_forward), m_require_tls(any.m_require_tls),
          m_block(any.m_block), m_multiplex(any.m_multiplex), m_auth_pkix(any.m_auth_pkix), m_auth_crls(any.m_auth_crls),
          m_auth_dialback(any.m_auth_dialback), m_auth_host(any.m_auth_host), m_dnssec_required(any.m_dnssec_required),
          m_tls_preference(any.m_tls_preference), m_min_tls_version(any.m_min_tls_version), m_max_tls_version(any.m_max_tls_version),
          m_stanza_timeout(any.m_stanza_timeout), m_dhparam(any.m_dhparam), m_cipherlist(any.m_cipherlist), m_auth_secret(any.m_auth_secret),
          m_ssl_ctx(nullptr), m_parent(&any) {
    m_logger = Config::config().logger("domain <" + m_domain + ">");
}

sigslot::tasklet<FILTER_RESULT> Config::Domain::filter(std::shared_ptr<sentry::span> span, FILTER_DIRECTION dir, Stanza &s) const {
    if (m_parent) co_return co_await m_parent->filter(span->start_child("filter", "parent"), dir, s);
    for (auto &filter : m_filters) {
        auto filter_result = co_await filter->apply(span->start_child("filter", filter->name()), dir, s);
        if (filter_result == DROP) co_return DROP;
    }
    co_return PASS;
}



Config::Domain::~Domain() {
    logger().warn("Domain {} destroyed", m_domain);
    if (m_ssl_ctx) {
        SSL_CTX_free(m_ssl_ctx);
        m_ssl_ctx = nullptr;
    }
}

void Config::Domain::host(std::string const &ihostname, uint32_t inaddr) {
    auto address = std::make_unique<DNS::Address>();
    std::string hostname = DNS::Utils::toASCII(ihostname);
    if (hostname[hostname.length() - 1] != '.') hostname += '.';
    address->dnssec = true;
    address->hostname = hostname;
    auto& a = address->addr.emplace_back();
    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&a);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inaddr;
    m_host_arecs[hostname] = std::move(address);
}

int Config::verify_callback_cb(int preverify_ok, struct x509_store_ctx_st *st) {
    if (!preverify_ok) {
        const int name_sz = 256;
        std::string cert_name;
        cert_name.resize(name_sz);
        X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)),
                          const_cast<char *>(cert_name.data()), name_sz);
        cert_name.resize(cert_name.find('\0'));
        Config::config().m_logger->info("Cert failed basic verification: {}", cert_name);
        Config::config().m_logger->info("Error is {}", X509_verify_cert_error_string(X509_STORE_CTX_get_error(st)));
    } else {
        const int name_sz = 256;
        std::string cert_name;
        cert_name.resize(name_sz);
        X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)),
                          const_cast<char *>(cert_name.data()), name_sz);
        cert_name.resize(cert_name.find('\0'));
        Config::config().m_logger->debug("Cert passed basic verification: {}", cert_name);
        if (Config::config().m_fetch_crls) {
            auto cert = X509_STORE_CTX_get_current_cert(st);
            std::unique_ptr<STACK_OF(DIST_POINT),std::function<void(STACK_OF(DIST_POINT) *)>> crldp_ptr{(STACK_OF(DIST_POINT)*)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL),[](STACK_OF(DIST_POINT) * crldp){ sk_DIST_POINT_pop_free(crldp, DIST_POINT_free); }};
            auto crldp = crldp_ptr.get();
            if (crldp) {
                for (int i = 0; i != sk_DIST_POINT_num(crldp); ++i) {
                    DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
                    if (dp->distpoint->type == 0) { // Full Name
                        auto names = dp->distpoint->name.fullname;
                        for (int ii = 0; ii != sk_GENERAL_NAME_num(names); ++ii) {
                            GENERAL_NAME *name = sk_GENERAL_NAME_value(names, ii);
                            if (name->type == GEN_URI) {
                                ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
                                std::string uristr{reinterpret_cast<char *>(uri->data),
                                                   static_cast<std::size_t>(uri->length)};
                                Config::config().m_logger->info("Prefetching CRL for {} - {}", cert_name, uristr);
                                Http::crl(uristr);
                            }
                        }
                    }
                }
            }
        }
    }
    return 1;
}

namespace {
    int ssl_servername_cb(SSL *ssl, int *ad, void *arg) {
        const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (!servername) return SSL_TLSEXT_ERR_OK;
        SSL_CTX *old_ctx = SSL_get_SSL_CTX(ssl);
        SSL_CTX *new_ctx = Config::config().domain(Jid(servername).domain()).ssl_ctx();
        if (!new_ctx) new_ctx = Config::config().domain("").ssl_ctx();
        if (new_ctx != old_ctx) SSL_set_SSL_CTX(ssl, new_ctx);
        return SSL_TLSEXT_ERR_OK;
    }
}

void Config::Domain::x509(std::string const &chain, std::string const &pkey) {
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
    m_ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_dane_enable(m_ssl_ctx);
    SSL_CTX_dane_set_flags(m_ssl_ctx, DANE_FLAG_NO_DANE_EE_NAMECHECKS);
    SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_ALL);
    SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, Config::verify_callback_cb);
    if (SSL_CTX_use_certificate_chain_file(m_ssl_ctx, chain.c_str()) != 1) {
        for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
            Config::config().logger().error("OpenSSL Error (chain): {}", ERR_reason_error_string(e));
        }
        throw std::runtime_error("Couldn't load chain file: " + chain);
    }
    if (SSL_CTX_use_PrivateKey_file(m_ssl_ctx, pkey.c_str(), SSL_FILETYPE_PEM) != 1) {
        for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
            Config::config().logger().error("OpenSSL Error (pkey): {}", ERR_reason_error_string(e));
        }
        throw std::runtime_error("Couldn't load keyfile: " + pkey);
    }
    if (SSL_CTX_check_private_key(m_ssl_ctx) != 1) {
        for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
            Config::config().logger().error("OpenSSL Error (check): {}", ERR_reason_error_string(e));
        }
        throw std::runtime_error("Private key mismatch");
    }
    SSL_CTX_set_purpose(m_ssl_ctx, X509_PURPOSE_SSL_SERVER);
//    if(SSL_CTX_set_default_verify_paths(m_ssl_ctx) == 0) {
    if(SSL_CTX_load_verify_locations(m_ssl_ctx, nullptr, "/etc/ssl/certs") == 0) {
        m_logger->warn("Loading default verify paths failed:");
        for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
            m_logger->error("OpenSSL Error (default_verify_paths): {}", ERR_reason_error_string(e));
        }
    }
    SSL_CTX_set_tlsext_servername_callback(m_ssl_ctx, ssl_servername_cb);
    std::string ctx = "Metre::" + m_domain;
    SSL_CTX_set_session_id_context(m_ssl_ctx, reinterpret_cast<const unsigned char *>(ctx.c_str()),
                                   static_cast<unsigned int>(ctx.size()));
}

Filter * Config::Domain::filter_by_name(const std::string &name) const {
    if (m_parent) return m_parent->filter_by_name(name);
    for (auto &f: m_filters) {
        if (f->name() == name) {
            return f.get();
        }
    }
    return nullptr;
}

void Config::Domain::max_tls_version(int ver) {
    m_max_tls_version = ver;
}

void Config::Domain::min_tls_version(int ver) {
    m_min_tls_version = ver;
}

SSL_CTX *Config::Domain::ssl_ctx() const {
    SSL_CTX *ctx = m_ssl_ctx;
    if (!ctx) {
        for (Domain const *d = this; d; d = d->m_parent) {
            ctx = d->m_ssl_ctx;
            if (ctx) break;
        }
    }
    return ctx;
}

Config::Config(std::string const &filename) : m_dialback_secret(random_identifier()) {
    s_config = this;
    // Spin up a temporary error logger.
    m_root_logger = spdlog::stderr_color_st("console");
    spdlog::set_level(spdlog::level::trace);
    load(filename);
    m_ub_ctx = ub_ctx_create();
    if (!m_ub_ctx) {
        throw std::runtime_error("DNS context creation failure.");
    }
}

Config::~Config() {
    // TODO: Should really do this, but need to shut it down first: ub_ctx_delete(m_ub_ctx);
}

void Config::write_runtime_config() const {
    std::string tmp = asString();
    std::ofstream of(m_data_dir + "/" + "metre.running.yml", std::ios_base::trunc);
    of << tmp;
}

void Config::load(std::string const &filename) {
    auto root_node = YAML::LoadFile(filename);
    if (auto globals = root_node["globals"]; globals) {
        m_default_domain = globals["default-domain"].as<std::string>(m_default_domain);
        m_runtime_dir = globals["rundir"].as<std::string>(m_runtime_dir);
        m_logfile = globals["log"]["file"].as<std::string>(m_logfile);
        m_log_level = globals["log"]["level"].as<std::string>("info");
        m_log_flush = globals["log"]["flush"].as<std::string>(m_log_level);
        m_boot = globals["boot-method"].as<std::string>(m_boot);
        m_data_dir = globals["datadir"].as<std::string>(m_data_dir);
        m_dns_keys = globals["dnssec-keys"].as<std::string>(m_dns_keys);
        m_fetch_crls = globals["fetch-crls"].as<bool>(m_fetch_crls);
        m_healthcheck_address =  "0.0.0.0";
        m_healthcheck_port = 7000;
        if (globals["healthcheck"]) {
            m_healthcheck_port = globals["healthcheck"]["port"].as<unsigned short>(m_healthcheck_port);
            m_healthcheck_address = globals["healthcheck"]["address"].as<std::string>(m_healthcheck_address);
            if (globals["healthcheck"]["checks"]) {
                for (auto const & from : globals["healthcheck"]["checks"]) {
                    m_healthchecks.emplace(std::make_pair(from.first.as<std::string>(), from.second.as<std::string>()));
                }
            }
        }
        if (auto filters = root_node["filters"]; filters) {
            for (auto const & item : filters) {
                auto filter_name = item.first.as<std::string>();
                auto it = Filter::all_filters().find(filter_name);
                if (it == Filter::all_filters().end()) {
                    throw std::runtime_error("Unknown filter " + filter_name);
                }
                auto &filter_desc = (*it).second;
                filter_desc->config(item.second);
            }
        }
    }
    if (m_runtime_dir.empty()) {
        m_runtime_dir = "/var/run/";
    }
    if (m_data_dir.empty()) {
        m_data_dir = m_runtime_dir;
    }
    m_pidfile = m_runtime_dir + "/metre.pid";
    if (m_boot.empty()) {
        m_boot = "none";
    }
    Config::Domain *any_domain = nullptr;
    if (auto external = root_node["remote"]; external) {
        YAML::Node block;
        block["block"] = true;
        auto const & any_node = external["any"] ? external["any"] : block;
        // This will 'parse' a non-existent domain if any isn't explicitly set, but that's OK.
        std::unique_ptr<Config::Domain> dom = parse_domain(nullptr, "any", any_node, true);
        any_domain = dom.get(); // Save this pointer.
        m_domains[dom->domain()] = std::move(dom);
        for (auto const & item : external) {
            auto name = item.first.as<std::string>();
            if (name == "any") {
                continue;
            }
            std::unique_ptr<Config::Domain> dom = parse_domain(any_domain, name, item.second, true);
            m_domains[dom->domain()] = std::move(dom);
        }
    }
    if (auto internal = root_node["local"]; internal) {
        for (auto const & item : internal) {
            auto name = item.first.as<std::string>();
            if (name == "any") {
                continue;
            }
            std::unique_ptr<Config::Domain> dom = parse_domain(any_domain, name, item.second, false);
            m_domains[dom->domain()] = std::move(dom);
        }
    }
    if (auto listeners = root_node["listeners"]; listeners) {
        for (auto listener : listeners) {
            // address : port* : default_domain[*X2X] : session_type : tls_mode
            auto port = listener["port"].as<unsigned short>();
            SESSION_TYPE stype = S2S;
            TLS_MODE tls = listener["tls"].as<bool>() ? IMMEDIATE : STARTTLS;
            if (listener["type"]) {
                std::string s = listener["type"].as<std::string>();
                if (s == "s2s") {
                    stype = S2S;
                } else if (s == "x2x") {
                    stype = X2X;
                } else if (s == "114") {
                    stype = COMP;
                } else {
                    throw std::runtime_error("Unknown type for listener");
                }
            }
            auto local_domain = listener["local-domain"].as<std::string>("");
            auto remote_domain = listener["remote-domain"].as<std::string>("");
            auto address =  listener["address"].as<std::string>("::");
            std::ostringstream ss;
            ss << "unnamed-" << address << "-" << port;
            auto name = listener["name"].as<std::string>(ss.str());
            m_listeners.emplace_back(local_domain, remote_domain, name, address, port, tls, stype);
            if (remote_domain[0]) m_listeners.rbegin()->allowed_domains.emplace(remote_domain);
            for (auto allowed : listener["allowed-domains"]) {
                m_listeners.rbegin()->allowed_domains.emplace(allowed.as<std::string>());
            }
        }
    } else {
        m_listeners.emplace_back("", "", "S2S", "::", 5269, STARTTLS, S2S);
        m_listeners.emplace_back("", "", "XEP-0368", "::", 5270, IMMEDIATE, S2S);
    }
}

Config::Listener::Listener(std::string const &ldomain, std::string const &rdomain, std::string const &aname,
                           std::string const &address, unsigned short port, TLS_MODE atls,
                           SESSION_TYPE asess)
        : session_type(asess), tls_mode(atls), name(aname), local_domain(ldomain), remote_domain(rdomain) {
    std::memset(&m_sockaddr, 0, sizeof(m_sockaddr)); // Clear, to avoid valgrind complaints later.
    if (1 == inet_pton(AF_INET6, address.c_str(), &(reinterpret_cast<struct sockaddr_in6 *>(&m_sockaddr)->sin6_addr))) {
        struct sockaddr_in6 *sa = reinterpret_cast<struct sockaddr_in6 *>(&m_sockaddr);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
    } else if (1 == inet_pton(AF_INET, address.c_str(), &(reinterpret_cast<struct sockaddr_in *>(&m_sockaddr)->sin_addr))) {
        struct sockaddr_in *sa = reinterpret_cast<struct sockaddr_in *>(&m_sockaddr);
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
    } else {
        throw std::runtime_error("Couldn't understand address syntax " + std::string(address));
    }
    if (asess == X2X) {
        if (local_domain.empty() || remote_domain.empty()) {
            throw std::runtime_error("Missing local or remote domains");
        }
    }
}

namespace {
    const char * tls_version_to_string(int ver) {
        switch (ver) {
            case SSL2_VERSION:
                return "SSLv2";
            case SSL3_VERSION:
                return "SSLv3";
            case TLS1_VERSION:
                return "TLSv1.0";
            case TLS1_1_VERSION:
                return "TLSv1.1";
            case TLS1_2_VERSION:
                return "TLSv1.2";
            case TLS1_3_VERSION:
                return "TLSv1.3";
        }
        return nullptr;
    }

    YAML::Node domain_to_yaml(Config::Domain const &domain) {
        YAML::Node config;
        config["forward"] = domain.forward();
        config["block"] = domain.block();
        config["stanza-timeout"] = domain.stanza_timeout();
        switch (domain.transport_type()) {
            case INTERNAL:
                config["transport"]["type"] = "internal";
                break;
            case S2S:
                config["transport"]["type"] = "s2s";
                break;
            case COMP:
                config["transport"]["type"] = "114";
                break;
            case X2X:
                config["transport"]["type"] = "x2x";
            default:
                throw std::runtime_error("No idea what this transport type is");
        }
        config["transport"]["multiplex"] = domain.multiplex();
        config["transport"]["tls_required"] = domain.require_tls();
        switch (domain.tls_preference()) {
            case PREFER_IMMEDIATE:
                config["transport"]["prefer"] = "direct";
                break;
            case PREFER_STARTTLS:
                config["transport"]["prefer"] = "starttls";
                break;
            case PREFER_ANY:
                config["transport"]["prefer"] = "any";
                break;
        }
        config["transport"]["xmpp_ver"] = domain.xmpp_ver();
        config["transport"]["connect-timeout"] = domain.connect_timeout();
        config["auth"]["pkix"] = domain.auth_pkix();
        config["auth"]["check-status"] = domain.auth_pkix_status();
        config["auth"]["dialback"] = domain.auth_dialback();
        if (domain.auth_secret()) {
            config["auth"]["secret"] = *domain.auth_secret();
        }
        config["dns"]["dnssec_required"] = domain.dnssec_required();
        if (domain.srv_override()) {
            for (auto &rr: domain.srv_override()->rrs) {
                YAML::Node srv;
                srv["host"] = rr.hostname;
                srv["port"] = rr.port;
                srv["priority"] = rr.priority;
                srv["weight"] = rr.weight;
                srv["tls"] = rr.tls;
                config["dns"]["srv"].push_back(srv);
            }
        }
        for (auto const & [name, records]: domain.tlsa_overrides()) {
            for (auto const &rr: records->rrs) {
                std::stringstream ss(records->domain);
                unsigned short int port = 0;
                std::string hostname;
                char underscore;
                ss >> underscore >> port >> hostname;
                YAML::Node tlsa;
                tlsa["hostname"] = hostname;
                tlsa["port"] = port;
                switch (rr.matchType) {
                    case DNS::TlsaRR::Sha256:
                        tlsa["matchtype"] = "Sha256";
                        break;
                    case DNS::TlsaRR::Sha512:
                        tlsa["matchtype"] = "Sha512";
                        break;
                    default:
                        tlsa["matchtype"] = "Full";
                        break;
                }
                switch (rr.selector) {
                    case DNS::TlsaRR::SubjectPublicKeyInfo:
                        tlsa["selector"] = "SubjectPublicKeyInfo";
                        break;
                    default:
                        tlsa["selector"] = "FullCert";
                        break;
                }
                switch (rr.certUsage) {
                    case DNS::TlsaRR::CAConstraint:
                        tlsa["certusage"] = "CAConstraint";
                        break;
                    case DNS::TlsaRR::CertConstraint:
                        tlsa["certusage"] = "CertConstraint";
                        break;
                    case DNS::TlsaRR::TrustAnchorAssertion:
                        tlsa["certusage"] = "TrustAnchorAssertion";
                        break;
                    default:
                        tlsa["certusage"] = "DomainCert";
                        break;
                }
                if (rr.matchType == DNS::TlsaRR::Full) {
                    // Base64 data (it might have come from a file, but never mind).
                    tlsa["matchdata"] = base64_encode(rr.matchData);
                } else {
                    std::ostringstream os;
                    os << std::hex << std::setfill('0') << std::setw(2);
                    bool colon = false;
                    for (char c: rr.matchData) {
                        auto byte = static_cast<unsigned short>(c);
                        // Use numeric type to avoid treating as character.
                        if (!colon) {
                            colon = true;
                        } else {
                            os << ':';
                        }
                        os << byte;
                    }
                    tlsa["matchdata"] = os.str();
                }
                config["dns"]["tlsa"].push_back(tlsa);
            }
        }
        for (auto const &[hostname, address]: domain.address_overrides()) {
            YAML::Node host;
            host["name"] = hostname;
            std::array<char, 32> buf{};
            auto sin = reinterpret_cast<struct sockaddr_in *>(address->addr.data());
            inet_ntop(AF_INET, &sin->sin_addr, buf.data(), buf.size());
            host["a"] = buf.data();
            config["dns"]["host"].push_back(host);
        }
        {
            SSL_CTX *ctx = domain.ssl_ctx();
            if (!ctx && domain.parent()) {
                ctx = domain.parent()->ssl_ctx();
            }
            if (ctx) {
                std::string prefix;
                if (domain.domain().empty()) {
                    prefix = "any_";
                } else {
                    prefix = domain.domain() + "_";
                    std::ranges::replace(prefix, '*', '_');
                }
                STACK_OF(X509) *chain = nullptr;
                std::string chainfile = Config::config().data_dir() + "/" + prefix + "chain.pem";
                if (SSL_CTX_get0_chain_certs(ctx, &chain) && chain) {
                    FILE *fp = fopen(chainfile.c_str(), "w");
                    for (int i = 0; i < sk_X509_num(chain); ++i) {
                        X509 *item = sk_X509_value(chain, i);
                        PEM_write_X509(fp, item);
                    }
                    fclose(fp);
                    config["tls"]["x509"]["chain"] = chainfile;
                }
                std::string keyfile = Config::config().data_dir() + "/" + prefix + "key.pem";
                if (SSL_CTX_get0_privatekey(ctx)) {
                    FILE *fp = fopen(keyfile.c_str(), "w");
                    PEM_write_PKCS8PrivateKey(fp, SSL_CTX_get0_privatekey(ctx), nullptr, nullptr, 0,
                                              nullptr,
                                              nullptr);
                    fclose(fp);
                    config["tls"]["x509"]["pkey"] = keyfile;
                }
            }
        }
        config["tls"]["dhparam"] = domain.dhparam();
        config["tls"]["ciphers"] = domain.cipherlist();
        if (auto const * s = tls_version_to_string(domain.min_tls_version()); s) {
            config["tls"]["min_version"] = s;
        }
        if (auto const * s = tls_version_to_string(domain.max_tls_version()); s) {
            config["tls"]["max_version"] = s;
        }

        for (auto const &filter: domain.filters()) {
            config["filter-in"][filter->name()] = filter->dump_config();
        }
        return config;
    }
}

std::string Config::asString() const {
    YAML::Node config;
    if (!m_default_domain.empty()) {
        config["globals"]["default-domain"] = m_default_domain;
    }

    config["globals"]["rundir"] = m_runtime_dir;
    config["globals"]["datadir"] = m_data_dir;
    config["globals"]["log"]["file"] = m_logfile;
    config["globals"]["log"]["level"] = m_log_level;
    config["globals"]["log"]["flush"] = m_log_flush;
    config["globals"]["boot-method"] = m_boot;
    config["globals"]["fetch-crls"] = m_fetch_crls;
    config["globals"]["dnssec-keys"] = m_dns_keys;
    config["globals"]["healthcheck"]["address"] = m_healthcheck_address;
    config["globals"]["healthcheck"]["port"] = m_healthcheck_port;
    for (auto const & [from, to] : m_healthchecks) {
        config["globals"]["healthcheck"]["checks"][from] = to;
    }

    for (auto const &[filter_name, filter] : Filter::all_filters()) {
        config["filters"][filter_name] = filter->config();
    }

    for (auto const & [domain_name, domain] : m_domains) {
        std::string key = domain_name;
        if (key.empty()) {
            key = "any";
        }
        config["remote"][key] = domain_to_yaml(*domain);
    }

    for (auto &listen : m_listeners) {
        YAML::Node listener;
        if (!listen.local_domain.empty()) {
            listener["local-domain"] = listen.local_domain;
        }
        if (!listen.remote_domain.empty()) {
            listener["remote-domain"] = listen.remote_domain;
        }
        listener["name"] = listen.name;
        if (listen.sockaddr()->sa_family == AF_INET) {
            const struct sockaddr_in *sa = reinterpret_cast<const struct sockaddr_in *>(listen.sockaddr());
            char buf[1024];
            inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(struct sockaddr_in));
            listener["address"] = buf;
            listener["port"] = ntohs(sa->sin_port);
        } else if (listen.sockaddr()->sa_family == AF_INET6) {
            const struct sockaddr_in6 *sa = reinterpret_cast<const struct sockaddr_in6 *>(listen.sockaddr());
            char buf[1024];
            inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(struct sockaddr_in6));
            listener["address"] = buf;
            listener["port"] = ntohs(sa->sin6_port);
        }
        switch (listen.session_type) {
            case S2S:
                listener["type"] = "s2s";
                break;
            case X2X:
                listener["type"] = "x2x";
                break;
            case COMP:
                listener["type"] = "114";
                break;
            default:
                continue;
        };
        listener["tls"] = listen.tls_mode == IMMEDIATE;
        config["listeners"].push_back(listener);
    }

    std::ostringstream ss;
    ss << config;
    return ss.str();
}

void Config::docker_setup() {
	m_logfile = std::string();
	m_data_dir = "/tmp";
	m_runtime_dir = "/tmp";
	log_init(true);
}

void Config::log_init(bool systemd) {
    if (!systemd && m_logfile.empty()) {
        m_logfile = "/var/log/metre/metre.log";
    }
    // Initialize logging.
    if (!m_logfile.empty()) {
        m_root_logger = spdlog::daily_logger_st("global", m_logfile);
    } else {
        m_root_logger = spdlog::stderr_logger_st("global");
    }
    m_root_logger->flush_on(spdlog::level::from_str(m_log_flush));
    m_root_logger->set_level(spdlog::level::from_str(m_log_level));
    m_logger = logger("config");
}

void Config::create_domain(std::string const &dom) {
    std::string search{dom};
    auto it = m_domains.find(dom);
    if (it != m_domains.end()) return;
    while (it == m_domains.end()) {
        it = m_domains.find("*." + search);
        if (it == m_domains.end()) {
            auto dot = search.find('.');
            if (dot == std::string::npos) {
                search = "";
            } else {
                search = search.substr(dot + 1);
            }
            it = m_domains.find(search);
        }
    }
    m_logger->info("Creating new domain config {} from parent ({})", dom, (*it).second->domain());
    m_domains[dom] = std::make_unique<Config::Domain>(*(*it).second, dom);
}

Config::Domain const &Config::domain(std::string const &dom) const {
    auto it = m_domains.find(dom);
    while (it == m_domains.end()) {
        const_cast<Config *>(this)->create_domain(dom);
        it = m_domains.find(dom);
    }
    return *(*it).second;
}

std::string Config::random_identifier() const {
    const size_t id_len = 16;
    char characters[] = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ@";
    std::default_random_engine random(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(characters) - 2);
    std::string id(id_len, char{});
    std::generate_n(id.begin(), id_len, [&characters, &random, &dist]() { return characters[dist(random)]; });
    return id;
}

std::string Config::dialback_key(std::string const &id, std::string const &local_domain, std::string const &remote_domain) const {
    std::string binoutput;
    binoutput.resize(20);
    std::string const &key = dialback_secret();
    std::string concat = id + '|' + local_domain + '|' + remote_domain;
    HMAC(EVP_sha1(), reinterpret_cast<const unsigned char *>(key.data()), key.length(),
         reinterpret_cast<const unsigned char *>(concat.data()), concat.length(),
         const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(binoutput.data())), nullptr);
    std::string hexoutput;
    for (unsigned char c : binoutput) {
        int low = c & 0x0F;
        int high = (c & 0xF0) >> 4;
        hexoutput += ((high < 0x0A) ? '0' : ('a' - 10)) + high;
        hexoutput += ((low < 0x0A) ? '0' : ('a' - 10)) + low;
    }
    assert(hexoutput.length() == 40);
    m_logger->debug("Dialback key id {} :: {} | {}", id, local_domain, remote_domain);
    return hexoutput;
}

Config const &Config::config() {
    return *s_config;
}

void Config::dns_init() const {
    // Libunbound initialization.
    const_cast<Config *>(this)->m_ub_ctx = DNS::Utils::dns_init(m_dns_keys);
}

std::shared_ptr<spdlog::logger> Config::logger(std::string const & logger_name) const {
    auto sinks = m_root_logger->sinks();
    auto logger = std::make_shared<spdlog::logger>(logger_name, begin(sinks), end(sinks));
    logger->flush_on(spdlog::level::from_str(m_log_flush));
    logger->set_level(spdlog::level::from_str(m_log_level));
    return logger;
}

/*
 * DNS resolver functions.
 */

void Config::Domain::tlsa(std::string const &ahostname, unsigned short port, DNS::TlsaRR::CertUsage certUsage,
                          DNS::TlsaRR::Selector selector, DNS::TlsaRR::MatchType matchType, std::string const &value) {
    std::ostringstream out;
    if (ahostname.empty()) throw std::runtime_error("Empty hostname in TLSA override");
    std::string hostname = ahostname;
    if (hostname[hostname.length() - 1] != '.') hostname += '.';
    out << "_" << port << "._tcp." << hostname;
    std::string domain = DNS::Utils::toASCII(out.str());
    auto tlsait = m_tlsarecs.find(domain);
    DNS::Tlsa *tlsa;
    if (tlsait == m_tlsarecs.end()) {
        auto tlsan = std::make_unique<DNS::Tlsa>();
        tlsan->dnssec = true;
        tlsan->domain = domain;
        tlsa = tlsan.get();
        m_tlsarecs[domain] = std::move(tlsan);
    } else {
        tlsa = tlsait->second.get();
    }
    DNS::TlsaRR rr;
    rr.certUsage = certUsage;
    rr.matchType = matchType;
    rr.selector = selector;
    // Match data. Annoying.
    // If the match type was a hash, it'll be an inline hash.
    switch (matchType) {
        case DNS::TlsaRR::Sha256:
        case DNS::TlsaRR::Sha512: {
            unsigned char byte = 0;
            bool flip = false;
            for (auto c : value) {
                if (std::isdigit(c)) {
                    byte += (c - '0');
                } else if (c >= 'A' && c <= 'F') {
                    byte += (c - 'A' + 0xA);
                } else if (c >= 'a' && c <= 'f') {
                    byte += (c - 'a' + 0xA);
                } else {
                    continue;
                }
                if (flip) {
                    rr.matchData += byte;
                    byte = 0;
                    flip = false;
                } else {
                    byte <<= 4;
                    flip = true;
                }
            }
        }
            break;
        default: {
            bool read_ok = false;
            if (value.find('\n') == std::string::npos && value.find('/') != std::string::npos) {
                std::ifstream in(value);
                rr.matchData.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                if (!rr.matchData.empty()) {
                    read_ok = true;
                }
                if (rr.selector == DNS::TlsaRR::FullCert && rr.matchType == DNS::TlsaRR::Full) {
                    // Full cert matching, so convenient to supply a PEM file as well. Let's check:
                    if (rr.matchData.find("-----BEGIN") == 0) {
                        // Tempting to replace this with a base64_decode call, mind.
                        std::string tmp = rr.matchData;
                        BIO * b = BIO_new_mem_buf(tmp.data(), static_cast<int>(tmp.size()));
                        auto cert = PEM_read_bio_X509(b, nullptr, nullptr, nullptr);
                        if (!cert) throw std::runtime_error("Invalid PEM certificate");
                        unsigned char * buf = nullptr;
                        auto len = i2d_X509(cert, &buf);
                        if (len < 0) throw std::runtime_error("Cannot re-encode to DER");
                        rr.matchData.assign(reinterpret_cast<const char *>(buf), len);
                    }
                }
            }
            if (!read_ok) {
                rr.matchData = base64_decode(value);
            }
        }
    }
    tlsa->rrs.push_back(rr);
}

Config::Resolver::Resolver(Domain const &d) : Metre::DNS::Resolver(d.domain(), d.dnssec_required(), d.tls_preference()), m_domain(d) {
    m_logger = Config::config().logger("Resolver <" + m_domain.domain() + ">");
}

Config::Resolver::~Resolver() = default;


void
Config::Domain::srv(std::string const &hostname, unsigned short priority, unsigned short weight, unsigned short port, bool tls) {
    if (!m_srvrec) {
        m_srvrec = std::make_unique<DNS::Srv>();
        std::string domain = DNS::Utils::toASCII(
                "_xmpp-server._tcp." + m_domain + "."); // Confusing: We fake a non-tls SRV record with TLS set in RR.
        m_srvrec->dnssec = true;
        m_srvrec->domain = domain;
    }
    DNS::SrvRR rr;
    rr.priority = priority;
    rr.weight = weight;
    rr.port = port;
    rr.hostname = DNS::Utils::toASCII(hostname);
    if (rr.hostname[rr.hostname.length() - 1] != '.') rr.hostname += '.';
    rr.tls = tls;
    m_srvrec->rrs.push_back(rr);
}

sigslot::tasklet<void> Config::Domain::gather_host(std::shared_ptr<sentry::span> span, Resolver & r, GatheredData & g, std::string const & host, uint16_t port, DNS::ConnectInfo::Method method) const {
    auto addr_recs = co_await r.AddressLookup(host);
    if (!addr_recs.error.empty()) co_return; // Interesting case: a DNSSEC-signed SVCB/SRV record pointing to a non-existent host still adds that host to the X.509-acceptable names.
    if (!addr_recs.dnssec && m_dnssec_required) co_return;
    for (auto const & arr : addr_recs.addr) {
        DNS::ConnectInfo conn_info;
        conn_info.method = method;
        conn_info.port = port;
        conn_info.sockaddr = arr;
        conn_info.hostname = host;
        if (conn_info.sockaddr.ss_family == AF_INET) {
            span->containing_transaction().tag("gather.ipv4", "yes");
            reinterpret_cast<sockaddr_in *>(&conn_info.sockaddr)->sin_port = port;
        } else if (conn_info.sockaddr.ss_family == AF_INET6) {
            span->containing_transaction().tag("gather.ipv6", "yes");
            reinterpret_cast<sockaddr_in6 *>(&conn_info.sockaddr)->sin6_port = port;
        }
        g.gathered_connect.push_back(conn_info);
    }
}

sigslot::tasklet<void> Config::Domain::gather_tlsa(std::shared_ptr<sentry::span> span, Resolver & r, GatheredData & g, std::string const & host, uint16_t port) const {
    auto recs = co_await r.TlsaLookup(port, host);
    if (!recs.error.empty()) co_return;
    if (!recs.dnssec) co_return;
    span->containing_transaction().tag("gather.tlsa", "yes");
    for (auto const & tlsa_rr : recs.rrs) {
        g.gathered_tlsa.push_back(tlsa_rr);
    }
}

sigslot::tasklet<Config::Domain::GatheredData> Config::Domain::gather(std::shared_ptr<sentry::span> span) const {
    auto r = resolver();
    std::string domain = m_domain;
    GatheredData g;
    span->containing_transaction().tag("gather.domain", domain);
    span->containing_transaction().tag("gather.svcb", "no");
    span->containing_transaction().tag("gather.srv", "no");
    span->containing_transaction().tag("gather.dnssec", "no");
    span->containing_transaction().tag("gather.ipv4", "no");
    span->containing_transaction().tag("gather.ipv6", "no");
    span->containing_transaction().tag("gather.tlsa", "no");
    span->containing_transaction().tag("gather.tls.direct", "no");
    span->containing_transaction().tag("gather.tls.starttls", "no");
aname_restart:
    g.gathered_connect.clear();
    auto svcb = co_await r->SvcbLookup(domain);
    if (svcb.error.empty() && !svcb.rrs.empty()) {
        span->containing_transaction().tag("gather.svcb", "yes");
        // SVCB pathway
        for (auto const & rr : svcb.rrs) {
            if (svcb.dnssec) {
                span->containing_transaction().tag("gather.dnssec", "yes");
                g.gathered_hosts.insert(rr.hostname);
            } else if (m_dnssec_required) {
                continue;
            }
            if (rr.priority == 0) {
                domain = rr.hostname;
                goto aname_restart;
            }
            uint16_t  default_port = 443; // Anticipation of WebSocket/WebTransport/BOSH.
            auto method = DNS::ConnectInfo::Method::StartTLS;
            if (rr.alpn.empty()) {
                method = DNS::ConnectInfo::Method::StartTLS;
                span->containing_transaction().tag("gather.tls.starttls", "yes");
                default_port = 5269;
            } else if (rr.alpn.contains("xmpp-server")) {
                method = DNS::ConnectInfo::Method::DirectTLS;
                span->containing_transaction().tag("gather.tls.direct", "yes");
                default_port = 5270;
            }
            co_await gather_host(span->start_child("gather.host", rr.hostname), *r, g, rr.hostname, rr.port ? rr.port : default_port, method);
            co_await gather_tlsa(span->start_child("gather.tlsa", rr.hostname), *r, g, rr.hostname, rr.port ? rr.port : default_port);
        }
    } else {
        // SRV path
        auto srv = co_await r->SrvLookup(domain); // Interesting case: An SVCB looking resulting in the ANAME case might follow to an SRV lookup.
        if (srv.error.empty() && !srv.rrs.empty()) {
            span->containing_transaction().tag("gather.srv", "yes");
            for (auto const & rr : srv.rrs) {
                if (srv.dnssec) {
                    span->containing_transaction().tag("gather.dnssec", "yes");
                    g.gathered_hosts.insert(rr.hostname);
                }
                if (rr.tls) {
                    span->containing_transaction().tag("gather.tls.direct", "yes");
                } else {
                    span->containing_transaction().tag("gather.tls.starttls", "yes");
                }
                co_await gather_host(span->start_child("gather.host", rr.hostname), *r, g, rr.hostname, rr.port, (rr.tls ? DNS::ConnectInfo::Method::DirectTLS : DNS::ConnectInfo::Method::StartTLS));
                co_await gather_tlsa(span->start_child("gather.tlsa", rr.hostname), *r, g, rr.hostname, rr.port);
            }
        } else {
            co_await gather_host(span->start_child("gather.host", domain), *r, g, domain, 5269, DNS::ConnectInfo::Method::StartTLS);
            co_await gather_tlsa(span->start_child("gather.tlsa", domain), *r, g, domain, 5269);
        }
    }
    co_return g;
}

DNS::Resolver::addr_callback_t &Config::Resolver::AddressLookup(std::string const &ihostname) {
    std::string hostname = DNS::Utils::toASCII(ihostname);
    logger().info("A/AAAA lookup for {}", hostname);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (!domain_override->address_overrides().empty()) {
            logger().debug("Found overrides at {}", domain_override->domain());
            auto it = domain_override->address_overrides().find(hostname);
            if (it != domain_override->address_overrides().end()) {
                auto addr = it->second.get();
                Router::defer([addr, this]() {
                    m_a_pending[addr->hostname].emit(*addr);
                });
                logger().debug("Using domain_override at {}", domain_override->domain());
                return m_a_pending[hostname];
            }
        }
    }
    return DNS::Resolver::AddressLookup(ihostname);
}

DNS::Resolver::srv_callback_t &Config::Resolver::SrvLookup(std::string const &base_domain) {
    std::string domain = DNS::Utils::toASCII("_xmpp-server._tcp." + base_domain + ".");
    std::string domains = DNS::Utils::toASCII("_xmpps-server._tcp." + base_domain + ".");
    m_logger->debug("SRV lookup: domain=[{}]", base_domain);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (domain_override->srv_override()) {
            logger().debug("Found domain_override at {}", domain_override->domain());
            Router::defer([domain_override, this]() {
                m_srv_pending.emit(*domain_override->srv_override());
            });
            logger().debug("Using domain_override at {}", domain_override->domain());
            return m_srv_pending;
        }
    }
    if (base_domain.empty()) {
        Router::defer([this]() {
            DNS::Srv r;
            r.error = "Empty Domain - DNS aborted";
            m_srv_pending.emit(r);
        });
    } else if (m_domain.transport_type() == X2X) {
        Router::defer([this]() {
            DNS::Srv r;
            r.error = "X2X - DNS aborted";
            m_srv_pending.emit(r);
        });
    } else {
        DNS::Resolver::SrvLookup(base_domain);
    }
    return m_srv_pending;
}

DNS::Resolver::svcb_callback_t &Config::Resolver::SvcbLookup(std::string const &base_domain) {
    std::string domain = DNS::Utils::toASCII("_xmpp-server." + base_domain + ".");
    m_logger->debug("SVCB lookup: domain=[{}]", base_domain);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (domain_override->svcb_override()) {
            logger().debug("Found domain_override at {}", domain_override->domain());
            Router::defer([domain_override, this]() {
                m_svcb_pending.emit(*domain_override->svcb_override());
            });
            logger().debug("Using domain_override at {}", domain_override->domain());
            return m_svcb_pending;
        }
    }
    if (base_domain.empty()) {
        Router::defer([this]() {
            DNS::Svcb r;
            r.error = "Empty Domain - DNS aborted";
            m_svcb_pending.emit(r);
        });
    } else if (m_domain.transport_type() == X2X) {
        Router::defer([this]() {
            DNS::Svcb r;
            r.error = "X2X - DNS aborted";
            m_svcb_pending.emit(r);
        });
    } else {
        DNS::Resolver::SvcbLookup(base_domain);
    }
    return m_svcb_pending;
}

DNS::Resolver::tlsa_callback_t &Config::Resolver::TlsaLookup(unsigned short port, std::string const &base_domain) {
    std::ostringstream out;
    out << "_" << port << "._tcp." << base_domain;
    std::string domain = DNS::Utils::toASCII(out.str());
    logger().info("TLSA lookup for domain=[{}]", domain);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (!domain_override->tlsa_overrides().empty()) {
            logger().debug("Found overrides at {}", domain_override->domain());
            auto it = domain_override->tlsa_overrides().find(domain);
            if (it != domain_override->tlsa_overrides().end()) {
                auto addr = it->second.get();
                Router::defer([addr, this]() {
                    m_tlsa_pending[addr->domain].emit(*addr);
                });
                logger().debug("Using domain_override at [{}]", domain_override->domain());
                return m_tlsa_pending[domain];
            }
        }
    }
    if (m_domain.transport_type() == X2X) {
        auto &cb = m_tlsa_pending[domain];
        Router::defer([&cb]() {
            DNS::Tlsa r;
            r.error = "X2X - DNS aborted";
            cb.emit(r);
        });
    } else {
        DNS::Resolver::TlsaLookup(port, base_domain);
    }
    return m_tlsa_pending[domain];
}
