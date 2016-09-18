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
#include <router.h>
#include <unbound.h>
#include <sstream>
#include <base64.h>

#include "log.h"
#include <rapidxml_print.hpp>
#include <http.h>
#include <iomanip>

using namespace Metre;
using namespace rapidxml;

namespace {
    std::string const any_element = "any";
    std::string const xmlns = "http://surevine.com/xmlns/metre/config";
    std::string const root_name = "config";

    bool xmlbool(const char *val) {
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

    std::unique_ptr<Config::Domain> parse_domain(Config::Domain const *any, xml_node<> *domain, SESSION_TYPE def) {
        std::string name;
        bool forward = (def == INT || def == COMP);
        SESSION_TYPE sess = def;
        bool tls_required = true;
        bool block = false;
        bool auth_pkix = (def == S2S);
        bool auth_dialback = false;
        bool dnssec_required = false;
        bool auth_pkix_crls = Config::config().fetch_pkix_status();
        int stanza_timeout = 10;
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
            auth_pkix_crls = any->auth_pkix_status();
            stanza_timeout = any->stanza_timeout();
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
                    forward = true;
                } else if (type == "internal") {
                    sess = INT;
                    tls_required = true;
                    forward = true;
                } else {
                    throw std::runtime_error("Unknown transport type");
                }
            }
            auto tls_a = transport->first_attribute("sec");
            if (tls_a) {
                tls_required = xmlbool(tls_a->value());
            }
            auto forward_a = domain->first_attribute("forward");
            if (forward_a) {
                forward = xmlbool(forward_a->value());
            }
            auto timeout_a = domain->first_attribute("forward");
            if (timeout_a && timeout_a->value()) {
                std::istringstream timeout(timeout_a->value());
                int tmp = 0;
                timeout >> tmp;
                if (tmp > 0) {
                    stanza_timeout = tmp;
                }
            }

            for (auto auth = transport->first_node("auth"); auth; auth = auth->next_sibling("auth")) {
                auto type_a = auth->first_attribute("type");
                if (type_a) {
                    std::string type = type_a->value();
                    if (type == "pkix") {
                        auth_pkix = true;
                        auto crl = auth->first_node("check-status");
                        if (crl && crl->value()) {
                            auth_pkix_crls = xmlbool(crl->value());
                            if (auth_pkix_crls && !Config::config().fetch_pkix_status())
                                throw std::runtime_error("Cannot check status without fetching status.");
                        }
                    } else if (type == "dialback") {
                        auth_dialback = true;
                    } else if (type == "secret") {
                        auth_secret.emplace(auth->value(), auth->value_size());
                    } else {
                        throw std::runtime_error("Unknown authentication type");
                    }
                }
            }
        }
        std::unique_ptr<Config::Domain> dom(
                new Config::Domain(name, sess, forward, tls_required, block, auth_pkix, auth_dialback,
                                   std::move(auth_secret)));
        dom->auth_pkix_status(auth_pkix_crls);
        dom->stanza_timeout(stanza_timeout);
        auto x509t = domain->first_node("x509");
        if (x509t) {
            auto chain_a = x509t->first_attribute("chain");
            if (chain_a) {
                std::string chain = chain_a->value();
                auto pkey_a = x509t->first_attribute("pkey");
                if (pkey_a) {
                    std::string pkey = pkey_a->value();
                    dom->x509(chain, pkey);
                } else {
                    throw std::runtime_error("Missing pkey for x509");
                }
            } else {
                throw std::runtime_error("Missing chain for x509");
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
                dnssec_required = xmlbool(dnssec->value());
            }
            for (auto hostt = dnst->first_node("host"); hostt; hostt = hostt->next_sibling("host")) {
                auto hosta = hostt->first_attribute("name");
                if (!hosta || !hosta->value()) throw std::runtime_error("Missing name in host DNS override");
                std::string host = hosta->value();
                auto aa = hostt->first_attribute("a");
                if (!aa || !aa->value()) throw std::runtime_error("Missing a in host DNS override");
                struct in_addr ina;
                if (inet_aton(aa->value(), &ina)) {
                    dom->host(host, ina.s_addr);
                }
            }
            for (auto srvt = dnst->first_node("srv"); srvt; srvt = srvt->next_sibling("srv")) {
                auto hosta = srvt->first_attribute("host");
                if (!hosta || !hosta->value()) throw std::runtime_error("Missing host in SRV DNS override");
                std::string host = hosta->value();
                auto porta = srvt->first_attribute("port");
                if (porta && porta->value()) {
                    std::istringstream ports(porta->value());
                    unsigned short port;
                    ports >> port;
                    dom->srv(host, 0, 0, port);
                }
            }
            for (auto tlsa = dnst->first_node("tlsa"); tlsa; tlsa = tlsa->next_sibling("tlsa")) {
                auto hosta = tlsa->first_attribute("hostname");
                if (!hosta || !hosta->value()) throw std::runtime_error("Missing hostname in TLSA DNS override");
                std::string host = hosta->value();
                auto porta = tlsa->first_attribute("port");
                if (!porta || !porta->value()) throw std::runtime_error("Missing port in TLSA DNS override");
                std::istringstream ports(porta->value());
                unsigned short port;
                ports >> port;
                auto certusagea = tlsa->first_attribute("certusage");
                if (!certusagea || !certusagea->value()) throw std::runtime_error("Missing certusage in TLSA DNS override");
                DNS::TlsaRR::CertUsage certUsage;
                std::string certusages = certusagea->value();
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
                auto matchtypea = tlsa->first_attribute("matchtype");
                DNS::TlsaRR::MatchType matchType = DNS::TlsaRR::Full;
                if (matchtypea && matchtypea->value()) {
                    std::string matchtypes = matchtypea->value();
                    if (matchtypes == "Full") {
                        matchType = DNS::TlsaRR::Full;
                    } else if (matchtypes == "Sha256") {
                        matchType = DNS::TlsaRR::Sha256;
                    } else if (matchtypes == "Sha512") {
                        matchType = DNS::TlsaRR::Sha512;
                    } else {
                        throw std::runtime_error("Unknown matchtype in TLSA DNS override");
                    }
                }
                auto selectora = tlsa->first_attribute("selector");
                DNS::TlsaRR::Selector selector = DNS::TlsaRR::FullCert;
                if (selectora && selectora->value()) {
                    std::string sel = selectora->value();
                    if (sel == "FullCert") {
                        selector = DNS::TlsaRR::FullCert;
                    } else if (sel == "SubjectPublicKeyInfo") {
                        selector = DNS::TlsaRR::SubjectPublicKeyInfo;
                    } else {
                        throw std::runtime_error("Unknown selector in TLSA DNS override");
                    }
                }
                dom->tlsa(host, port, certUsage, selector, matchType, tlsa->value());
            }
        }
        dom->dnssec_required(dnssec_required);
        return dom;
    }

    Config *s_config = nullptr;

    bool openssl_init = false;
}

Config::Domain::Domain(std::string const &domain, SESSION_TYPE transport_type, bool forward, bool require_tls,
                       bool block, bool auth_pkix, bool auth_dialback, std::optional<std::string> &&auth_secret)
        : m_domain(domain), m_type(transport_type), m_forward(forward), m_require_tls(require_tls), m_block(block),
          m_auth_pkix(auth_pkix), m_auth_dialback(auth_dialback), m_auth_secret(auth_secret), m_ssl_ctx(nullptr) {
}

Config::Domain::Domain(Config::Domain const &any, std::string const &domain)
        : m_domain(domain), m_type(any.m_type), m_forward(any.m_forward), m_require_tls(any.m_require_tls),
          m_block(any.m_block), m_auth_pkix(any.m_auth_pkix), m_auth_crls(any.m_auth_crls),
          m_auth_dialback(any.m_auth_dialback), m_dnssec_required(any.m_dnssec_required),
          m_stanza_timeout(any.m_stanza_timeout), m_dhparam(any.m_dhparam), m_cipherlist(any.m_cipherlist),
          m_ssl_ctx(nullptr) {
    m_domain = domain;
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
    address->hostname = hostname + ".";
    address->addr.emplace_back();
    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&*address->addr.rbegin());
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inaddr;
    m_host_arecs[hostname + "."] = std::move(address);
}

int Config::verify_callback_cb(int preverify_ok, struct x509_store_ctx_st *st) {
    if (!preverify_ok) {
        const int name_sz = 256;
        std::string cert_name;
        cert_name.resize(name_sz);
        X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)),
                          const_cast<char *>(cert_name.data()), name_sz);
        cert_name.resize(cert_name.find('\0'));
        METRE_LOG(Metre::Log::INFO, "Cert failed basic verification: " + cert_name);
        METRE_LOG(Metre::Log::INFO,
                  std::string("Error is ") + X509_verify_cert_error_string(X509_STORE_CTX_get_error(st)));
    } else {
        const int name_sz = 256;
        std::string cert_name;
        cert_name.resize(name_sz);
        X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(st)),
                          const_cast<char *>(cert_name.data()), name_sz);
        cert_name.resize(cert_name.find('\0'));
        METRE_LOG(Metre::Log::DEBUG, "Cert passed basic verification: " + cert_name);
        if (Config::config().m_fetch_crls) {
            auto crldp = X509_STORE_CTX_get_current_cert(st)->crldp;
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
                                METRE_LOG(Metre::Log::INFO, "Fetching CRL for " << cert_name << " - " << uristr);
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
    m_ssl_ctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_ALL);
    SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, Config::verify_callback_cb);
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

Config::Config(std::string const &filename) : m_config_str(), m_dialback_secret(random_identifier()) {
    s_config = this;
    load(filename);
    std::string tmp = asString();
    std::ofstream of(m_data_dir + "/" + "metre.running.xml", std::ios_base::trunc);
    of << tmp;
    m_ub_ctx = ub_ctx_create();
    if (!m_ub_ctx) {
        throw std::runtime_error("DNS context creation failure.");
    }
    int retval;
    if ((retval = ub_ctx_resolvconf(m_ub_ctx, NULL)) != 0) {
        throw std::runtime_error(ub_strerror(retval));
    }
    if (!m_dns_keys.empty()) {
        if ((retval = ub_ctx_add_ta_file(m_ub_ctx, m_dns_keys.c_str())) != 0) {
            throw std::runtime_error(ub_strerror(retval));
        }
    }
}

Config::~Config() {
    ub_ctx_delete(m_ub_ctx);
}

void Config::load(std::string const &filename) {
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
        auto rundir = globals->first_node("rundir");
        if (rundir && rundir->value()) {
            m_runtime_dir = rundir->value();
        }
        auto logfile = globals->first_node("logfile");
        if (logfile && logfile->value()) {
            m_logfile = logfile->value();
        }
        auto bootm = globals->first_node("boot_method");
        if (bootm && bootm->value()) {
            m_boot = bootm->value();
        }
        auto datadir = globals->first_node("datadir");
        if (datadir && datadir->value()) {
            m_data_dir = datadir->value();
        }
        auto dns_keys = globals->first_node("dnssec");
        if (dns_keys && dns_keys->value()) {
            m_dns_keys = dns_keys->value();
        }
        auto crls = globals->first_node("fetch-crls");
        if (crls && crls->value()) {
            m_fetch_crls = xmlbool(crls->value());
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
        m_domains[""] = std::unique_ptr<Config::Domain>(
                new Config::Domain("", INT, false, true, true, true, true, std::optional<std::string>()));
    }
}

std::string Config::asString() {
    xml_document<> doc;
    auto root = doc.allocate_node(node_element, root_name.c_str());
    root->append_attribute(doc.allocate_attribute("xmlns", xmlns.c_str()));
    {
        root->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        auto globals = doc.allocate_node(node_element, "globals");

        {
            if (m_default_domain.empty()) {
                globals->append_node(
                        doc.allocate_node(node_comment, nullptr, "<domain name='default.domain.example'/>"));
            } else {
                auto domain = doc.allocate_node(node_element, "domain");
                domain->append_attribute(doc.allocate_attribute("name", m_default_domain.c_str()));
                globals->append_node(domain);
            }
            globals->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "Default domain. Used in extremis if no domain is present in the stream header."));
            globals->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        }

        auto global = [&] (const char * elname, std::string const & val, const char * comment) {
            globals->append_node(doc.allocate_node(node_element, elname, val.c_str()));
            globals->append_node(doc.allocate_node(node_comment, nullptr, comment));
            globals->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        };

        global("rundir", m_runtime_dir, "Runtime directory, used to store pid file.");
        global("datadir", m_data_dir, "Data directory, used only for the running config.");
        global("logfile", m_logfile, "Logfile path.");
        global("dnssec", m_dns_keys, "DNSSEC root keys file.");
        global("boot_method", m_boot, "Boot method - none, fork, or systemd");
        global("fetch-crls", m_fetch_crls ? "true" : "false",
               "Controls if CRLs are fetched - MUST be on for status checking!");
        global("dnssec", m_dns_keys, "DNS key file - obtain this from IANA");

        root->append_node(globals);
    }
    {
        root->append_node(doc.allocate_node(node_data, nullptr, "\n"));
        auto domains = doc.allocate_node(node_element, "remote");
        domains->append_node(doc.allocate_node(node_comment, nullptr, "All domains, internal and external, are listed here.\nNote that this will include all settings, including defaults.\n"));
        domains->append_node(doc.allocate_node(node_data, nullptr, "\n"));

        auto dout = [&](Config::Domain const & dom) {
            auto d = doc.allocate_node(node_element, dom.domain().empty() ? "any" : "domain");
            if (!dom.domain().empty()) {
                d->append_attribute(doc.allocate_attribute("name", dom.domain().c_str()));
                d->append_attribute(doc.allocate_attribute("forward", dom.forward() ? "true" : "false"));
                d->append_attribute(doc.allocate_attribute("sec", dom.require_tls() ? "true" : "false"));
                std::ostringstream os;
                os << dom.stanza_timeout();
                d->append_attribute(doc.allocate_attribute("timeout", doc.allocate_string(os.str().c_str())));
                d->append_node(doc.allocate_node(node_comment, nullptr, "A remote domain. Forwarded domains are proxied through to non-forwarded domains."));
                d->append_node(doc.allocate_node(node_comment, nullptr,
                                                 "A 'sec' attribute set to true mandates a secured connection (usually TLS)."));
            }
            {
                auto transport = doc.allocate_node(node_element, "transport");
                const char *tt;
                switch (dom.transport_type()) {
                    case INT:
                        tt = "internal";
                        break;
                    case S2S:
                        tt = "s2s";
                        break;
                    case COMP:
                        tt = "114";
                        break;
                    default:
                        return;
                }
                transport->append_attribute(doc.allocate_attribute("type", tt));
                transport->append_attribute(doc.allocate_attribute("sec", dom.require_tls() ? "true" : "false"));
                if (dom.auth_pkix()) {
                    auto auth = doc.allocate_node(node_element, "auth");
                    auth->append_attribute(doc.allocate_attribute("type", "pkix"));
                    auth->append_node(
                            doc.allocate_node(node_element, "check-status", dom.m_auth_crls ? "true" : "false"));
                    transport->append_node(auth);
                }
                if (dom.auth_dialback()) {
                    auto auth = doc.allocate_node(node_element, "auth");
                    auth->append_attribute(doc.allocate_attribute("type", "dialback"));
                    transport->append_node(auth);
                }
                if (dom.auth_secret()) {
                    auto auth = doc.allocate_node(node_element, "auth", dom.auth_secret().value().c_str());
                    auth->append_attribute(doc.allocate_attribute("type", "secret"));
                    transport->append_node(auth);
                }
                d->append_node(transport);
            }
            {
                auto dns = doc.allocate_node(node_element, "dns");
                dns->append_attribute(doc.allocate_attribute("dnssec", dom.dnssec_required() ? "true" : "false"));
                dns->append_node(
                        doc.allocate_node(node_comment, nullptr,
                                          "DNS overrides are always treated as if signed with DNSSEC."));
                for (auto &srv : dom.m_srvrecs) {
                    for (auto &rr : srv.second->rrs) {
                        auto s = doc.allocate_node(node_element, "srv");
                        s->append_attribute(doc.allocate_attribute("host", rr.hostname.c_str()));
                        std::ostringstream ss;
                        ss << rr.port;
                        s->append_attribute(doc.allocate_attribute("port", doc.allocate_string(ss.str().data())));
                        dns->append_node(s);
                    }
                }
                dns->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "<srv host='hostname to connect to' port='port number'/>"));
                for (auto & tlsa : dom.tlsa()) {
                    for (auto &rr : tlsa.rrs) {
                        std::stringstream ss(tlsa.domain);
                        unsigned short int port = 0;
                        std::string hostname;
                        char underscore;
                        ss >> underscore >> port >> hostname;
                        std::ostringstream ssout;
                        ssout << port;
                        auto e = doc.allocate_node(node_element, "tlsa");
                        e->append_attribute(
                                doc.allocate_attribute("hostname", doc.allocate_string(hostname.c_str() + 6)));
                        e->append_attribute(doc.allocate_attribute("port", doc.allocate_string(ssout.str().c_str())));
                        const char *match = "Full";
                        switch (rr.matchType) {
                            case DNS::TlsaRR::Full:
                                match = "Full";
                                break;
                            case DNS::TlsaRR::Sha256:
                                match = "Sha256";
                                break;
                            case DNS::TlsaRR::Sha512:
                                match = "Sha512";
                                break;
                        }
                        e->append_attribute(doc.allocate_attribute("matchtype", match));
                        const char *selector;
                        switch (rr.selector) {
                            case DNS::TlsaRR::FullCert:
                                selector = "FullCert";
                                break;
                            case DNS::TlsaRR::SubjectPublicKeyInfo:
                                selector = "SubjectPublicKeyInfo";
                                break;
                        }
                        e->append_attribute(doc.allocate_attribute("selector", selector));
                        const char *certUsage;
                        switch (rr.certUsage) {
                            case DNS::TlsaRR::CAConstraint:
                                certUsage = "CAConstraint";
                                break;
                            case DNS::TlsaRR::CertConstraint:
                                certUsage = "CertConstraint";
                                break;
                            case DNS::TlsaRR::DomainCert:
                                certUsage = "DomainCert";
                                break;
                            case DNS::TlsaRR::TrustAnchorAssertion:
                                certUsage = "TrustAnchorAssertion";
                                break;
                        }
                        e->append_attribute(doc.allocate_attribute("certusage", certUsage));
                        if (rr.matchType == DNS::TlsaRR::Full) {
                            // Base64 data (it might have come from a file, but never mind).
                            e->value(doc.allocate_string(base64_encode(rr.matchData).c_str()));
                        } else {
                            std::ostringstream os;
                            os << std::hex << std::setfill('0') << std::setw(2);
                            bool colon = false;
                            for (char c : rr.matchData) {
                                unsigned char byte = static_cast<unsigned char>(c);
                                if (!colon) {
                                    colon = true;
                                } else {
                                    os << ':';
                                }
                                os << byte;
                            }
                            e->value(doc.allocate_string(os.str().c_str()));
                        }
                        dns->append_node(e);
                    }
                }
                dns->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "<tlsa host='nominal hostname [ignored]' port='nominal port number [ignored]' certusage='CAConstraint|CertConstraint|DomainCert|TrustAnchorAssertion' selector='FullCert|SubjectPublicKeyInfo' matchtype='Full|Sha256|Sha512'>Value</tsla>"));
                dns->append_node(doc.allocate_node(node_comment, nullptr,
                                                   "Value should be hex hash for hash matchtypes, or a filename (no return character, at least one '/') or base64 DER (PEM without headers)"));
                for (auto const &h : dom.m_host_arecs) {
                    auto host = doc.allocate_node(node_element, "host");
                    host->append_attribute(doc.allocate_attribute("name", h.first.c_str()));
                    char buf[32];
                    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(h.second->addr.data());
                    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                    host->append_attribute(doc.allocate_attribute("a", doc.allocate_string(buf)));
                    dns->append_node(host);
                }
                dns->append_node(
                        doc.allocate_node(node_comment, nullptr, "<host name='name.example' a='123.45.67.89'/>"));
                d->append_node(dns);
            }
            {
                auto x509 = doc.allocate_node(node_element, "x509");
                std::string prefix;
                if (dom.domain().empty()) {
                    prefix = "any_";
                } else {
                    prefix = dom.domain() + "_";
                }
                STACK_OF(X509) * chain = nullptr;
                std::string chainfile = m_data_dir + "/" + prefix + "chain.pem";
                FILE * fp = fopen(chainfile.c_str(), "w");
                if (0 == SSL_CTX_get0_chain_certs(dom.ssl_ctx(), &chain)) {
                    for (int i = 0; i != sk_X509_num(chain); ++i) {
                        X509 * item = sk_X509_value(chain, i);
                        PEM_write_X509(fp, item);
                    }
                }
                fclose(fp);
                x509->append_attribute(doc.allocate_attribute("chain", doc.allocate_string(chainfile.c_str())));
                std::string keyfile = m_data_dir + "/" + prefix + "key.pem";
                fp = fopen(keyfile.c_str(), "w");
                PEM_write_PKCS8PrivateKey(fp, SSL_CTX_get0_privatekey(dom.ssl_ctx()), nullptr, nullptr, 0, nullptr, nullptr);
                fclose(fp);
                x509->append_attribute(doc.allocate_attribute("pkey", doc.allocate_string(keyfile.c_str())));
                d->append_node(x509);
                d->append_node(doc.allocate_node(node_comment, nullptr, "The x509 element provides a chainfile and private key to use as the local identity when acting as this domain."));
            }
            {
                auto dhp = doc.allocate_node(node_element, "dhparam");
                dhp->append_attribute(doc.allocate_attribute("size", dom.dhparam().c_str()));
                d->append_node(dhp);
                d->append_node(doc.allocate_node(node_comment, nullptr, "Provides the size of the DH keys used for Perfect Forward Secrecy - 1024, 2048, or 4096."));
            }
            d->append_node(doc.allocate_node(node_element, "ciphers", dom.cipherlist().c_str()));
            d->append_node(doc.allocate_node(node_comment, nullptr, "This is a normal OpenSSL cipher string."));
            domains->append_node(d);
        };
        for (auto & p : m_domains) {
            dout(*(p.second));
        }
        root->append_node(domains);
    }
    doc.append_node(root);
    std::string tmp;
    rapidxml::print(std::back_inserter(tmp), doc);
    return tmp;
}

void Config::log_init(bool systemd) {
    if (!systemd && m_logfile.empty()) {
        m_logfile = "/var/log/metre/metre.log";
    }
    m_log.reset(new Metre::Log(m_logfile));
}

Config::Domain const &Config::domain(std::string const &dom) const {
    auto it = m_domains.find(dom);
    if (it == m_domains.end()) {
        it = m_domains.find("");
        std::unique_ptr<Config::Domain> newdom{new Config::Domain(*(*it).second, dom)};
        std::tie(it, std::ignore) = const_cast<Config *>(this)->m_domains.insert(
                std::make_pair(dom, std::move(newdom)));
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
    return std::move(id);
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
    METRE_LOG(Metre::Log::DEBUG, "Dialback key id " << id << " ::  " << local_domain << " | " << remote_domain);
    return hexoutput;
}

Config const &Config::config() {
    return *s_config;
}


/*
 * DNS resolver functions.
 */

namespace {
    class UBResult {
        /* Quick guard class. */
    public:
        struct ub_result *result;

        UBResult(struct ub_result *r) : result(r) {}

        ~UBResult() { ub_resolve_free(result); }
    };

    void srv_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        reinterpret_cast<Config::Domain *>(x)->srv_lookup_done(err, result);
    }

    void a_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        reinterpret_cast<Config::Domain *>(x)->a_lookup_done(err, result);
    }

    void tlsa_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        reinterpret_cast<Config::Domain *>(x)->tlsa_lookup_done(err, result);
    }
}

void Config::Domain::tlsa(std::string const &hostname, unsigned short port, DNS::TlsaRR::CertUsage certUsage,
                          DNS::TlsaRR::Selector selector, DNS::TlsaRR::MatchType matchType, std::string const &value) {
    std::ostringstream out;
    out << "_" << port << "._tcp." << hostname;
    std::string domain = out.str();
    auto tlsait = m_tlsarecs.find(domain);
    DNS::Tlsa *tlsa;
    if (tlsait == m_tlsarecs.end()) {
        std::unique_ptr<DNS::Tlsa> tlsan(new DNS::Tlsa);
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
        default: {
            bool read_ok = false;
            if (value.find('\n') == std::string::npos && value.find('/') != std::string::npos) {
                std::ifstream in(value);
                rr.matchData.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                if (!rr.matchData.empty()) {
                    read_ok = true;
                }
            }
            if (!read_ok) {
                rr.matchData = base64_decode(value);
            }
        }
    }
    tlsa->rrs.push_back(rr);
}

std::vector<DNS::Tlsa> const &Config::Domain::tlsa() const {
    if (m_tlsa_all.empty()) {
        for (auto &item : m_tlsarecs) {
            m_tlsa_all.push_back(*item.second);
        }
    }
    return m_tlsa_all;
}

void Config::Domain::tlsa_lookup_done(int err, struct ub_result *result) {
    std::string error;
    if (err != 0) {
        error = ub_strerror(err);
    } else if (!result->havedata) {
        error = "No TLSA records present";
    } else if (result->bogus) {
        error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        error = "DNSSEC required but unsigned";
    } else {
        DNS::Tlsa tlsa;
        tlsa.dnssec = !!result->secure;
        tlsa.domain = result->qname;
        for (int i = 0; result->data[i]; ++i) {
            DNS::TlsaRR rr;
            rr.certUsage = static_cast<DNS::TlsaRR::CertUsage>(result->data[i][0]);
            rr.selector = static_cast<DNS::TlsaRR::Selector>(result->data[i][1]);
            rr.matchType = static_cast<DNS::TlsaRR::MatchType>(result->data[i][2]);
            rr.matchData.assign(result->data[i] + 3, result->len[i] - 3);
            tlsa.rrs.push_back(rr);
            METRE_LOG(Metre::Log::DEBUG, "Data[" << i << "]: (" << result->len[i] << " bytes) "
                                                 << rr.certUsage << ":"
                                                 << rr.selector << ":"
                                                 << rr.matchType << "::"
                                                 << rr.matchData);
        }
        m_tlsa_pending.emit(&tlsa);
        return;
    }
    METRE_LOG(Metre::Log::DEBUG, "DNS Error: " << error);
    DNS::Tlsa tlsa;
    tlsa.error = error;
    tlsa.domain = result->qname;
    m_tlsa_pending.emit(&tlsa);
    m_tlsa_pending.disconnect_all();
}

void
Config::Domain::srv(std::string const &hostname, unsigned short priority, unsigned short weight, unsigned short port) {
    DNS::Srv *srv;
    std::string domain = "_xmpp-server._tcp." + m_domain + ".";
    auto it = m_srvrecs.find(domain);
    if (it == m_srvrecs.end()) {
        std::unique_ptr<DNS::Srv> s(new DNS::Srv);
        s->dnssec = true;
        s->domain = domain;
        srv = &*s;
        m_srvrecs[domain] = std::move(s);
    } else {
        srv = &*(it->second);
    }
    DNS::SrvRR rr;
    rr.priority = priority;
    rr.weight = weight;
    rr.port = port;
    rr.hostname = hostname;
    srv->rrs.push_back(rr);
}

void Config::Domain::srv_lookup_done(int err, struct ub_result *result) {
    std::string error;
    std::map<unsigned short, unsigned short> weights;
    if (err != 0) {
        error = ub_strerror(err);
    } else if (!result->havedata) {
        error = "No SRV records present";
    } else if (result->bogus) {
        error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        error = "DNSSEC required but unsigned";
    } else {
        DNS::Srv &srv = m_current_srv;
        bool xmpps = false;
        srv.dnssec = !!result->secure;
        srv.domain = result->qname;
        if (srv.domain.find("_xmpps") == 0) {
            xmpps = true;
            srv.xmpps = true;
        } else {
            srv.xmpp = true;
        }
        for (int i = 0; result->data[i]; ++i) {
            DNS::SrvRR rr;
            rr.priority = ntohs(*reinterpret_cast<unsigned short *>(result->data[i]));
            rr.weight = ntohs(*reinterpret_cast<unsigned short *>(result->data[i] + 2));
            rr.port = ntohs(*reinterpret_cast<unsigned short *>(result->data[i] + 4));
            rr.tls = xmpps;
            for (int x = 6; result->data[i][x]; x += result->data[i][x] + 1) {
                rr.hostname.append(result->data[i] + x + 1, result->data[i][x]);
                rr.hostname += ".";
            }
            weights[rr.priority] += rr.weight;
            rr.weight = weights[rr.priority];
            srv.rrs.push_back(rr);
            METRE_LOG(Metre::Log::DEBUG, "Data[" << i << "]: (" << result->len[i] << " bytes) "
                                                 << rr.priority << ":"
                                                 << rr.weight << ":"
                                                 << rr.port << "::"
                                                 << rr.hostname);
        }
        if (srv.xmpp && srv.xmpps) {
            m_srv_pending.emit(&srv);
            m_srv_pending.disconnect_all();
        }
        return;
    }
    METRE_LOG(Metre::Log::DEBUG, "DNS Error: " << error);
    if (m_current_srv.xmpp || m_current_srv.xmpps) {
        if (m_current_srv.rrs.empty()) {
            DNS::Srv srv;
            srv.error = error;
            srv.domain = result->qname;
            m_srv_pending.emit(&srv);
            m_srv_pending.disconnect_all();
        } else {
            m_srv_pending.emit(&m_current_srv);
            m_srv_pending.disconnect_all();
        }
    }
}

void Config::Domain::a_lookup_done(int err, struct ub_result *result) {
    std::string error;
    if (err != 0) {
        error = ub_strerror(err);
    } else if (!result->havedata) {
        error = "No A records present";
    } else if (result->bogus) {
        error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        error = "DNSSEC required but unsigned";
    } else {
        DNS::Address &a = m_current_arec;
        if (a.hostname != result->qname) {
            a.error = "";
            a.dnssec = !!result->secure;
            a.hostname = result->qname;
            a.addr.clear();
            a.ipv4 = a.ipv6 = false;
        } else {
            a.dnssec = a.dnssec && !!result->secure;
        }
        if (result->qtype == 1) {
            m_current_arec.ipv4 = true;
            for (int i = 0; result->data[i]; ++i) {
                a.addr.emplace_back();
                struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&*a.addr.rbegin());
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = *reinterpret_cast<in_addr_t *>(result->data[i]);
            }
        } else if (result->qtype == 28) {
            m_current_arec.ipv6 = true;
            for (int i = 0; result->data[i]; ++i) {
                a.addr.emplace(a.addr.begin());
                struct sockaddr_in6 *sin = reinterpret_cast<struct sockaddr_in6 *>(&*a.addr.begin());
                sin->sin6_family = AF_INET6;
                memcpy(sin->sin6_addr.__in6_u.__u6_addr8, result->data[i], 16);
            }
        }
        if (m_current_arec.ipv4 && m_current_arec.ipv6) {
            m_a_pending.emit(&a);
            m_a_pending.disconnect_all();
        }
        return;
    }
    if (m_current_arec.ipv4 || m_current_arec.ipv6) {
        if (m_current_arec.addr.empty()) {
            DNS::Address a;
            a.error = error;
            a.hostname = result->qname;
            m_a_pending.emit(&a);
            m_a_pending.disconnect_all();
        } else {
            m_a_pending.emit(&m_current_arec);
            m_a_pending.disconnect_all();
        }
    }
}

Config::addr_callback_t &Config::Domain::AddressLookup(std::string const &hostname) const {
    METRE_LOG(Metre::Log::DEBUG, "A/AAAA lookup for " << hostname << " context:" << m_domain);
    auto it = m_host_arecs.find(hostname);
    if (it != m_host_arecs.end()) {
        auto addr = &*(it->second);
        Router::defer([addr, this]() {
            m_a_pending.emit(addr);
        });
        METRE_LOG(Metre::Log::DEBUG, "Using DNS override");
    } else {
        m_current_arec.hostname = "";
        ub_resolve_async(Config::config().ub_ctx(), hostname.c_str(), 28, 1,
                         const_cast<void *>(reinterpret_cast<const void *>(this)), a_lookup_done_cb, NULL);
        ub_resolve_async(Config::config().ub_ctx(),
                         hostname.c_str(),
                         1, /* A */
                         1,  /* IN */
                         const_cast<void *>(reinterpret_cast<const void *>(this)),
                         a_lookup_done_cb,
                         NULL); /* int * async_id */
    }
    return m_a_pending;
}

Config::srv_callback_t &Config::Domain::SrvLookup(std::string const &base_domain) const {
    std::string domain = "_xmpp-server._tcp." + base_domain + ".";
    std::string domains = "_xmpps-server._tcp." + base_domain + ".";
    METRE_LOG(Metre::Log::DEBUG, "SRV lookup for " << domain << " context:" << m_domain);
    auto it = m_srvrecs.find(domain);
    if (it != m_srvrecs.end()) {
        auto addr = &*(it->second);
        Router::defer([addr, this]() {
            m_srv_pending.emit(addr);
        });
        METRE_LOG(Metre::Log::DEBUG, "Using DNS override");
    } else {
        m_current_srv.xmpp = m_current_srv.xmpps = false;
        ub_resolve_async(Config::config().ub_ctx(),
                         domain.c_str(),
                         33, /* SRV */
                         1,  /* IN */
                         const_cast<void *>(reinterpret_cast<const void *>(this)),
                         srv_lookup_done_cb,
                         NULL); /* int * async_id */
        ub_resolve_async(Config::config().ub_ctx(),
                         domains.c_str(),
                         33, /* SRV */
                         1,  /* IN */
                         const_cast<void *>(reinterpret_cast<const void *>(this)),
                         srv_lookup_done_cb,
                         NULL); /* int * async_id */
    }
    return m_srv_pending;
}

Config::tlsa_callback_t &Config::Domain::TlsaLookup(unsigned short port, std::string const &base_domain) const {
    std::ostringstream out;
    out << "_" << port << "._tcp." << base_domain;
    std::string domain = out.str();
    METRE_LOG(Metre::Log::DEBUG, "TLSA lookup for " << domain);
    auto it = m_tlsarecs.find(domain);
    if (it != m_tlsarecs.end()) {
        auto addr = &*(it->second);
        Router::defer([addr, this]() {
            m_tlsa_pending.emit(addr);
        });
        METRE_LOG(Metre::Log::DEBUG, "Using DNS override");
    } else {
        ub_resolve_async(Config::config().ub_ctx(),
                         domain.c_str(),
                         52, /* TLSA */
                         1,  /* IN */
                         const_cast<void *>(reinterpret_cast<const void *>(this)),
                         tlsa_lookup_done_cb,
                         NULL); /* int * async_id */
    }
    return m_tlsa_pending;
}
