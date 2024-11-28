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
#include <covent/dns.h>
#include <router.h>
#include <sstream>
#include <base64.h>
#include <xmlstream.h>

#include "log.h"
#include <covent/sockaddr-cast.h>
#include <covent/gather.h>
#include <iomanip>
#include <filter.h>
#include <cstring>
#include <utility>
#include <yaml-cpp/yaml.h>

using namespace Metre;
using namespace rapidxml;

namespace {
    std::unique_ptr<Config::Domain> parse_domain(Config::Domain const *any, std::string const & domain_name, YAML::Node const & domain, bool external) {
        std::string name;
        bool forward = !external;
        SESSION_TYPE sess = SESSION_TYPE::S2S;
        bool tls_required = external;
        bool xmpp_ver = true;
        bool block = false;
        bool multiplex = true;
        bool auth_pkix = true;
        bool auth_dialback = !external;
        bool dnssec_required = false;
        bool auth_host = false;
        TLS_PREFERENCE tls_preference = TLS_PREFERENCE::PREFER_ANY;
        unsigned int stanza_timeout = 20;
        unsigned int connect_timeout = 10;
        std::optional<std::string> auth_secret;
        if (any) {
            auth_pkix = any->auth_pkix();
            auth_dialback = any->auth_dialback();
            tls_required = tls_required && any->require_tls();
            tls_preference = any->tls_preference();
            xmpp_ver = any->xmpp_ver();
            dnssec_required = any->dnssec_required();
            stanza_timeout = any->stanza_timeout();
            connect_timeout = any->connect_timeout();
        }
        if (domain_name == "any") {
            name = "";
        } else {
            name = Jid(domain_name).domain(); // This stringpreps.
        }
        block = domain["block"].as<bool>(block);
        if (domain["transport"]) {
            if (auto type = domain["transport"]["type"].as<std::string>("s2s"); type == "s2s") {
                sess = SESSION_TYPE::S2S;
            } else if (type == "x2x") {
                sess = SESSION_TYPE::X2X;
            } else if (type == "114") {
                sess = SESSION_TYPE::COMP;
                tls_required = false;
                forward = true;
            } else if (type == "internal") {
                sess = SESSION_TYPE::INTERNAL;
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
                auto tls_pref_str = domain["transport"]["prefer"].as<std::string>();
                if (tls_pref_str == "immediate" || tls_pref_str == "direct") {
                    tls_preference = TLS_PREFERENCE::PREFER_IMMEDIATE;
                } else if (tls_pref_str == "starttls") {
                    tls_preference = TLS_PREFERENCE::PREFER_STARTTLS;
                }
            }
            connect_timeout = domain["transport"]["connect-timeout"].as<int>(connect_timeout);
        }
        stanza_timeout = domain["stanza-timeout"].as<int>(stanza_timeout);
        forward = domain["forward"].as<bool>(forward);

        if(domain["auth"]) {
            auth_pkix = domain["auth"]["pkix"].as<bool>(auth_pkix);
            auth_dialback = domain["auth"]["dialback"].as<bool>(auth_dialback);
            if (domain["auth"]["secret"]) {
                auth_secret = domain["auth"]["secret"].as<std::string>();
            }
            auth_host = domain["auth"]["host"].as<bool>(auth_host);
            if (auth_host && sess == SESSION_TYPE::X2X) {
                dnssec_required = true;
            }
            if (!(block || auth_pkix || auth_dialback || auth_secret || auth_host)) {
                throw std::runtime_error("Cannot authenticate domain, but not blocked.");
            }
        }
        auto dom = std::make_unique<Config::Domain>(name, sess, xmpp_ver, forward, tls_required, block, multiplex, auth_pkix, auth_dialback,
                                                    auth_host, std::move(auth_secret));
        dom->stanza_timeout(stanza_timeout);
        dom->connect_timeout(connect_timeout);
        dom->tls_preference(tls_preference);
        bool validator_loaded = false;
        if (auto tls = domain["tls"]; tls) {
            if (tls["config"]) {
                dom->tls_context(std::make_unique<TLSContext>(tls["config"], name));
            } else {
                dom->tls_context(std::make_unique<TLSContext>(tls, name));
            }
            if (tls["x509"]) {
                dom->tls_context().add_identity(std::make_unique<PKIXIdentity>(tls["x509"]));
            }
            dom->tls_context().context(); // Force everything to get instantiated here.
            if (tls["validation"]) {
                dom->pkix_validator(std::make_unique<PKIXValidator>(tls["validation"]));
                dom->pkix_validator().load(); // Force loading here.
                validator_loaded = true;
            }
        }
        if (!validator_loaded) {
            YAML::Node tmp;
            if (domain["auth"]) {
                tmp["crls"] = domain["auth"]["check-status"].as<bool>(Config::config().fetch_pkix_status());
            }
            dom->pkix_validator(std::make_unique<PKIXValidator>(tmp));
        }

        if (auto dnst = domain["dns"]; dnst) {
            auto dnssec = dnst["dnssec_required"] ? dnst["dnssec_required"] : dnst["dnssec"];
            dnssec_required = dnssec.as<bool>(dnssec_required);
            for (auto hostt : dnst["host"]) {
                auto hosta = hostt["name"];
                if (!hosta) throw std::runtime_error("Missing name in host DNS override");
                auto host = hosta.as<std::string>();
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
                auto host = hosta.as<std::string>();
                auto tls = srvt["tls"].as<bool>(false);
                auto port = srvt["port"].as<unsigned short>(tls ? 5270 : 5269);
                auto weight = srvt["weight"].as<unsigned short>(0);
                auto prio = srvt["priority"].as<unsigned short>(0);
                dom->srv(host, prio, weight, port, tls);
            }
            for (auto tlsa : dnst["tlsa"]) {
                auto hosta = tlsa["hostname"];
                if (!hosta) throw std::runtime_error("Missing hostname in TLSA DNS override");
                auto host = hosta.as<std::string>();
                auto port = tlsa["port"].as<unsigned short>(5269);
                auto certusagea = tlsa["certusage"];
                if (!certusagea) throw std::runtime_error("Missing certusage in TLSA DNS override");
                using enum covent::dns::rr::TLSA::CertUsage;
                covent::dns::rr::TLSA::CertUsage certUsage;
                if (auto certusages = certusagea.as<std::string>(); certusages == "CAConstraint") {
                    certUsage = CAConstraint;
                } else if (certusages == "CertConstraint") {
                    certUsage = CertConstraint;
                } else if (certusages == "TrustAnchorAssertion") {
                    certUsage = TrustAnchorAssertion;
                } else if (certusages == "DomainCert") {
                    certUsage = DomainCert;
                } else {
                    throw std::runtime_error("Unknown certusage in TLSA DNS override");
                }
                auto matchtypes = tlsa["matchtype"].as<std::string>("Full");
                using enum covent::dns::rr::TLSA::MatchType;
                covent::dns::rr::TLSA::MatchType matchType = Full;
                if (matchtypes == "Full") {
                    matchType = Full;
                } else if (matchtypes == "Sha256") {
                    matchType = Sha256;
                } else if (matchtypes == "Sha512") {
                    matchType = Sha512;
                } else {
                    throw std::runtime_error("Unknown matchtype in TLSA DNS override");
                }
                auto sel = tlsa["selector"].as<std::string>("FullCert");
                covent::dns::rr::TLSA::Selector selector = covent::dns::rr::TLSA::Selector::FullCert;
                if (sel == "FullCert") {
                    selector = covent::dns::rr::TLSA::Selector::FullCert;
                } else if (sel == "SubjectPublicKeyInfo") {
                    selector = covent::dns::rr::TLSA::Selector::SubjectPublicKeyInfo;
                } else {
                    throw std::runtime_error("Unknown selector in TLSA DNS override");
                }
                dom->tlsa(host, port, certUsage, selector, matchType, tlsa["matchdata"].as<std::string>());
            }
        }
        dom->dnssec_required(dnssec_required);
        for (auto const & filter : domain["filter-in"]) {
            auto filter_name = filter.first.as<std::string>();
            auto it = Filter::all_filters().find(filter_name);
            if (it == Filter::all_filters().end()) {
                throw std::runtime_error("Unknown filter " + filter_name);
            }
            auto const &filter_desc = (*it).second;
            dom->filters().emplace_back(filter_desc->create(*dom, filter.second));
        }
        return dom;
    }

    Config *s_config = nullptr;

    bool openssl_init = false;
}

Config::Domain::Domain(std::string domain, SESSION_TYPE transport_type, bool xmpp_ver, bool forward, bool require_tls,
                       bool block, bool multiplex, bool auth_pkix, bool auth_dialback, bool auth_host,
                       std::optional<std::string> &&auth_secret)
        : m_domain(std::move(domain)), m_type(transport_type), m_xmpp_ver(xmpp_ver), m_forward(forward), m_require_tls(require_tls), m_block(block), m_multiplex(multiplex),
          m_auth_pkix(auth_pkix), m_auth_dialback(auth_dialback), m_auth_host(auth_host), m_auth_secret(std::move(auth_secret)),
          m_logger(Config::config().logger("domain <{}>", m_domain)) {}

Config::Domain::Domain(Config::Domain const &any, std::string domain)
        : m_domain(std::move(domain)), m_type(any.m_type), m_xmpp_ver(any.m_xmpp_ver), m_forward(any.m_forward), m_require_tls(any.m_require_tls),
          m_block(any.m_block), m_multiplex(any.m_multiplex), m_auth_pkix(any.m_auth_pkix),
          m_auth_dialback(any.m_auth_dialback), m_auth_host(any.m_auth_host), m_dnssec_required(any.m_dnssec_required),
          m_tls_preference(any.m_tls_preference),
          m_stanza_timeout(any.m_stanza_timeout), m_auth_secret(any.m_auth_secret),
          m_parent(&any),
          m_logger(Config::config().logger("domain <{}>", m_domain)) {}

covent::task<FILTER_RESULT> Config::Domain::filter(FILTER_DIRECTION dir, Stanza &s) const {
    using enum FILTER_RESULT;
    if (m_parent) co_return co_await m_parent->filter(dir, s);
    for (auto &filter : m_filters) {
        auto filter_result = co_await filter->apply(dir, s);
        if (filter_result == DROP) co_return DROP;
    }
    co_return PASS;
}



Config::Domain::~Domain() = default;

void Config::Domain::host(std::string const &ihostname, uint32_t inaddr) {
    auto address = std::make_unique<covent::dns::answers::Address>();
    std::string hostname = covent::dns::utils::toASCII(ihostname);
    if (hostname[hostname.length() - 1] != '.') hostname += '.';
    address->dnssec = true;
    address->domain = hostname;
    auto& a = address->addr.emplace_back();
    auto *sin = covent::sockaddr_cast<AF_INET>(&a);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inaddr;
    m_host_arecs[hostname] = std::move(address);
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

Config::Config(std::string const &filename, bool lite) : m_dialback_secret(random_identifier()) {
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
    s_config = this;
    // Spin up a temporary error logger.
    m_root_logger = spdlog::stderr_color_st(lite ? "boot" : "console");
    spdlog::set_level(spdlog::level::trace);
    load(filename, lite);
}

Config::~Config() {
    // TODO: Should really do this, but need to shut it down first: ub_ctx_delete(m_ub_ctx);
}

void Config::write_runtime_config() const {
    std::string tmp = asString();
    std::ofstream of(m_data_dir + "/" + "metre.running.yml", std::ios_base::trunc);
    of << tmp;
}

void Config::load(std::string const &filename, bool lite) {
    auto root_node = YAML::LoadFile(filename);
    logger().debug("Config loaded from {} lite-mode: {}", filename, lite);
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
            m_healthcheck_tls = std::make_unique<TLSContext>(globals["healthcheck"]["tls"], "healthcheck");
            logger().debug("Found healthcheck info, will bail if lite mode is on: {}", lite);
            if (lite) return;
            if (globals["healthcheck"]["jwt_pub_key"]) {
                m_healthcheck_verifier = std::make_unique<JWTVerifier>(globals["healthcheck"]["jwt_pub_key"].as<std::string>());
            }
            m_healthcheck_tls->context();
            if (globals["healthcheck"]["checks"]) {
                for (auto const & from : globals["healthcheck"]["checks"]) {
                    m_healthchecks.emplace(from.first.as<std::string>(), from.second.as<std::string>());
                }
            }
        } else {
            m_healthcheck_tls = std::make_unique<TLSContext>(globals["healthcheck"], "healthcheck"); // Non-existent node to gain defaults
        }
        logger().debug("Completed globals, will bail if lite mode is on: {}", lite);
        if (lite) return;
        if (auto filters = root_node["filters"]; filters) {
            for (auto const & item : filters) {
                auto filter_name = item.first.as<std::string>();
                auto it = Filter::all_filters().find(filter_name);
                if (it == Filter::all_filters().end()) {
                    throw std::runtime_error("Unknown filter " + filter_name);
                }
                auto const &filter_desc = (*it).second;
                filter_desc->config(item.second);
            }
        }
    }
    if (lite) return;
    logger().debug("Proceeding with full config load");
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
        std::unique_ptr<Config::Domain> any_dom = parse_domain(nullptr, "any", any_node, true);
        m_domains[any_dom->domain()] = std::move(any_dom);
        any_domain = m_domains[""].get();
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
            SESSION_TYPE stype = SESSION_TYPE::S2S;
            TLS_MODE tls = listener["tls"].as<bool>(false) ? TLS_MODE::IMMEDIATE : TLS_MODE::STARTTLS;
            if (listener["type"]) {
                using enum SESSION_TYPE;
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
        m_listeners.emplace_back("", "", "S2S", "::", 5269, TLS_MODE::STARTTLS, SESSION_TYPE::S2S);
        m_listeners.emplace_back("", "", "XEP-0368", "::", 5270, TLS_MODE::IMMEDIATE, SESSION_TYPE::S2S);
    }
    for (auto & listener : m_listeners) {
        covent::Loop::thread_loop().listen(listener);
    }
}

Config::Listener::Listener(std::string const &ldomain, std::string const &rdomain, std::string const &aname,
                           std::string const &address, unsigned short port, TLS_MODE atls,
                           SESSION_TYPE asess)
        : covent::Listener<XMLStream>(covent::Loop::thread_loop(), address, port), session_type(asess), tls_mode(atls), name(aname), local_domain(ldomain), remote_domain(rdomain) {
    if (asess == SESSION_TYPE::X2X
        && (local_domain.empty() || remote_domain.empty())) {
        throw std::runtime_error("Missing local or remote domains");
    }
}

namespace {
    YAML::Node domain_to_yaml(Config::Domain const &domain) {
        YAML::Node config;
        config["forward"] = domain.forward();
        config["block"] = domain.block();
        config["stanza-timeout"] = domain.stanza_timeout();
        switch (domain.transport_type()) {
            using enum SESSION_TYPE;
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
            using enum TLS_PREFERENCE;
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
        config["auth"]["dialback"] = domain.auth_dialback();
        if (domain.auth_secret()) {
            config["auth"]["secret"] = *domain.auth_secret();
        }
        config["dns"]["dnssec_required"] = domain.dnssec_required();
        if (domain.has_srv_override()) {
            auto [srv, srv_tls] = domain.srv_override();
            for (auto const &rr: srv.rrs) {
                YAML::Node s;
                s["host"] = rr.hostname;
                s["port"] = rr.port;
                s["priority"] = rr.priority;
                s["weight"] = rr.weight;
                s["tls"] = false;
                config["dns"]["srv"].push_back(s);
            }
            for (auto const &rr: srv_tls.rrs) {
                YAML::Node s;
                s["host"] = rr.hostname;
                s["port"] = rr.port;
                s["priority"] = rr.priority;
                s["weight"] = rr.weight;
                s["tls"] = true;
                config["dns"]["srv"].push_back(s);
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
                    using enum covent::dns::rr::TLSA::MatchType;
                    case Sha256:
                        tlsa["matchtype"] = "Sha256";
                        break;
                    case Sha512:
                        tlsa["matchtype"] = "Sha512";
                        break;
                    default:
                        tlsa["matchtype"] = "Full";
                        break;
                }
                switch (rr.selector) {
                    using enum covent::dns::rr::TLSA::Selector;
                    case SubjectPublicKeyInfo:
                        tlsa["selector"] = "SubjectPublicKeyInfo";
                        break;
                    default:
                        tlsa["selector"] = "FullCert";
                        break;
                }
                switch (rr.certUsage) {
                    using enum covent::dns::rr::TLSA::CertUsage;
                    case CAConstraint:
                        tlsa["certusage"] = "CAConstraint";
                        break;
                    case CertConstraint:
                        tlsa["certusage"] = "CertConstraint";
                        break;
                    case TrustAnchorAssertion:
                        tlsa["certusage"] = "TrustAnchorAssertion";
                        break;
                    default:
                        tlsa["certusage"] = "DomainCert";
                        break;
                }
                if (rr.matchType == covent::dns::rr::TLSA::MatchType::Full) {
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
            host["a"] = covent::address_tostring(address->addr.data());
            config["dns"]["host"].push_back(host);
        }
        if (domain.tls_enabled()) {
            config["tls"]["config"] = domain.tls_context().write();
            config["tls"]["validation"] = domain.pkix_validator().write();
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
    config["globals"]["healthcheck"]["tls"] = m_healthcheck_tls->write();

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
        listener["address"] = covent::address_tostring(listen.sockaddr());
        listener["port"] = covent::address_toport(listen.sockaddr());
        switch (listen.session_type) {
            using enum SESSION_TYPE;
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
        }
        listener["tls"] = listen.tls_mode == TLS_MODE::IMMEDIATE;
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
    m_logger = std::make_shared<spdlog::logger>(logger("config"));
}

void Config::create_domain(std::string const &dom) {
    std::string search{dom};
    auto it = m_domains.find(dom);
    if (it != m_domains.end()) return;
    while (it == m_domains.end()) {
        it = m_domains.find("*." + search);
        if (it == m_domains.end()) {
            if (auto dot = search.find('.'); dot == std::string::npos) {
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
    std::string characters = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ@";
    std::default_random_engine random(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(characters) - 2);
    std::string id(id_len, char{});
    std::generate_n(id.begin(), id_len, [&characters, &random, &dist]() { return characters[dist(random)]; });
    return id;
}

std::string Config::dialback_key(std::string const &id, std::string const &local_domain, std::string const &remote_domain) const {
    std::array<unsigned char, 256/8> binoutput = {};
    std::string const &key = dialback_secret();
    std::string concat = id + '|' + local_domain + '|' + remote_domain;
    HMAC(EVP_sha256(), reinterpret_cast<const unsigned char *>(key.data()), static_cast<int>(key.length()),
         reinterpret_cast<const unsigned char *>(concat.data()), concat.length(),
         binoutput.data(), nullptr);
    std::string hexoutput;
    for (unsigned char c : binoutput) {
        int low = c & 0x0F;
        int high = (c & 0xF0) >> 4;
        hexoutput += static_cast<char>(((high < 0x0A) ? '0' : ('a' - 10)) + high);
        hexoutput += static_cast<char>(((low < 0x0A) ? '0' : ('a' - 10)) + low);
    }
    assert(hexoutput.length() == binoutput.size() * 2);
    m_logger->debug("Dialback key id {} :: {} | {}", id, local_domain, remote_domain);
    return hexoutput;
}

Config const &Config::config() {
    return *s_config;
}

/*
 * DNS resolver functions.
 */

void Config::Domain::tlsa(std::string const &ahostname, unsigned short port, covent::dns::rr::TLSA::CertUsage certUsage,
                          covent::dns::rr::TLSA::Selector selector, covent::dns::rr::TLSA::MatchType matchType, std::string const &value) {
    std::ostringstream out;
    if (ahostname.empty()) throw std::runtime_error("Empty hostname in TLSA override");
    std::string hostname = ahostname;
    if (hostname[hostname.length() - 1] != '.') hostname += '.';
    out << "_" << port << "._tcp." << hostname;
    std::string domain = covent::dns::utils::toASCII(out.str());
    auto tlsait = m_tlsarecs.find(domain);
    covent::dns::answers::TLSA *tlsa;
    if (tlsait == m_tlsarecs.end()) {
        auto tlsan = std::make_unique<covent::dns::answers::TLSA>();
        tlsan->dnssec = true;
        tlsan->domain = domain;
        tlsa = tlsan.get();
        m_tlsarecs[domain] = std::move(tlsan);
    } else {
        tlsa = tlsait->second.get();
    }
    covent::dns::rr::TLSA rr;
    rr.certUsage = certUsage;
    rr.matchType = matchType;
    rr.selector = selector;
    // Match data. Annoying.
    // If the match type was a hash, it'll be an inline hash.
    switch (matchType) {
        case covent::dns::rr::TLSA::MatchType::Sha256:
        case covent::dns::rr::TLSA::MatchType::Sha512: {
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
            if (!value.contains('\n') && value.contains('/')) {
                std::ifstream in(value);
                rr.matchData.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                if (!rr.matchData.empty()) {
                    read_ok = true;
                }
                // If full cert matching, convenient to supply a PEM file as well. Let's check:
                if (rr.selector == covent::dns::rr::TLSA::Selector::FullCert
                    && rr.matchType == covent::dns::rr::TLSA::MatchType::Full
                    && rr.matchData.starts_with("-----BEGIN")) {
                    // Tempting to replace this with a base64_decode call, mind.
                    std::string tmp = rr.matchData;
                    struct raii {
                        BIO * b;
                        ~raii() { BIO_free(b);}
                    } bio = {BIO_new_mem_buf(tmp.data(), static_cast<int>(tmp.size()))};
                    auto cert = PEM_read_bio_X509(bio.b, nullptr, nullptr, nullptr);
                    if (!cert) throw std::runtime_error("Invalid PEM certificate");
                    unsigned char * buf = nullptr;
                    auto len = i2d_X509(cert, &buf);
                    if (len < 0) throw std::runtime_error("Cannot re-encode to DER");
                    rr.matchData.assign(reinterpret_cast<const char *>(buf), len);
                    OPENSSL_free(buf);
                }
            }
            if (!read_ok) {
                rr.matchData = base64_decode(value);
            }
        }
    }
    tlsa->rrs.push_back(rr);
}

Config::Resolver::Resolver(Domain const &d) : m_resolver(d.dnssec_required(), false, Config::config().m_dns_keys), m_domain(d), m_logger(Config::config().logger("Resolver <{}>", m_domain.domain())) {}

Config::Resolver::~Resolver() = default;

void Config::Domain::srv(std::string const &hostname, unsigned short priority, unsigned short weight, unsigned short port, bool tls) {
    if (!m_srvrec) {
        m_srvrec = std::make_unique<covent::dns::answers::SRV>();
        std::string domain = covent::dns::utils::toASCII(
                "_xmpp-server._tcp." + m_domain + ".");
        m_srvrec->dnssec = true;
        m_srvrec->domain = domain;
    }
    if (!m_srvtlsrec) {
        m_srvtlsrec = std::make_unique<covent::dns::answers::SRV>();
        std::string domain = covent::dns::utils::toASCII(
                "_xmpps-server._tcp." + m_domain + ".");
        m_srvtlsrec->dnssec = true;
        m_srvtlsrec->domain = domain;
    }
    covent::dns::rr::SRV rr;
    rr.priority = priority;
    rr.weight = weight;
    rr.port = port;
    rr.hostname = covent::dns::utils::toASCII(hostname);
    if (rr.hostname[rr.hostname.length() - 1] != '.') rr.hostname += '.';
    if (tls) {
        m_srvtlsrec->rrs.push_back(rr);
    } else {
        m_srvrec->rrs.push_back(rr);
    }
}

covent::task<void> Config::Domain::gather_host(Config::Resolver & r, GatheredData & g, const covent::dns::rr::SRV & rr, ConnectInfo::Method method) const {
    auto addr_recs = co_await r.address_lookup(rr.hostname);
    if (!addr_recs.error.empty()) co_return; // Interesting case: a DNSSEC-signed SVCB/SRV record pointing to a non-existent host still adds that host to the X.509-acceptable names.
    if (!addr_recs.dnssec && m_dnssec_required) co_return;
    for (auto const & arr : addr_recs.addr) {
        ConnectInfo conn_info;
        conn_info.method = method;
        conn_info.port = rr.port;
        conn_info.sockaddr = arr;
        conn_info.hostname = rr.hostname;
        if (conn_info.sockaddr.ss_family == AF_INET) {
//            span->containing_transaction().tag("gather.ipv4", "yes");
            covent::sockaddr_cast<AF_INET>(&conn_info.sockaddr)->sin_port = htons(rr.port);
        } else if (conn_info.sockaddr.ss_family == AF_INET6) {
//            span->containing_transaction().tag("gather.ipv6", "yes");
            covent::sockaddr_cast<AF_INET6>(&conn_info.sockaddr)->sin6_port = htons(rr.port);
        }
        g.gathered_connect.push_back(conn_info);
    }
}

covent::task<void> Config::Domain::gather_tlsa(Config::Resolver & r, GatheredData & g, std::string host, uint16_t port) const {
    auto recs = co_await r.tlsa_lookup(port, host);
    if (!recs.error.empty()) co_return;
    if (!recs.dnssec) co_return;
//    span->containing_transaction().tag("gather.tlsa", "yes");
    for (auto const & tlsa_rr : recs.rrs) {
        g.gathered_tlsa.push_back(tlsa_rr);
    }
}

covent::task<Config::Domain::GatheredData> Config::Domain::gather() const {
    m_logger.info("Gathering discovery data for {}", m_domain);
    Resolver r(*this);
    std::string domain = m_domain;
    GatheredData g;
//    span->containing_transaction().tag("gather.domain", domain);
//    span->containing_transaction().tag("gather.svcb", "no");
//    span->containing_transaction().tag("gather.srv", "no");
//    span->containing_transaction().tag("gather.dnssec", "no");
//    span->containing_transaction().tag("gather.ipv4", "no");
//    span->containing_transaction().tag("gather.ipv6", "no");
//    span->containing_transaction().tag("gather.tlsa", "no");
//    span->containing_transaction().tag("gather.tls.direct", "no");
//    span->containing_transaction().tag("gather.tls.starttls", "no");
    bool dnssec = true;
aname_restart:
    m_logger.debug("ANAME restart");
    g.gathered_connect.clear();
    auto svcb = co_await r.svcb_lookup(domain);
    if (svcb.error.empty() && !svcb.rrs.empty()) {
        dnssec = dnssec && svcb.dnssec;
//        span->containing_transaction().tag("gather.svcb", "yes");
        // SVCB pathway
        for (auto const & rr : svcb.rrs) {
            if (svcb.dnssec) {
                g.gathered_hosts.insert(rr.hostname);
            } else if (m_dnssec_required) {
                continue;
            }
            if (rr.priority == 0) {
                domain = rr.hostname;
                goto aname_restart;
            }
            uint16_t  default_port = 443; // Anticipation of WebSocket/WebTransport/BOSH.
            auto method = ConnectInfo::Method::StartTLS;
            if (rr.alpn.empty()) {
                method = ConnectInfo::Method::StartTLS;
//                span->containing_transaction().tag("gather.tls.starttls", "yes");
                default_port = 5269;
            } else if (rr.alpn.contains("xmpp-server")) {
                method = ConnectInfo::Method::DirectTLS;
//                span->containing_transaction().tag("gather.tls.direct", "yes");
                default_port = 5270;
            }
            covent::dns::rr::SRV srv_rr;
            srv_rr.hostname = rr.hostname;
            srv_rr.port =  rr.port ? rr.port : default_port;
            co_await gather_host(r, g, srv_rr, method);
            if (dnssec) co_await gather_tlsa(r, g, srv_rr.hostname, srv_rr.port);
        }
    } else {
        // SRV path
        auto [srv, srv_tls] = co_await r.srv_lookup(domain); // Interesting case: An SVCB looking resulting in the ANAME case might follow to an SRV lookup.
        bool has_srv = (srv.error.empty() && !srv.rrs.empty());
        bool has_srv_tls = (srv.error.empty() && !srv.rrs.empty());
        if (has_srv) {
            dnssec = dnssec && srv.dnssec;
//            span->containing_transaction().tag("gather.srv", "yes");
            for (auto const &rr: srv.rrs) {
                if (srv.dnssec) {
                    g.gathered_hosts.insert(rr.hostname);
                }
//                if (rr.tls) {
//                    span->containing_transaction().tag("gather.tls.direct", "yes");
//                } else {
//                    span->containing_transaction().tag("gather.tls.starttls", "yes");
//                }
                co_await gather_host(r, g, rr, ConnectInfo::Method::StartTLS);
                if (dnssec) co_await gather_tlsa(r, g, rr.hostname, rr.port);
            }
        }
        if (has_srv_tls) {
            dnssec = dnssec && srv.dnssec;
//            span->containing_transaction().tag("gather.srv", "yes");
            for (auto const &rr: srv_tls.rrs) {
                if (srv_tls.dnssec) {
                    g.gathered_hosts.insert(rr.hostname);
                }
//                if (rr.tls) {
//                    span->containing_transaction().tag("gather.tls.direct", "yes");
//                } else {
//                    span->containing_transaction().tag("gather.tls.starttls", "yes");
//                }
                co_await gather_host(r, g, rr, ConnectInfo::Method::DirectTLS);
                if (dnssec) co_await gather_tlsa(r, g, rr.hostname, rr.port);
            }
        }
        if (!has_srv && !has_srv_tls) {
            covent::dns::rr::SRV rr;
            rr.hostname = domain;
            rr.port = 5269;
            rr.priority = 1;
            rr.weight = 1;
            co_await gather_host(r, g, rr, ConnectInfo::Method::StartTLS);
            if (dnssec) co_await gather_tlsa(r, g, domain, 5269);
        }
        // TODO : Do SRV sorting here.
    }
//    span->containing_transaction().tag("gather.dnssec", dnssec ? "yes" : "no");
    co_return g;
}

covent::task<covent::dns::answers::Address> Config::Resolver::address_lookup(std::string const &ihostname) {
    std::string hostname = covent::dns::utils::toASCII(ihostname);
    logger().info("A/AAAA lookup for {}", hostname);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (!domain_override->address_overrides().empty()) {
            logger().debug("Found overrides at {}", domain_override->domain());
            auto it = domain_override->address_overrides().find(hostname);
            if (it != domain_override->address_overrides().end()) {
                auto addr = it->second.get();
                co_return *addr;
            }
        }
    }
    auto [av4, av6] = co_await covent::gather(
         m_resolver.address_v4(ihostname),
         m_resolver.address_v6(ihostname)
    );
    if (!av6.error.empty()) {
        co_return av4;
    }
    if (!av4.error.empty()) {
        co_return av6;
    }
    for (const auto & rr : av6.addr) {
        av4.addr.push_back(rr);
    }
    co_return av4;
}

covent::task<std::tuple<covent::dns::answers::SRV,covent::dns::answers::SRV>> Config::Resolver::srv_lookup(std::string const &base_domain) {
    std::string domain = covent::dns::utils::toASCII("_xmpp-server._tcp." + base_domain + ".");
    std::string domains = covent::dns::utils::toASCII("_xmpps-server._tcp." + base_domain + ".");
    m_logger.debug("SRV lookup: domain=[{}]", base_domain);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (domain_override->has_srv_override()) {
            logger().debug("Found domain_override at {}", domain_override->domain());
            co_return domain_override->srv_override();
        }
    }
    if (base_domain.empty()) {
        covent::dns::answers::SRV r;
        r.error = "Empty Domain - DNS aborted";
        co_return {r,r};
    } else if (m_domain.transport_type() == SESSION_TYPE::X2X) {
        covent::dns::answers::SRV r;
        r.error = "X2X - DNS aborted";
        co_return {r,r};
    } else {
        auto [srv, srv_tls] = co_await covent::gather(
            m_resolver.srv("xmpp-server", base_domain),
            m_resolver.srv("xmpps-server", base_domain)
        );
        co_return {srv, srv_tls};
    }
}

covent::task<covent::dns::answers::SVCB> Config::Resolver::svcb_lookup(std::string const &base_domain) {
    std::string domain = covent::dns::utils::toASCII("_xmpp-server." + base_domain + ".");
    m_logger.debug("SVCB lookup: domain=[{}]", base_domain);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (domain_override->svcb_override()) {
            logger().debug("Found domain_override at {}", domain_override->domain());
            co_return *domain_override->svcb_override();
        }
    }
    if (base_domain.empty()) {
        covent::dns::answers::SVCB r;
        r.error = "Empty Domain - DNS aborted";
        co_return r;
    } else if (m_domain.transport_type() == SESSION_TYPE::X2X) {
        covent::dns::answers::SVCB r;
        r.error = "X2X - DNS aborted";
        co_return r;
    } else {
        co_return co_await m_resolver.svcb("xmpp-server", base_domain);
    }
}

covent::task<covent::dns::answers::TLSA> Config::Resolver::tlsa_lookup(unsigned short port, std::string const &base_domain) {
    std::ostringstream out;
    out << "_" << port << "._tcp." << base_domain;
    std::string domain = covent::dns::utils::toASCII(out.str());
    logger().info("TLSA lookup for domain=[{}]", domain);
    for (Domain const *domain_override = &m_domain; domain_override; domain_override = domain_override->parent()) {
        if (!domain_override->tlsa_overrides().empty()) {
            logger().debug("Found overrides at {}", domain_override->domain());
            auto it = domain_override->tlsa_overrides().find(domain);
            if (it != domain_override->tlsa_overrides().end()) {
                auto addr = it->second.get();
                co_return *addr;
            }
        }
    }
    if (m_domain.transport_type() == SESSION_TYPE::X2X) {
        covent::dns::answers::TLSA r;
        r.error = "X2X - DNS aborted";
        co_return r;
    } else {
        co_return co_await m_resolver.tlsa(port, base_domain);
    }
}
