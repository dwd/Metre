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
    template<typename T>
    void from_config(covent::Service::Entry & entry, YAML::Node const & config);

    template<typename T>
    [[nodiscard]] YAML::Node to_config(T const & obj) {
        return {};
    }

    template<>
    void from_config<covent::pkix::PKIXValidator>(covent::Service::Entry & entry, YAML::Node const & config) {
        auto crls = config["crls"].as<bool>(Config::config().fetch_pkix_status());
        if (crls && !Config::config().fetch_pkix_status()) {
            throw covent::pkix::pkix_config_error("Cannot check status without fetching status");
        }
        auto system_trust = config["system-trust"].as<bool>(true);
        auto & result = entry.make_validator(crls, system_trust);
        for (auto const & ta : config["trust-anchors"]) {
            result.add_trust_anchor(ta.as<std::string>());
        }
    }

    template<>
    [[nodiscard]] YAML::Node to_config(covent::pkix::PKIXValidator const & obj) {
        // TODO : Write this (and accessors).
        return YAML::Node{};
    }

    int yaml_to_tls(YAML::Node const &tls_version_node, int def) {
        if (!tls_version_node) return def;
        auto version_string = tls_version_node.as<std::string>();
        int version = def;
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

    constexpr const char * tls_version_to_string(int ver) {
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
            default:
                return nullptr;
        }
    }

    template<>
    void from_config<covent::pkix::TLSContext>(covent::Service::Entry & entry, YAML::Node const & config) {
        if (config) {
            auto enabled = config["enabled"].as<bool>(true);
            Config::config().logger().info("TLSContext for '{}' is {}", entry.name(), enabled);
            auto & result = entry.make_tls_context(enabled, true, entry.name());
            Config::config().logger().info("TLSContext for '{}' is {}", entry.name(), result.enabled());
            result.dhparam(config["dhparam"].as<std::string>("auto"));
            result.cipherlist(config["cipherlist"].as<std::string>("HIGH:!3DES:!eNULL:!aNULL:@STRENGTH")); // Apparently 3DES qualifies for HIGH, but is 112 bits, which the IM Observatory marks down for.
            Config::config().logger().info("Cipherlist set to {}", result.cipherlist());
            result.min_version(yaml_to_tls(config["min_version"], TLS1_2_VERSION));
            result.max_version(yaml_to_tls(config["max_version"], TLS1_3_VERSION));
            for (auto const &identity: config["identities"]) {
                auto cert_chain_file = identity["chain"].as<std::string>();
                auto pkey_file = identity["pkey"].as<std::string>();
                // auto generate = identity["generate"].as<bool>(false);
                result.add_identity(std::make_unique<covent::pkix::PKIXIdentity>(cert_chain_file, pkey_file));
                Config::config().logger().debug("Debug");
                Config::config().logger().info("Loaded certificate {}", cert_chain_file);
            }
        }
    }

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
            // if (auth_host && sess == SESSION_TYPE::X2X) {
            //     dnssec_required = true;
            // }
            if (!(block || auth_pkix || auth_dialback || auth_secret || auth_host)) {
                throw std::runtime_error("Cannot authenticate domain, but not blocked.");
            }
        }
        auto dom = std::make_unique<Config::Domain>(name, sess, xmpp_ver, forward, tls_required, block, multiplex, auth_pkix, auth_dialback,
                                                    auth_host, std::move(auth_secret));
        dom->stanza_timeout(stanza_timeout);
        dom->connect_timeout(connect_timeout);
        dom->tls_preference(tls_preference);
        if (auto tls = domain["tls"]; tls) {
            if (tls["config"]) {
                from_config<covent::pkix::TLSContext>(dom->entry(), tls["config"]);
            }
            spdlog::info("Loaded identities, initialize");
            dom->tls_context().context(); // Force everything to get instantiated here.
            spdlog::info("Loaded identities, done");
            if (tls["validation"]) {
                from_config<covent::pkix::PKIXValidator>(dom->entry(), tls["validation"]);
            }
        }

        if (auto dnst = domain["dns"]; dnst) {
            if (auto dnssec = dnst["dnssec_required"]; dnssec) {
                auto & ta_file = Config::config().dns_ta_file();
                dom->entry().make_resolver(dnssec.as<bool>(), false, ta_file);
            }
            auto & resolver = dom->resolver();
            for (auto hostt : dnst["host"]) {
                covent::dns::answers::Address rr;
                rr.dnssec = hostt["dnssec"].as<bool>(true);
                auto af = AF_INET;
                auto aa = hostt["a"];
                if (aa) {
                    if (!aa) throw std::runtime_error("Missing a in host DNS override");
                    if (aa.as<std::string>().contains(':')) {
                        af = AF_INET6;
                    }
                }
                struct sockaddr_storage saddr;
                saddr.ss_family = af;
                if (af == AF_INET) {
                    auto * s4 = covent::sockaddr_cast<AF_INET>(&saddr);
                    auto addr = aa.as<std::string>();
                    if (!inet_pton(AF_INET, addr.c_str(), &s4->sin_addr)) {
                        throw std::runtime_error("Unable to parse IPv4 address");
                    }
                } else {
                    auto * s6 = covent::sockaddr_cast<AF_INET6>(&saddr);
                    auto addr = aa.as<std::string>();
                    if (!inet_pton(AF_INET, addr.c_str(), &s6->sin6_addr)) {
                        throw std::runtime_error("Unable to parse IPv6 address");
                    }
                }
                rr.addr.push_back(saddr);
                resolver.inject(rr);
            }
            for (auto srvt : dnst["srv"]) {
                auto hosta = srvt["host"];
                if (!hosta) throw std::runtime_error("Missing host in SRV DNS override");
                auto host = hosta.as<std::string>();
                auto tls = srvt["tls"].as<bool>(false);
                auto port = srvt["port"].as<unsigned short>(tls ? 5270 : 5269);
                auto weight = srvt["weight"].as<unsigned short>(0);
                auto prio = srvt["priority"].as<unsigned short>(0);
                covent::dns::answers::SRV srv;
                srv.rrs.emplace(srv.rrs.begin());
                srv.rrs[0].hostname = host;
                srv.rrs[0].port = port;
                srv.rrs[0].priority = prio;
                srv.rrs[0].weight = weight;
                srv.rrs[0].service = tls ? "xmpps-service" : "xmpp-service";
                srv.dnssec = srvt["dnssec"].as<bool>(true);
                resolver.inject(srv);
            }
            for (auto tlsa : dnst["tlsa"]) {
                covent::dns::answers::TLSA rr;
                rr.rrs.emplace(rr.rrs.begin());
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
                rr.rrs[0].certUsage = certUsage;
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
                rr.rrs[0].matchType = matchType;
                auto sel = tlsa["selector"].as<std::string>("FullCert");
                covent::dns::rr::TLSA::Selector selector = covent::dns::rr::TLSA::Selector::FullCert;
                if (sel == "FullCert") {
                    selector = covent::dns::rr::TLSA::Selector::FullCert;
                } else if (sel == "SubjectPublicKeyInfo") {
                    selector = covent::dns::rr::TLSA::Selector::SubjectPublicKeyInfo;
                } else {
                    throw std::runtime_error("Unknown selector in TLSA DNS override");
                }
                rr.rrs[0].selector = selector;
                // Match data. Annoying.
                // If the match type was a hash, it'll be an inline hash.
                auto value = tlsa["matchdata"].as<std::string>();
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
                                rr.rrs[0].matchData += byte;
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
                            rr.rrs[0].matchData.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                            if (!rr.rrs[0].matchData.empty()) {
                                read_ok = true;
                            }
                            // If full cert matching, convenient to supply a PEM file as well. Let's check:
                            if (rr.rrs[0].selector == covent::dns::rr::TLSA::Selector::FullCert
                                && rr.rrs[0].matchType == covent::dns::rr::TLSA::MatchType::Full
                                && rr.rrs[0].matchData.starts_with("-----BEGIN")) {
                                // Tempting to replace this with a base64_decode call, mind.
                                std::string tmp = rr.rrs[0].matchData;
                                struct raii {
                                    BIO * b;
                                    ~raii() { BIO_free(b);}
                                } bio = {BIO_new_mem_buf(tmp.data(), static_cast<int>(tmp.size()))};
                                auto cert = PEM_read_bio_X509(bio.b, nullptr, nullptr, nullptr);
                                if (!cert) throw std::runtime_error("Invalid PEM certificate");
                                unsigned char * buf = nullptr;
                                auto len = i2d_X509(cert, &buf);
                                if (len < 0) throw std::runtime_error("Cannot re-encode to DER");
                                rr.rrs[0].matchData.assign(reinterpret_cast<const char *>(buf), len);
                                OPENSSL_free(buf);
                            }
                        }
                        if (!read_ok) {
                            rr.rrs[0].matchData = base64_decode(value);
                        }
                    }
                }

                resolver.inject(rr);
            }
        }
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
        : m_entry(Config::config().xmpp_service().add(domain)), m_domain(std::move(domain)), m_type(transport_type), m_xmpp_ver(xmpp_ver), m_forward(forward), m_require_tls(require_tls), m_block(block), m_multiplex(multiplex),
          m_auth_pkix(auth_pkix), m_auth_dialback(auth_dialback), m_auth_host(auth_host), m_auth_secret(std::move(auth_secret)),
          m_logger(Config::config().logger("domain <{}>", m_domain)) {}

Config::Domain::Domain(Config::Domain const &any, std::string domain)
        : m_entry(Config::config().xmpp_service().add(domain, any.entry())), m_domain(std::move(domain)), m_type(any.m_type), m_xmpp_ver(any.m_xmpp_ver), m_forward(any.m_forward), m_require_tls(any.m_require_tls),
          m_block(any.m_block), m_multiplex(any.m_multiplex), m_auth_pkix(any.m_auth_pkix),
          m_auth_dialback(any.m_auth_dialback), m_auth_host(any.m_auth_host), m_dnssec_required(any.m_dnssec_required),
          m_tls_preference(any.m_tls_preference),
          m_stanza_timeout(any.m_stanza_timeout), m_auth_secret(any.m_auth_secret),
          m_parent(&any),
          m_logger(Config::config().logger("domain <{}>", m_domain)) {}

covent::task<FILTER_RESULT> Config::Domain::filter(FILTER_DIRECTION dir, Stanza &s) const {
    auto span = covent::sentry::span::start("fn", fmt::format("filters for {} {}", m_domain, dir));
    using enum FILTER_RESULT;
    if (m_parent) co_return co_await m_parent->filter(dir, s);
    for (auto &filter : m_filters) {
        auto filter_span = covent::sentry::span::start("fn.filter", fmt::format("{}:{}", filter->name(), dir));
        auto filter_result = co_await filter->apply(dir, s);
        if (filter_result == DROP) co_return DROP;
    }
    co_return PASS;
}



Config::Domain::~Domain() = default;

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
    // spdlog::set_default_logger(spdlog::stderr_color_st(lite ? "boot" : "console"));
    m_root_logger = spdlog::default_logger();
    if (!lite) m_xmpp_service = std::make_unique<covent::Service>();
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
            // m_healthcheck_tls = std::make_unique<covent::pkix::TLSContext>(
            //     globals["healthcheck"]["tls"]["enabled"].as<bool>(false),
            //     false,
            //     "healthcheck"
            // );
            logger().debug("Found healthcheck info, will bail if lite mode is on: {}", lite);
            if (lite) return;
            if (globals["healthcheck"]["jwt_pub_key"]) {
                m_healthcheck_verifier = std::make_unique<JWTVerifier>(globals["healthcheck"]["jwt_pub_key"].as<std::string>());
            }
            // m_healthcheck_tls->context();
            if (globals["healthcheck"]["checks"]) {
                for (auto const & from : globals["healthcheck"]["checks"]) {
                    m_healthchecks.emplace(from.first.as<std::string>(), from.second.as<std::string>());
                }
            }
        } else {
            // m_healthcheck_tls = std::make_unique<covent::pkix::TLSContext>(false, false, "healthcheck"); // Non-existent node to gain defaults
        }
        logger().debug("Completed globals, will bail if lite mode is on: {}", lite);
        if (lite) return;
        // At this point, spin up the API
        auto m_http_server = std::make_unique<covent::http::Server>(m_healthcheck_port, false);
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
        // config["dns"]["dnssec_required"] = domain.resolver().dnssec_required();
        // if (domain.has_srv_override()) {
        //     auto [srv, srv_tls] = domain.srv_override();
        //     for (auto const &rr: srv.rrs) {
        //         YAML::Node s;
        //         s["host"] = rr.hostname;
        //         s["port"] = rr.port;
        //         s["priority"] = rr.priority;
        //         s["weight"] = rr.weight;
        //         s["tls"] = false;
        //         config["dns"]["srv"].push_back(s);
        //     }
        //     for (auto const &rr: srv_tls.rrs) {
        //         YAML::Node s;
        //         s["host"] = rr.hostname;
        //         s["port"] = rr.port;
        //         s["priority"] = rr.priority;
        //         s["weight"] = rr.weight;
        //         s["tls"] = true;
        //         config["dns"]["srv"].push_back(s);
        //     }
        // }
        // for (auto const & [name, records]: domain.tlsa_overrides()) {
        //     for (auto const &rr: records->rrs) {
        //         std::stringstream ss(records->domain);
        //         unsigned short int port = 0;
        //         std::string hostname;
        //         char underscore;
        //         ss >> underscore >> port >> hostname;
        //         YAML::Node tlsa;
        //         tlsa["hostname"] = hostname;
        //         tlsa["port"] = port;
        //         switch (rr.matchType) {
        //             using enum covent::dns::rr::TLSA::MatchType;
        //             case Sha256:
        //                 tlsa["matchtype"] = "Sha256";
        //                 break;
        //             case Sha512:
        //                 tlsa["matchtype"] = "Sha512";
        //                 break;
        //             default:
        //                 tlsa["matchtype"] = "Full";
        //                 break;
        //         }
        //         switch (rr.selector) {
        //             using enum covent::dns::rr::TLSA::Selector;
        //             case SubjectPublicKeyInfo:
        //                 tlsa["selector"] = "SubjectPublicKeyInfo";
        //                 break;
        //             default:
        //                 tlsa["selector"] = "FullCert";
        //                 break;
        //         }
        //         switch (rr.certUsage) {
        //             using enum covent::dns::rr::TLSA::CertUsage;
        //             case CAConstraint:
        //                 tlsa["certusage"] = "CAConstraint";
        //                 break;
        //             case CertConstraint:
        //                 tlsa["certusage"] = "CertConstraint";
        //                 break;
        //             case TrustAnchorAssertion:
        //                 tlsa["certusage"] = "TrustAnchorAssertion";
        //                 break;
        //             default:
        //                 tlsa["certusage"] = "DomainCert";
        //                 break;
        //         }
        //         if (rr.matchType == covent::dns::rr::TLSA::MatchType::Full) {
        //             // Base64 data (it might have come from a file, but never mind).
        //             tlsa["matchdata"] = base64_encode(rr.matchData);
        //         } else {
        //             std::ostringstream os;
        //             os << std::hex << std::setfill('0') << std::setw(2);
        //             bool colon = false;
        //             for (char c: rr.matchData) {
        //                 auto byte = static_cast<unsigned short>(c);
        //                 // Use numeric type to avoid treating as character.
        //                 if (!colon) {
        //                     colon = true;
        //                 } else {
        //                     os << ':';
        //                 }
        //                 os << byte;
        //             }
        //             tlsa["matchdata"] = os.str();
        //         }
        //         config["dns"]["tlsa"].push_back(tlsa);
        //     }
        // }
        // for (auto const &[hostname, address]: domain.address_overrides()) {
        //     YAML::Node host;
        //     host["a"] = covent::address_tostring(address->addr.data());
        //     config["dns"]["host"].push_back(host);
        // }
        if (domain.tls_enabled()) {
            config["tls"]["config"] = to_config(domain.tls_context());
            config["tls"]["validation"] = to_config(domain.pkix_validator());
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
    // config["globals"]["healthcheck"]["tls"] = m_healthcheck_tls->write();

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
        spdlog::set_default_logger(spdlog::daily_logger_st("global", m_logfile));
    }
    m_root_logger = spdlog::default_logger();
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
