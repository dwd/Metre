#include "dns.h"

#include <random>
#include <sstream>
#include <unbound.h>

#include "config.h"
#include "log.h"

using namespace Metre;
using namespace Metre::DNS;
using namespace Metre::DNS::Utils;

#ifdef HAVE_ICU2
std::string Utils::toASCII(std::string const &input) {
    if (std::find_if(input.begin(), input.end(), [](const char c) { return c & (1 << 7); }) == input.end())
        return input;
    static UIDNA *idna = 0;
    UErrorCode error = U_ZERO_ERROR;
    if (!idna) {
        idna = uidna_openUTS46(UIDNA_DEFAULT, &error);
    }
    std::string ret;
    ret.resize(1024);
    UIDNAInfo pInfo = UIDNA_INFO_INITIALIZER;
    auto sz = uidna_nameToASCII_UTF8(idna, input.data(), input.size(), const_cast<char *>(ret.data()), 1024, &pInfo,
                                     &error);
    ret.resize(sz);
    return ret;
}
#else
#ifdef HAVE_ICUXX
std::string Utils::toASCII(std::string const &input) {
    if (std::find_if(input.begin(), input.end(), [](const char c) { return c & (1 << 7); }) == input.end())
        return input;
    static UIDNA *idna = 0;
    UErrorCode error = U_ZERO_ERROR;
    if (!idna) {
        idna = uidna_openUTS46(UIDNA_DEFAULT, &error);
    }
    std::string ret;
    ret.resize(1024);
    UIDNAInfo pInfo = UIDNA_INFO_INITIALIZER;
    auto sz = uidna_nameToASCII_UTF8(idna, input.data(), input.size(), const_cast<char *>(ret.data()), 1024, &pInfo,
                                     &error);
    ret.resize(sz);
    return ret;
}
#else

std::string Utils::toASCII(std::string const &input) {
    if (std::ranges::find_if(input, [](const char c) { return c & (1 << 7); }) == input.end()) {
        std::string ret = input;
        std::ranges::transform(ret, ret.begin(),
                       [](const char c) { return static_cast<char>(tolower(c)); });
        return ret;
    }
    throw std::runtime_error("IDNA domain but no ICU");
}

#endif
#endif


template<>
uint8_t Utils::ntoh<uint8_t>(uint8_t u) {
    return u;
}

template<>
uint16_t Utils::ntoh<uint16_t>(uint16_t u) {
    return ntohs(u);
}

template<>
uint32_t Utils::ntoh<uint32_t>(uint32_t u) {
    return ntohl(u);
}

std::string Metre::DNS::Utils::read_hostname(std::istringstream & ss) {
    std::string hostname;
    for(std::string label = read_pf_string<uint8_t>(ss); !label.empty(); label = read_pf_string<uint8_t>(ss)) {
        hostname += label;
        hostname += '.';
    }
    if (hostname.empty()) return ".";
    return hostname;
}

Metre::DNS::SrvRR Metre::DNS::SrvRR::parse(std::string const & s) {
    std::istringstream ss(s);
    SrvRR rr;
    rr.priority = Utils::read_uint<uint16_t>(ss);
    rr.weight = read_uint<uint16_t>(ss);
    rr.port = read_uint<uint16_t>(ss);
    rr.hostname = read_hostname(ss);
    return rr;
}

Metre::DNS::SvcbRR Metre::DNS::SvcbRR::parse(std::string const & s) {
    std::istringstream ss(s);
    SvcbRR rr;
    rr.priority = read_uint<uint16_t>(ss);
    rr.hostname = read_hostname(ss);
    long last = -1;
    while(!ss.eof()) {
        uint16_t param;
        try {
            param = read_uint<uint16_t>(ss);
        } catch (std::runtime_error & e) {
            break;
        }
        if (param <= last) {
            throw std::runtime_error("Duplicate/out of order SvcParam");
        }
        last = param;
        switch(param) {
            case 1: // ALPN
            {
                auto len = read_uint<uint16_t>(ss);
                while (len > 0) {
                    auto alpn = read_pf_string<uint8_t>(ss);
                    if (alpn.length() + 1 > len) {
                        throw std::runtime_error("ALPN value overrun");
                    }
                    len -= alpn.length();
                    len -= 1;
                    rr.alpn.insert(alpn);
                }
            }
            break;

            case 3: // Port
                if (read_uint<uint16_t>(ss) != 2) {
                    throw std::runtime_error("Unexpected length for port");
                }
                rr.port = read_uint<uint16_t>(ss);
                break;

            default:
                rr.params[param] = read_pf_string<uint16_t>(ss);
        }
    }
    return rr;
}

TlsaRR TlsaRR::parse(std::string const & s) {
    std::istringstream ss(s);
    TlsaRR rr;
    rr.certUsage = static_cast<CertUsage>(read_uint<uint8_t>(ss));
    rr.selector = static_cast<Selector>(read_uint<uint8_t>(ss));
    rr.matchType = static_cast<MatchType>(read_uint<uint8_t>(ss));
    std::ostringstream os;
    os << ss.rdbuf();
    rr.matchData = os.str();
    return rr;
}


/*
 * DNS resolver functions.
 */

namespace {
    // This holds a set of live resolver pointers.
    // If a result comes in for an old one, we can therefore ignore it.
    // Yeah, this is a bit weird.
    std::unordered_set<Metre::DNS::Resolver const *> s_resolvers;

    // Unbound context.
    struct ub_ctx * s_ub_ctx;

    class UBResult {
        /* Quick guard class. */
    public:
        struct ub_result *result;

        explicit UBResult(struct ub_result *r) : result(r) {}
        UBResult(UBResult const &) = delete;
        UBResult(UBResult &&) = delete;
        UBResult & operator=(UBResult const &) = delete;
        UBResult & operator=(UBResult &&) = delete;

        ~UBResult() { ub_resolve_free(result); }
    };

    void srv_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        METRE_LOG(Log::DEBUG, "DNS result for resolver " << x);
        auto resolver = reinterpret_cast<Metre::DNS::Resolver *>(x);
        if (!s_resolvers.contains(resolver)) return;
        resolver->srv_lookup_done(err, result);
    }

    void svcb_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        METRE_LOG(Log::DEBUG, "DNS result for resolver " << x);
        auto resolver = reinterpret_cast<Metre::DNS::Resolver *>(x);
        if (!s_resolvers.contains(resolver)) return;
        resolver->svcb_lookup_done(err, result);
    }

    void a_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        METRE_LOG(Log::DEBUG, "DNS result for resolver " << x);
        auto resolver = reinterpret_cast<Metre::DNS::Resolver *>(x);
        if (!s_resolvers.contains(resolver)) return;
        resolver->a_lookup_done(err, result);
    }

    void tlsa_lookup_done_cb(void *x, int err, struct ub_result *result) {
        UBResult r{result};
        METRE_LOG(Log::DEBUG, "DNS result for resolver " << x);
        auto resolver = reinterpret_cast<Metre::DNS::Resolver *>(x);
        if (!s_resolvers.contains(resolver)) return;
        resolver->tlsa_lookup_done(err, result);
    }
}

ub_ctx * Utils::dns_init(std::string const & dns_keys) {
    s_ub_ctx = ub_ctx_create();
    if (!s_ub_ctx) {
        throw std::runtime_error("Couldn't start resolver");
    }
    int retval;
    if ((retval = ub_ctx_async(s_ub_ctx, 1)) != 0) {
        throw std::runtime_error(ub_strerror(retval));
    }
    if ((retval = ub_ctx_resolvconf(s_ub_ctx, nullptr)) != 0) {
        throw std::runtime_error(ub_strerror(retval));
    }
    if ((retval = ub_ctx_hosts(s_ub_ctx, nullptr)) != 0) {
        throw std::runtime_error(ub_strerror(retval));
    }
    if (!dns_keys.empty()) {
        if ((retval = ub_ctx_add_ta_file(s_ub_ctx, dns_keys.c_str())) != 0) {
            throw std::runtime_error(ub_strerror(retval));
        }
    }
    return s_ub_ctx;
}

Metre::DNS::Resolver::Resolver(std::string const & name, bool dnssec_required, TLS_PREFERENCE tls_preference) : m_dnssec_required(dnssec_required), m_tls_preference(tls_preference) {
    METRE_LOG(Log::DEBUG, "New resolver " << this);
    s_resolvers.insert(this);
}

void Metre::DNS::Resolver::tlsa_lookup_done(int err, struct ub_result *result) {
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
        }
        m_tlsa_pending[tlsa.domain].emit(tlsa);
        return;
    }
    DNS::Tlsa tlsa;
    tlsa.error = error;
    tlsa.domain = result->qname;
    m_tlsa_pending[tlsa.domain].emit(tlsa);
}

namespace {
    void srv_sort(Metre::DNS::Srv &srv, Metre::TLS_PREFERENCE pref) {
        std::vector<Metre::DNS::SrvRR> tmp = std::move(srv.rrs);
        if (pref != Metre::PREFER_ANY) {
            bool tls = (pref == Metre::PREFER_IMMEDIATE);
            for (auto &rr : tmp) {
                rr.priority *= 2;
                if (rr.tls != tls) {
                    rr.priority += 1;
                }
            }
        }
        std::ranges::sort(tmp, [](Metre::DNS::SrvRR const &a, Metre::DNS::SrvRR const &b) {
            return a.priority < b.priority;
        });
        srv.rrs = std::vector<Metre::DNS::SrvRR>();
        std::map<unsigned short, int> weights;
        for (auto const &rr : tmp) {
            weights[rr.priority] += rr.weight;
        }
        std::default_random_engine random(std::random_device{}());
        std::uniform_int_distribution<> dist(0, 65535);
        bool any;
        do {
            int prio = -1;
            int r = dist(random);
            any = false;
            for (auto &rr : tmp) {
                if (rr.port == 0) continue;
                if (prio > 0 && prio != rr.priority) break; // We've not completed the last priority level yet.
                if (weights[rr.priority] == rr.weight) {
                    // Pick the only one.
                    srv.rrs.push_back(rr);
                    rr.port = 0;
                    weights[rr.priority] = 0;
                    continue;
                }
                if (r % weights[rr.priority] <= rr.weight) {
                    srv.rrs.push_back(rr);
                    rr.port = 0;
                    weights[rr.priority] -= rr.weight;
                } else {
                    any = true;
                    prio = rr.priority;
                }
            }
        } while (any);
    }
}

void Metre::DNS::Resolver::srv_lookup_done(int err, struct ub_result *result) {
    std::string error;
    if (err != 0) {
        error = ub_strerror(err);
    } else if (!result->havedata) {
        error = "No SRV records present";
    } else if (result->bogus) {
        error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        error = "DNSSEC required but unsigned";
    } else {
        m_current_srv.dnssec = m_current_srv.dnssec && !!result->secure;
        m_current_srv.domain = result->qname;
        if (m_current_srv.domain.find("_xmpps") == 0) {
            m_current_srv.xmpps = true;
            m_current_srv.domain = std::string("_xmpp") + (m_current_srv.domain.c_str() + 6);
        } else {
            m_current_srv.xmpp = true;
        }
        for (int i = 0; result->data[i]; ++i) {
            m_current_srv.rrs.push_back(SrvRR::parse(std::string(result->data[i], result->len[i])));
        }
        if (m_current_srv.xmpp && m_current_srv.xmpps) {
            srv_sort(m_current_srv, m_tls_preference);
            m_srv_pending.emit(m_current_srv);
        }
        return;
    }
    m_current_srv.domain = result->qname;
    if (err == 0 && !result->havedata) {
        if (m_current_srv.xmpps || m_current_srv.xmpp) {
            // We have done (precisely) one, so set this flag.
            m_current_srv.nxdomain = true;
        }
    } else {
        m_current_srv.nxdomain = false;
    }
    if (m_current_srv.domain.find("_xmpps") == 0) {
        m_current_srv.xmpps = true;
        m_current_srv.domain = std::string("_xmpp") + (m_current_srv.domain.c_str() + 6);
    } else {
        m_current_srv.xmpp = true;
    }
    if (m_current_srv.xmpp && m_current_srv.xmpps) {
        if (m_current_srv.rrs.empty() && m_current_srv.nxdomain) {
            // Synthesize an SRV.
            DNS::SrvRR rr;
            rr.port = 5269;
            rr.hostname =
                    m_current_srv.domain.c_str() + sizeof("_xmpp-server._tcp.") - 1; // Trim "_xmpp-server._tcp."
            m_current_srv.rrs.push_back(rr);
            m_current_srv.error.clear();
        }
        if (m_current_srv.rrs.empty()) {
            DNS::Srv srv;
            srv.error = error;
            srv.domain = result->qname;
            srv.dnssec = srv.dnssec && !!result->secure;
            m_srv_pending.emit(srv);
        } else {
            srv_sort(m_current_srv, m_tls_preference);
            m_current_srv.dnssec = m_current_srv.dnssec && !!result->secure;
            m_srv_pending.emit(m_current_srv);
        }
    }
}

void Metre::DNS::Resolver::svcb_lookup_done(int err, struct ub_result *result) {
    DNS::Svcb svcb;
    if (err != 0) {
        svcb.error = ub_strerror(err);
    } else if (!result->havedata) {
        svcb.error = "No SRV records present";
    } else if (result->bogus) {
        svcb.error = std::string("Bogus: ") + result->why_bogus;
    } else if (!result->secure && m_dnssec_required) {
        svcb.error = "DNSSEC required but unsigned";
    } else {
        svcb.dnssec = !!result->secure;
        svcb.domain = result->qname;
        for (int i = 0; result->data[i]; ++i) {
            svcb.rrs.push_back(SvcbRR::parse(std::string(result->data[i], result->len[i])));
        }
    }
    m_svcb_pending.emit(svcb);
}

void Metre::DNS::Resolver::a_lookup_done(int err, struct ub_result *result) {
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
        if (m_current_arec.hostname != result->qname) {
            m_current_arec.error = "";
            m_current_arec.dnssec = !!result->secure;
            m_current_arec.hostname = result->qname;
            m_current_arec.addr.clear();
            m_current_arec.ipv4 = m_current_arec.ipv6 = false;
        } else {
            m_current_arec.dnssec = m_current_arec.dnssec && !!result->secure;
            m_current_arec.error = "";
        }
        if (result->qtype == 1) {
            m_current_arec.ipv4 = true;
            for (int i = 0; result->data[i]; ++i) {
                auto& a = m_current_arec.addr.emplace_back();
                auto sin = reinterpret_cast<struct sockaddr_in *>(&a);
                sin->sin_family = AF_INET;
#ifdef METRE_WINDOWS
                sin->sin_addr = *reinterpret_cast<struct in_addr *>(result->data[i]);
#else
                sin->sin_addr.s_addr = *reinterpret_cast<in_addr_t *>(result->data[i]);
#endif
            }
        } else if (result->qtype == 28) {
            m_current_arec.ipv6 = true;
            for (int i = 0; result->data[i]; ++i) {
                auto it = m_current_arec.addr.emplace(m_current_arec.addr.begin());
                auto sin = reinterpret_cast<struct sockaddr_in6 *>(std::to_address(it));
                sin->sin6_family = AF_INET6;
                memcpy(sin->sin6_addr.s6_addr, result->data[i], 16);
            }
        }
        if (m_current_arec.ipv4 && m_current_arec.ipv6) {
            m_a_pending[m_current_arec.hostname].emit(m_current_arec);
        }
        return;
    }
    if (m_current_arec.hostname != result->qname) {
        m_current_arec.error = error;
        m_current_arec.dnssec = !!result->secure;
        m_current_arec.hostname = result->qname;
        m_current_arec.addr.clear();
        m_current_arec.ipv4 = m_current_arec.ipv6 = false;
    }
    switch (result->qtype) {
        case 1:
            m_current_arec.ipv4 = true;
            break;
        case 28:
            m_current_arec.ipv6 = true;
            break;
    }
    if (m_current_arec.ipv4 && m_current_arec.ipv6) {
        if (m_current_arec.addr.empty()) {
            m_current_arec.error = error;
        }
        m_a_pending[m_current_arec.hostname].emit(m_current_arec);
    }
}

namespace {
    int resolve_async(Metre::DNS::Resolver const *resolver, std::string const &record, int rrtype, ub_callback_type cb) {
        int retval;
        int async_id;
        if ((retval = ub_resolve_async(s_ub_ctx, const_cast<char *>(record.c_str()), rrtype, 1,
                                       const_cast<void *>(reinterpret_cast<const void *>(resolver)), cb, &async_id)) < //NOSONAR(cpp:S3630)
                                                                                                                               0) {
            throw std::runtime_error(std::string("While resolving ") + record + ": " + ub_strerror(retval));
        }
        return async_id;
    }
}

Metre::DNS::Resolver::addr_callback_t &Metre::DNS::Resolver::AddressLookup(std::string const &ihostname) {
    std::string hostname = toASCII(ihostname);
    m_current_arec.hostname = "";
    m_current_arec.addr.clear();
    m_current_arec.ipv6 = m_current_arec.ipv4 = false;
    m_queries.insert(resolve_async(this, hostname, 28, a_lookup_done_cb));
    m_queries.insert(resolve_async(this, hostname, 1, a_lookup_done_cb));
    return m_a_pending[hostname];
}

Metre::DNS::Resolver::srv_callback_t &Metre::DNS::Resolver::SrvLookup(std::string const &base_domain) {
    std::string domain = toASCII("_xmpp-server._tcp." + base_domain + ".");
    std::string domains = toASCII("_xmpps-server._tcp." + base_domain + ".");
    m_current_srv.xmpp = m_current_srv.xmpps = false;
    m_current_srv.rrs.clear();
    m_current_srv.dnssec = true;
    m_current_srv.error.clear();
    m_queries.insert(resolve_async(this, domain, 33, srv_lookup_done_cb));
    m_queries.insert(resolve_async(this, domains, 33, srv_lookup_done_cb));
    return m_srv_pending;
}

Metre::DNS::Resolver::svcb_callback_t &Metre::DNS::Resolver::SvcbLookup(std::string const &base_domain) {
    std::string domain = toASCII("_xmpp-server." + base_domain + ".");
    m_queries.insert(resolve_async(this, domain, 65, svcb_lookup_done_cb));
    return m_svcb_pending;
}

Metre::DNS::Resolver::tlsa_callback_t &Metre::DNS::Resolver::TlsaLookup(unsigned short port, std::string const &base_domain) {
    std::ostringstream out;
    out << "_" << port << "._tcp." << base_domain;
    std::string domain = toASCII(out.str());
    m_queries.insert(resolve_async(this, domain, 52, tlsa_lookup_done_cb));
    return m_tlsa_pending[domain];
}

Metre::DNS::Resolver::~Resolver() {
    for (auto async_id : m_queries) {
        ub_cancel(s_ub_ctx, async_id);
    }
    s_resolvers.erase(this);
    METRE_LOG(Log::DEBUG, "Deleted resolver " << this);
}
