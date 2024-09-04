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

#ifndef METRE_DNS_H
#define METRE_DNS_H

#include "defs.h"
#include "sigslot.h"
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <unordered_set>
#include <spdlog/logger.h>
// For struct sockaddr_storage :
#ifdef METRE_UNIX
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

// FWD
struct ub_result;
struct ub_ctx;

namespace Metre::DNS {

    namespace Utils {
        std::string toASCII(std::string const &);

        template<typename UINT>
        UINT ntoh(UINT);

        template<>
        uint8_t ntoh<uint8_t>(uint8_t u);

        template<>
        uint16_t ntoh<uint16_t>(uint16_t u);

        template<>
        uint32_t ntoh<uint32_t>(uint32_t u);

        template<typename UINT>
        UINT read_uint(std::istringstream &ss) {
            UINT l;
            ss.read(reinterpret_cast<char *>(&l), sizeof(l));
            if (!ss) {
                throw std::runtime_error("End of data in DNS parsing");
            }
            return ntoh(l);
        }

        template<typename UINT>
        std::string read_pf_string(std::istringstream & ss) {
            auto len = read_uint<UINT>(ss);
            if (len == 0) {
                return {};
            }
            std::vector<char> str_data(len);
            ss.read(str_data.data(), len);
            if (!ss) {
                throw std::runtime_error("End of data in DNS parsing");
            }
            return {str_data.begin(), str_data.end()};
        }

        std::string read_hostname(std::istringstream & ss);

        struct ub_ctx * dns_init(std::string const & dns_key_file);
    }

    class SrvRR {
    public:
        std::string hostname;
        unsigned short port = 0;
        unsigned short weight = 0;
        unsigned short priority = 0;
        bool tls = false;
        static SrvRR parse(std::string const &);
    };

    class Srv {
    public:
        bool xmpp = false;
        bool xmpps = false;
        std::vector<SrvRR> rrs;
        std::string domain;
        bool dnssec = false;
        std::string error;
        bool nxdomain = false;
    };

    class SvcbRR {
    public:
        std::string hostname;
        unsigned short priority = 0;
        unsigned short port = 0;
        std::set<std::string, std::less<>> alpn;
        std::map<long,std::string> params; // These might be binary!
        static SvcbRR parse(std::string const &);
    };

    class Svcb {
    public:
        std::vector<SvcbRR> rrs;
        std::string domain;
        bool dnssec = false;
        std::string error;
        bool nxdomain = false;
    };

    class Address {
    public:
        bool ipv4 = false;
        bool ipv6 = false;
        std::vector<struct sockaddr_storage> addr;
        bool dnssec = false;
        std::string error;
        std::string hostname;
    };

    class TlsaRR {
    public:
        enum class CertUsage : uint8_t {
            CAConstraint = 0,
            CertConstraint = 1,
            TrustAnchorAssertion = 2,
            DomainCert = 3
        };
        enum class Selector : uint8_t {
            FullCert = 0,
            SubjectPublicKeyInfo = 1
        };
        enum class MatchType : uint8_t {
            Full = 0,
            Sha256 = 1,
            Sha512 = 2
        };
        CertUsage certUsage;
        Selector selector;
        MatchType matchType;
        std::string matchData;
        static TlsaRR parse(std::string const &);
    };

    class Tlsa {
    public:
        std::string domain;
        std::string error;
        bool dnssec = false;

        std::vector<TlsaRR> rrs;
    };

    class ConnectInfo {
    public:
        enum class  Method {
            StartTLS,
            DirectTLS,
            Websocket
        };
        Method method;
        std::string hostname;
        struct sockaddr_storage sockaddr;
        uint16_t port;
    };

    class Resolver {
    public:
        /* DNS */
        using srv_callback_t = sigslot::signal<DNS::Srv>;
        using svcb_callback_t = sigslot::signal<DNS::Svcb>;
        using addr_callback_t = sigslot::signal<DNS::Address>;
        using tlsa_callback_t = sigslot::signal<DNS::Tlsa>;


        Resolver(std::string const & name, bool dnssec_required, TLS_PREFERENCE tls_preference);
        Resolver(Resolver const &) = delete;
        Resolver(Resolver &&) = delete;

        virtual ~Resolver();

        virtual /* DNS */
        srv_callback_t &SrvLookup(std::string const &domain);

        virtual svcb_callback_t &SvcbLookup(std::string const &domain);

        virtual addr_callback_t &AddressLookup(std::string const &hostname);

        virtual tlsa_callback_t &TlsaLookup(short unsigned int port, std::string const &hostname);

        /* DNS callbacks */
        void a_lookup_done(int err, struct ub_result *result);

        void srv_lookup_done(int err, struct ub_result *result);

        void svcb_lookup_done(int err, struct ub_result *result);

        void tlsa_lookup_done(int err, struct ub_result *result);

    private:
        bool m_dnssec_required;
        TLS_PREFERENCE m_tls_preference;

    protected:
        Address m_current_arec; // Built from A and AAAA
        Srv m_current_srv; // Built from _xmpp-server and _xmpps-server
        srv_callback_t m_srv_pending;
        svcb_callback_t m_svcb_pending;
        std::map<std::string, addr_callback_t, std::less<>> m_a_pending;
        std::map<std::string, tlsa_callback_t, std::less<>> m_tlsa_pending;
        std::unordered_set<int> m_queries;
    };
}


template <>
struct fmt::formatter<Metre::DNS::TlsaRR::CertUsage> : fmt::formatter<std::string> {
    auto format(const Metre::DNS::TlsaRR::CertUsage c, fmt::format_context& ctx) const {
        switch (c) {
            using enum Metre::DNS::TlsaRR::CertUsage;
            case CertConstraint:
                return fmt::formatter<std::string>::format("CertConstraint (PKIX-EE)", ctx);
            case CAConstraint:
                return fmt::formatter<std::string>::format("CAConstraint (PKIX-CA)", ctx);
            case DomainCert:
                return fmt::formatter<std::string>::format("DomainCert (DANE-EE)", ctx);
            case TrustAnchorAssertion:
                return fmt::formatter<std::string>::format("TrustAnchorAssertion (DANE-TA)", ctx);
            default:
                return fmt::formatter<std::string>::format("[Unknown enum value]", ctx);
        }
    }
};

template <>
struct fmt::formatter<Metre::DNS::TlsaRR::Selector> : fmt::formatter<std::string> {
    auto format(const Metre::DNS::TlsaRR::Selector c, fmt::format_context& ctx) const {
        switch (c) {
            using enum Metre::DNS::TlsaRR::Selector;
            case SubjectPublicKeyInfo:
                return fmt::formatter<std::string>::format("SubjectPublicKeyInfo", ctx);
            case FullCert:
                return fmt::formatter<std::string>::format("FullCert", ctx);
            default:
                return fmt::formatter<std::string>::format("[Unknown enum value]", ctx);
        }
    }
};

template <>
struct fmt::formatter<Metre::DNS::TlsaRR::MatchType> : fmt::formatter<std::string> {
    auto format(const Metre::DNS::TlsaRR::MatchType c, fmt::format_context& ctx) const {
        switch (c) {
            using enum Metre::DNS::TlsaRR::MatchType;
            case Sha256:
                return fmt::formatter<std::string>::format("SHA-256", ctx);
            case Sha512:
                return fmt::formatter<std::string>::format("SHA-512", ctx);
            case Full:
                return fmt::formatter<std::string>::format("Full", ctx);
            default:
                return fmt::formatter<std::string>::format("[Unknown enum value]", ctx);
        }
    }
};


#endif
