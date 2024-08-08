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

#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include "router.h"
#include "netsession.h"
#include "config.h"
#include "log.h"
#include "tls.h"
#include <memory>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/decoder.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <evdns.h>
#include <http.h>

using namespace Metre;
using namespace rapidxml;
namespace {
    std::string const dh_str_4096 = R"(-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAk9O+tKPjzXUxBEnRO6ktnsQh+oMxDS/3QDmKh9cEaoGx81gzH5Xl
Iiu5GZqKND90QOlkwXcyjGzXdIxU8QEfSvo6zsIkyhPuu4ZkOuy8TMvG34Jgv19k
Pbz6n5u9HhsiasLaLd8Cf3Dm/uaA+19PjLA8hlVoj+Tqvmk/3z1tDIRGkynLUOxF
83DEwmocOHWD2y1FBlDL60Noo5yKGf9zyDnTRN6uOTO7+LZW1bglyQ2GrzL291ac
WpxP2gcmdEbEmrT2jCaJALDgtU3cWmW19Nvy5sgtFEZ9l4dWpyq7sRncUBHwo8Z+
5x/WJKXgZdzo68YK5CtbmD57Zn1iy1eUAB9kxR8JHDTPOPg6LxfK3uecWNyS5T/I
xSSB+jvqf39ayA+mcQm9oKH+VY5w3dd7B+0oiFemP4li70Ym9K6uKpStbYUFmUbg
lUojTn/2/wIbq7VFylqlc659VfKY0yQ23eOySO2u6MhpxCsexG5i6NbqfHP+06i6
sIuZsWjDoaOQo1e2n2zeTwYt1qeyrt1ChVy3eXHN0BHhqF5ltez0r0IoZ/AwQ3rz
Zoz/Ee1FLNFOLdghBXTNGORdbSC3O8UEoq13vwkgf3v0sfewhzdTzXIhvLCWQlNH
UcahR3Wj0J6PZ6XVMjKSRX2w97tXDyGfaUXRJnPNrOzyJIo/gE9J9K8CAQI=
-----END DH PARAMETERS-----
)";
    std::string const dh_str_3072 = R"(-----BEGIN DH PARAMETERS-----
MIIBiAKCAYEA61Pa5ngNNeU3sCgh30WrB7ktstxHs/i7haokrhSsQGK4+Ha4w/UI
KnQXT4WNj1tJTUW9rCHuW6gYNCpIzqVi32a0iBmE7fVQvM+5lpFbB/5xITJZTmUu
4Z9RGJRw8klgS8G3qwHc1hkPxdAtP2nfvpc7W/iOncz9ayQ05pn9cKSBFWTSoM9d
8oBD7zQ/35lovoFx2zaO8p2FmYxH3SS+qziQHU+sALN1Z90vV1/eLBUnlfLFEhqU
u6K5klqSM1Bi7gH5xhzD0b+NMm4xjojIUXwpblmim4yAbfmS/W1tiGndzO/4W58X
StnV8hzHqonVgvbkskfxaj9jncu5oLpRdv87eEE6OFtjQatLI5qg8GuHqsYGgRRS
4fyBjkJXxzK+Ltnssemu8D9T2KbagsKAwZ/9clBhsCeCD6ex3dkRwcYNv6+7BCNK
ZCg9+ojbvTMqBNWm2vblt/mRp7DUg9jSDPldwp6DwKmQV9XFV8NnSjJFlzoXFo4x
xK4ykAz8PqxfAgEC
-----END DH PARAMETERS-----
)";
    std::string const dh_str_2236 = R"(-----BEGIN DH PARAMETERS-----
MIIBHwKCARgMe1n9pTQMdQp/0kZfq6qo7s1aBBJE1fm5324517qc5p85jehRW3NQ
Zo8L47A80WopBsRxHWLentDfjofoVZIsj2rkYcAPWtXs6S1cY0FpzKE6NJ1R+uEw
n6oodtKjncmXbLdcud/sw0GHeorYX17OfpGu5skqJFQGDj20FIpxmDvZQBaN6E4H
cbvfxfZw5kQjYFQTRr4Lo19veOagChSS8xPlA6LpnRkAd0GJBwUpBozXuaZRK78v
9oluK6tLNcA9XdXwQWj77wr9AzCIvmqTzjRRXukVACFVNyBOhBrCLEN4jIlfxMpY
BckUuWW9ryzNRkdSpR9BOLeYnBbqyTR+zrI7ZQHBHNcCR+QqguhxKopRFibOUGIH
AgEC
-----END DH PARAMETERS-----
)";
    std::string const dh_str_2048 = R"(-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA/cHG04YT8IdL4GaMId//cf+M1YhI3wLqWa3Ad2rc2HlObKPKSBSR
LwiUy62WdhcBJsSmhFKCPpQ3ma7YpbTBKFLWJ0SdaspipGdYIk8TsgN5S9WL7LxA
HsCdPC8SnjC8k7G35vulwKVOdfhOeyRGjEsvuz2JohlIFQUOLXuGeuTSZjRVd4md
1GEYuuYCKTSJvnKDZ2PCen9Kn5726x9ZP/kDuFMopqH5uTfTbtimZ6Bhaxjnft+0
EAhurLOF+ETqJav393WOQH5lwm/Eorr6lfl1kwQhpNUEAsLWYz0y46e7CO31tzIf
TjuAW7Ho3gCaeg7QiGpGiwr+2Yt4j8hl7wIBAg==
-----END DH PARAMETERS-----
)";
    std::string dh_str_1024 = R"(-----BEGIN DH PARAMETERS-----
MIGHAoGBAILtTtZQdevX4/JhgmxuMRRTEQlFtp491NLc7nkykFrGIOIhnLhQEXaj
ZPvubjYBNqfMEkPAefyNEwVrIL9Wg9+K4D130Lqt//qLUJlWT60+LlbdLUdBmeMh
EjhZjvPJOKqTisDI6g9A9ak87cfIh26eYj+vm5JOnjYltmaZ6U83AgEC
-----END DH PARAMETERS-----
)";
    EVP_PKEY * get_builtin_dh(int keylength) {
        const char * keydata = dh_str_2236.data();
        size_t keylen = dh_str_2236.size();
        int actual_keylen = 2236;
        static std::map<int,EVP_PKEY *> s_cache;
        if (keylength == 0) {
            // Defaults as above.
        } else if (keylength < 2048) {
            keydata = dh_str_1024.data();
            keylen = dh_str_1024.size();
            actual_keylen = 1024;
        } else if (keylength < 2236) {
            keydata = dh_str_2048.data();
            keylen = dh_str_2048.size();
            actual_keylen = 2048;
        } else if (keylength < 3072) {
            keydata = dh_str_2236.data();
            keylen = dh_str_2236.size();
            actual_keylen = 2236;
        } else if (keylength < 4096) {
            keydata = dh_str_3072.data();
            keylen = dh_str_3072.size();
            actual_keylen = 3072;
        } else if (keylength == 4096) {
            keydata = dh_str_4096.data();
            keylen = dh_str_4096.size();
            actual_keylen = 4096;
        } else {
            throw std::runtime_error("Don't have a packages DH key that size, sorry.");
        }
        if (s_cache.contains(actual_keylen)) {
            return s_cache[actual_keylen];
        }
        EVP_PKEY * evp = nullptr;
        auto * dctx = OSSL_DECODER_CTX_new_for_pkey(&evp, "PEM", nullptr, "DH", OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, NULL, NULL);
        if(OSSL_DECODER_from_data(dctx, reinterpret_cast<const unsigned char **>(&keydata), &keylen)) {
            EVP_PKEY_up_ref(evp);
            s_cache[actual_keylen] = evp;
            return evp;
        } else {
            throw std::runtime_error("Decoding of internal DH params failed");
        }
    }
    EVP_PKEY * get_file_dh(std::string const & filename) {
        EVP_PKEY * evp = nullptr;
        static std::map<std::string,EVP_PKEY *> s_cache;
        auto * dctx = OSSL_DECODER_CTX_new_for_pkey(&evp, "PEM", nullptr, "DH", OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, NULL, NULL);
        auto * fp = fopen(filename.c_str(), "rb");
        if(OSSL_DECODER_from_fp(dctx, fp)) {
            EVP_PKEY_up_ref(evp);
            s_cache[filename] = evp;
            return evp;
        } else {
            throw std::runtime_error("Decoding of external DH params failed");
        }
    }

    void setup_session(SSL *ssl, std::string const &remote_domain) {
        Config::Domain const &domain = Config::config().domain(remote_domain);
        SSL_dane_enable(ssl, domain.domain().c_str());
        // Cipherlist
        SSL_set_cipher_list(ssl, domain.cipherlist().c_str());
        // Min / max TLS versions.
        if (auto v = domain.min_tls_version(); v != 0) {
            SSL_set_min_proto_version(ssl, v);
        }
        if (auto v = domain.max_tls_version(); v != 0) {
            SSL_set_max_proto_version(ssl, v);
        }
        // DH parameters
        std::string const &dhparam = domain.dhparam();
        if (dhparam == "auto") {
            SSL_set_dh_auto(ssl, 1);
        } else {
            EVP_PKEY * evp = nullptr;
            try {
                int keylen = std::stoi(dhparam);
                evp = get_builtin_dh(keylen);
            } catch (std::invalid_argument & e) {
                // Pass
            }
            if (!evp) {
                evp = get_file_dh(dhparam);
            }
            SSL_set0_tmp_dh_pkey(ssl, evp);
        }
    }
}

namespace {
    const std::string tls_ns = "urn:ietf:params:xml:ns:xmpp-tls";

    class StartTls : public Feature, public sigslot::has_slots {
    public:
        explicit StartTls(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<StartTls> {
        public:
            Description() : Feature::Description<StartTls>(tls_ns, FEAT_SECURE) {};

            sigslot::tasklet<bool> offer(std::shared_ptr<sentry::span>, optional_ptr<xml_node<>> node, XMLStream &s) override {
                if (s.secured()) co_return false;
                SSL_CTX *ctx = Config::config().domain(s.local_domain()).ssl_ctx();
                if (!ctx) co_return false;
                auto feature = node->append_element({tls_ns, "starttls"});
                if (Config::config().domain(s.local_domain()).require_tls()) {
                    feature->append_element("required");
                }
                co_return true;
            }
        };

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction>, rapidxml::optional_ptr<rapidxml::xml_node<>> node) override {
            METRE_LOG(Metre::Log::DEBUG, "Handle StartTLS");
            if ((node->name() == "starttls" && m_stream.direction() == INBOUND) ||
                (node->name() == "proceed" && m_stream.direction() == OUTBOUND)) {
                if (!m_stream.remote_domain().empty()) {
                    m_stream.logger().debug("Negotiating TLS");
                    start_tls(m_stream, true);
                    co_return true;
                } else if (m_stream.type() == COMP) {
                    start_tls(m_stream, true);
                    co_return true;
                } else {
                    xml_document<> doc;
                    doc.append_element({tls_ns, "failure"});
                    m_stream.send(doc);
                    co_return false;
                }
            }
            co_return false;
        }

        bool negotiate(rapidxml::optional_ptr<rapidxml::xml_node<>> offer) override {
            if (m_stream.secured()) {
                m_stream.logger().warn("Remote is offering TLS but we already have it?");
                return false;
            }
            SSL_CTX *ctx = Config::config().domain(m_stream.local_domain()).ssl_ctx();
            if (ctx) {
                xml_document<> d;
                d.append_element({tls_ns, "starttls"});
                m_stream.send(d);
                return true;
            } else {
                m_stream.logger().warn("Can't negotiate TLS as have no CTX - maybe configure a chain and pkey for {}?", m_stream.local_domain());
                if (offer->first_node("required")) {
                    m_stream.logger().warn("Remote end requires TLS, this is likely to go wrong.");
                }
                if (Config::config().domain(m_stream.remote_domain()).require_tls()) {
                    m_stream.logger().warn("We require TLS, aborting.");
                    throw Metre::stanza_policy_violation("We require TLS but you don't offer it, boo!");
                }
                return false;
            }
        }
    };

    DECLARE_FEATURE(StartTls, S2S);
    DECLARE_FEATURE(StartTls, C2S);
    DECLARE_FEATURE(StartTls, COMP);
}

namespace Metre {
    sigslot::tasklet<void> fetch_crls(std::shared_ptr<sentry::span>, spdlog::logger & logger, const SSL *ssl, X509 *cert) {
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
        SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_CTX *st = X509_STORE_CTX_new();
        X509_STORE_CTX_init(st, store, cert, chain);
        X509_verify_cert(st);
        STACK_OF(X509) *verified = X509_STORE_CTX_get1_chain(st);
        std::__cxx11::list<std::string> crls;
        for (int certnum = 0; certnum != sk_X509_num(verified); ++certnum) {
            auto current_cert = sk_X509_value(verified, certnum);
            std::unique_ptr<STACK_OF(DIST_POINT), std::function<void(STACK_OF(DIST_POINT) *)>> crldp_ptr{
                    (STACK_OF(DIST_POINT) *) X509_get_ext_d2i(current_cert, NID_crl_distribution_points, nullptr, nullptr),
                    [](STACK_OF(DIST_POINT) *crldp) { sk_DIST_POINT_pop_free(crldp, DIST_POINT_free); }};
            if (crldp_ptr) {
                auto crldp = crldp_ptr.get();
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
                                logger.info("verify_tls: Fetching CRL - {}", uristr);
                                Http::crl(uristr);
                                // We don't await here, just get them going in parallel.
                            }
                        }
                    }
                }
            }
        }
        // Now we wait for them all. Order doesn't matter - we'll get new copies
        // in the rare case we happen to cross an expiry boundary, but that's
        // no biggie.
        for (auto & uri : crls) {
            auto [uristr, code, crl] = co_await Http::crl(uri);
            logger.info("verify_tls: Fetched CRL - {}, with code {}", uristr, code);
            if (!X509_STORE_add_crl(store, crl)) {
                // Erm. Whoops? Probably doesn't matter.
                ERR_clear_error();
            }
        }
    }

    int reverify_callback(int preverify_ok, X509_STORE_CTX * st) {
        std::array<char, 256> buffer{};
        std::string cert_name{"<no cert name>"};
        if (auto cert = X509_STORE_CTX_get_current_cert(st)) {
            X509_NAME_oneline(X509_get_subject_name(cert), buffer.data(), buffer.size());
            cert_name = buffer.data();
        }
        auto depth = X509_STORE_CTX_get_error_depth(st);
        if (preverify_ok) {
            Config::config().logger().info("Cert {} passed reverification: {}", depth, cert_name);
        } else {
            Config::config().logger().info("Cert {} failed reverification: {}", depth, cert_name);
            Config::config().logger().info("Error is {}", X509_verify_cert_error_string(X509_STORE_CTX_get_error(st)));
        }
        return preverify_ok;
    }

/**
     * This is a fairly massive coroutine, but I've kept it this way because it's
     * difficult to break apart. Indeed, I pulled it together out of two major callback
     * loops which were pretty nasty in complexity terms.
     *
     * @param stream
     * @param route
     * @return true if TLS verified correctly.
     */
    sigslot::tasklet<bool> verify_tls(std::shared_ptr<sentry::span> span, XMLStream &stream, Route &route) {
        SSL *ssl = bufferevent_openssl_get_ssl(stream.session().bufferevent());
        auto & domain = Config::config().domain(route.domain());
        if (!ssl) co_return false; // No TLS.
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (!cert) {
            stream.logger().info("verify_tls: No cert, so no auth");
            co_return false;
        }
        if (X509_V_OK != SSL_get_verify_result(ssl)) {
            stream.logger().info("verify_tls: Cert failed verification but rechecking anyway.");
        } // TLS failed basic verification.
        stream.logger().debug("verify_tls: [Re]verifying TLS for {}", domain.domain());
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
        SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
        X509_STORE *free_store = nullptr;
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_VERIFY_PARAM *vpm = X509_VERIFY_PARAM_new();
        if (domain.auth_pkix_status()) {
            co_await fetch_crls(span->start_child("tls", "fetch_crls"), stream.logger(), ssl, cert);
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK_ALL);
        }
        X509_VERIFY_PARAM_set1_host(vpm, domain.domain().c_str(), domain.domain().size());
        // Add RFC 6125 additional names.
        auto gathered = co_await domain.gather(span->start_child("gather", domain.domain()));
        for (auto const &host : gathered.gathered_hosts) {
            stream.logger().debug("Adding gathered hostname {}", host);
            X509_VERIFY_PARAM_add1_host(vpm, host.c_str(), host.size());
        }
        X509_STORE_CTX *st = X509_STORE_CTX_new();
//        if (!domain.pkix_tas().empty()) {
//            store = free_store = X509_STORE_new();
//            for (auto * ta : domain.pkix_tas()) {
//                X509_STORE_add_cert(store, ta);
//            }
//        }
        X509_STORE_CTX_set0_param(st, vpm); // Hands ownership to st.
        // Fun fact: We can only add these to SSL_DANE via the connection.
        for (auto const & rr : gathered.gathered_tlsa) {
            stream.logger().debug("Adding TLSA {} / {} / {} with {} bytes of match data", rr.certUsage, rr.selector, rr.matchType, rr.matchData.length());
            if (0 == SSL_dane_tlsa_add(ssl, rr.certUsage, rr.selector, rr.matchType,
                              reinterpret_cast<const unsigned char *>(rr.matchData.data()), rr.matchData.length())) {
                stream.logger().warn("TLSA record rejected");
            }
        }
        X509_STORE_CTX_init(st, store, cert, chain);
        X509_STORE_CTX_set0_dane(st, SSL_get0_dane(ssl));
        X509_STORE_CTX_set_verify_cb(st, reverify_callback);
        stream.logger().info("Reverification for {} by {}", route.domain(), route.local());
        bool valid = (X509_verify_cert(st) == 1);
        if (valid) {
            if (gathered.gathered_tlsa.empty()) {
                stream.logger().info("verify_tls: PKIX verification succeeded");
            } else {
                stream.logger().info("verify_tls: DANE verification succeeded");
            }
        } else {
            auto error = X509_STORE_CTX_get_error(st);
            auto depth = X509_STORE_CTX_get_error_depth(st);
            char buf[1024];
            stream.logger().warn("verify_tls: Chain failed validation: {} (at depth {})", ERR_error_string(error, buf),
                                 depth);
        }
        X509_STORE_CTX_free(st);
        if (free_store) X509_STORE_free(free_store);
        co_return valid;
    }

    bool start_tls(XMLStream &stream, bool send_proceed) {
        SSL_CTX *ctx = Config::config().domain(stream.local_domain()).ssl_ctx();
        if (!ctx) throw std::runtime_error("Failed to load certificates for " + stream.local_domain());
        SSL *ssl = SSL_new(ctx);
        setup_session(ssl, stream.remote_domain());
        if (!ssl) throw std::runtime_error("Failure to initiate TLS, sorry!");
        bufferevent_ssl_state st = BUFFEREVENT_SSL_ACCEPTING;
        if (stream.direction() == INBOUND) {
            SSL_set_accept_state(ssl);
            if (send_proceed) {
                xml_document<> d;
                auto n = d.allocate_node(node_element, "proceed");
                n->append_attribute(d.allocate_attribute("xmlns", tls_ns.c_str()));
                d.append_node(n);
                stream.send(d);
            }
            stream.restart();
        } else { //m_stream.direction() == OUTBOUND
            SSL_set_connect_state(ssl);
            SSL_set_tlsext_host_name(ssl, stream.remote_domain().c_str());
            st = BUFFEREVENT_SSL_CONNECTING;
        }
        struct bufferevent *bev = stream.session().bufferevent();
        struct bufferevent *bev_ssl = bufferevent_openssl_filter_new(bufferevent_get_base(bev), bev, ssl, st,
                                                                     BEV_OPT_CLOSE_ON_FREE);
        stream.session().bufferevent(bev_ssl); // Might set it to NULL - this is OK!
        if (!bev_ssl) throw std::runtime_error("Cannot create OpenSSL filter");
        stream.set_secured();
        return true;
    }
}
