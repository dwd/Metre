//
// Created by dwd on 30/08/16.
//

#include <http.h>
#include <router.h>
#include <evhttp.h>
#include <event2/bufferevent_ssl.h>
#include <log.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace Metre;

namespace Metre {
    Http * s_http = 0;
}

Http & Http::http() {
    if (!s_http) s_http = new Http();
    return *s_http;
}

Http::crl_callback_t &Http::crl(std::string const &uri) {
    return Http::http().do_crl(uri);
}

void Http::s_done_crl(struct evhttp_request *req, void *arg) {
    auto key = reinterpret_cast<std::uintptr_t>(arg);
    Http::http().done_crl(req, key);
}

void Http::done_crl(struct evhttp_request *req, std::uintptr_t key) {
    auto iter = m_requests.find(key);
    if (iter == m_requests.end()) {
        METRE_LOG(Metre::Log::ERR, "Unable to locate request key");
        return;
    }
    std::string const & uri = iter->second;
    int response = (req ? evhttp_request_get_response_code(req) : 500);
    METRE_LOG(Log::INFO, "HTTP GET for " << uri << " returned " << response);
    if ((response / 100) == 2) {
        auto buffer = evhttp_request_get_input_buffer(req);
        auto len = evbuffer_get_length(buffer);
        auto buf = evbuffer_pullup(buffer, len);
        X509_CRL *data = d2i_X509_CRL(nullptr, const_cast<const unsigned char **>(&buf), len);
        if (data) {
            m_crl_cache[uri] = data;
            m_crl_waiting[uri].emit(uri, 200, data);
            m_crl_waiting[uri].disconnect_all();
        } else {
            while (unsigned long ssl_err = ERR_get_error()) {
                char error_buf[1024];
                METRE_LOG(Metre::Log::DEBUG, " :: " << ERR_error_string(ssl_err, error_buf));
            }
            m_crl_waiting[uri].emit(uri, 400, nullptr);
            m_crl_waiting[uri].disconnect_all();
        }
        METRE_LOG(Log::INFO, " - Got " << len << " bytes");
    } else {
        m_crl_waiting[uri].emit(uri, response, nullptr);
        m_crl_waiting[uri].disconnect_all();
    }
    m_requests.erase(key);
}

Http::crl_callback_t &Http::do_crl(std::string const &urix) {
    std::string uri{urix}; // Destructively parsed
    // Step one: Look in cache.
    auto iter = m_crl_cache.find(uri);
    if (iter != m_crl_cache.end() && iter->second) {
        auto data = iter->second;
        auto nextupdate = X509_CRL_get0_nextUpdate(data);
        int day, sec;
        ASN1_TIME_diff(&day, &sec, nullptr, nextupdate);
        if (day > 0) {
            // nextUpdate is today sometime - refetch.,
            Router::defer([data, uri, this]() {
                m_crl_waiting[uri].emit(uri, 200, data);
                m_crl_waiting[uri].disconnect_all();
            });
            return m_crl_waiting[uri];
        }
    }
    // Step two: Are we fetching this already?
    for (auto const &k : m_requests) {
        if (k.second == uri) {
            return m_crl_waiting[uri];
        }
    }
    // Step three: Actually issue a new HTTP request:
    try {
        auto parsed = evhttp_uri_parse(uri.c_str());
        if (!parsed) {
            throw std::runtime_error("Cannot parse URI " + uri);
        }
        if (!evhttp_uri_get_scheme(parsed)) {
            throw std::runtime_error("Cannot locate scheme in " + uri);
        }
        std::string scheme = evhttp_uri_get_scheme(parsed);
        bool ssl = false;
        if (scheme == "https") {
            ssl = true;
        } else if (scheme != "http") {
            throw std::runtime_error("Unknown scheme in " + uri);
        }
        if (!evhttp_uri_get_host(parsed)) throw std::runtime_error("Cannot locate host in " + uri);
        std::string host = evhttp_uri_get_host(parsed);
        int port = evhttp_uri_get_port(parsed);
        if (port < 0) port = (ssl ? 443 : 80);
        evhttp_connection * evcon = nullptr;
        if (ssl) {
            SSL_CTX * ssl_ctx = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);
            SSL * ssl = SSL_new(ssl_ctx);
            SSL_set_tlsext_host_name(ssl, host.c_str());
            auto bev = bufferevent_openssl_socket_new(Router::event_base(), -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
            evcon = evhttp_connection_base_bufferevent_new(Router::event_base(), nullptr, bev, host.c_str(), port);
       } else {
            evcon = evhttp_connection_base_new(Router::event_base(), nullptr, host.c_str(), port);
        }
        // TODO config
        //evhttp_connection_set_retries(evcon, 3);
        //evhttp_connection_set_timeout(evcon, 5); // seconds
        m_requests[++m_req] = uri;
        auto request = evhttp_request_new(Http::s_done_crl, reinterpret_cast<void *>(m_req));
        evhttp_add_header(evhttp_request_get_output_headers(request), "Host", host.c_str());
        if (!request) {
            throw std::runtime_error("evhttp couldn't create for " + uri);
        }
        auto res = evhttp_make_request(evcon, request, EVHTTP_REQ_GET, uri.c_str());
        if (res != 0) {
            throw std::runtime_error("evhttp failed for " + uri);
        }
        METRE_LOG(Log::INFO, "Performing HTTP GET for " << uri);
    } catch(std::runtime_error & e) {
        METRE_LOG(Log::INFO, "HTTP GET for " << uri << " failed, " << e.what());
        Router::defer([uri,this]() {
            m_crl_waiting[uri].emit(uri, 500, nullptr);
            m_crl_waiting[uri].disconnect_all();
        });
    }
    return m_crl_waiting[uri];
}
