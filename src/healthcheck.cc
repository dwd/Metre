//
// Created by dwd on 9/19/24.
//

#include "config.h"
#include <iostream>
#include <openssl/ssl.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>

namespace {
    struct callback_arg {
        struct event_base * base;
        bool healthcheck_response;
    };

    void request_callback(struct evhttp_request *req, void *arg) {
        auto * cb = static_cast<callback_arg *>(arg);
        if (req) {
            int response_code = evhttp_request_get_response_code(req);
            if (response_code == HTTP_OK) {
                cb->healthcheck_response = true;
                std::cerr << "Healthcheck is happy bunny" << std::endl;
            } else {
                std::cerr << "Healthcheck failure, status code " << response_code << std::endl;
            }
        } else {
            std::cerr << "Healthcheck received no response." << std::endl;
        }
        event_base_loopbreak(cb->base);
    }
}

bool Metre::Config::run_healthcheck(unsigned short port, bool tls) {
    struct event_base* base = event_base_new();
    struct evhttp_connection* conn = nullptr;

    if (tls) {
        SSL_CTX * ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);
        SSL * ssl = SSL_new(ssl_ctx);
        auto bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        conn = evhttp_connection_base_bufferevent_new(base, nullptr, bev, "127.0.0.1", port);
    } else {
        conn = evhttp_connection_base_new(base, nullptr, "127.0.0.1", port);
    }
    struct callback_arg cb = {base, false};
    struct evhttp_request* req = evhttp_request_new(request_callback, &cb);

    // Set the request path (e.g., "/api/status")
    evhttp_make_request(conn, req, EVHTTP_REQ_GET, "/api/status");

    event_base_dispatch(base);

    evhttp_connection_free(conn);
    event_base_free(base);

    return cb.healthcheck_response;
}
