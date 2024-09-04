//
// Created by dwd on 30/08/16.
//

#ifndef METRE_HTTP_H
#define METRE_HTTP_H

#include "sigslot.h"
#include <map>

struct evhttp_request;
struct X509_crl_st;

namespace Metre {
    class Http {
    public:
        using crl_callback_t = sigslot::signal<std::string const &, int, struct X509_crl_st *>;

    private:
        std::map<std::string, crl_callback_t, std::less<>> m_crl_waiting;
        std::map<std::string, struct X509_crl_st *, std::less<>> m_crl_cache;
        std::map<std::uintptr_t, std::string> m_requests;
        std::uintptr_t m_req = 0;

    public:
        Http() = default;
        static crl_callback_t &crl(std::string const &uri);
    private:
        static Http & http();
        crl_callback_t &do_crl(std::string const &uri);
        void done_crl(struct evhttp_request *, std::uintptr_t key);
        static void s_done_crl(struct evhttp_request *, void *arg);
    };
}

#endif //METRE_HTTP_H
