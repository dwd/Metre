//
// Created by dwd on 30/08/16.
//

#ifndef METRE_HTTP_H
#define METRE_HTTP_H

#include <sigslot/sigslot.h>
#include <map>

struct evhttp_request;
struct X509_crl_st;

namespace Metre {
    class Http {
    public:
        typedef sigslot::signal<sigslot::thread::st, std::string const &, int, struct X509_crl_st *> crl_callback_t;
        typedef sigslot::signal<sigslot::thread::st, std::string const &, int, std::string const &> ocsp_callback_t;

    private:
        std::map<std::string, crl_callback_t> m_crl_waiting;
        std::map<std::string, ocsp_callback_t> m_ocsp_waiting;
        std::map<std::string, struct X509_crl_st *> m_crl_cache;
        std::map<std::string, std::string> m_ocsp_cache;
        std::map<std::uintptr_t, std::string> m_requests;
        std::uintptr_t m_req = 0;

    public:
        Http();

        static crl_callback_t &crl(std::string const &uri);

        static ocsp_callback_t &ocsp(std::string const &uri);

    private:
        static Http & http();

        crl_callback_t &do_crl(std::string const &uri);

        void done_crl(struct evhttp_request *, std::uintptr_t key);

        static void s_done_crl(struct evhttp_request *, void *arg);

        ocsp_callback_t &do_ocsp(std::string const &uri);

        void done_ocsp(struct evhttp_request *, std::uintptr_t key);

        static void s_done_ocsp(struct evhttp_request *, void *arg);
    };
}

#endif //METRE_HTTP_H
