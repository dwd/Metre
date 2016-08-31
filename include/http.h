//
// Created by dwd on 30/08/16.
//

#ifndef METRE_HTTP_H
#define METRE_HTTP_H

#include <sigslot/sigslot.h>
#include <map>

struct evhttp_request;

namespace Metre {
    class Http {
    public:
        typedef sigslot::signal<sigslot::thread::st, std::string const &, int, std::string const &> callback_t;
        std::map<std::string, callback_t> m_waiting;
        std::map<std::string, std::string> m_cache;
        std::map<std::uintptr_t, std::string> m_requests;
        std::uintptr_t m_req = 0;

        Http();
        static callback_t & get(std::string const & uri);

    private:
        static Http & http();
        callback_t & do_get(std::string const & uri);
        void done_get(struct evhttp_request *, std::uintptr_t key);
        static void s_done_get(struct evhttp_request *, void * arg);
    };
}

#endif //METRE_HTTP_H
