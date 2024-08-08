//
// Created by dwd on 13/04/19.
//


#ifndef METRE_CORE_H
#define METRE_CORE_H

#include "defs.h"

#include <functional>
#include <memory>
#include <string>

struct event_base;
struct sockaddr;

namespace Metre {
    namespace Router {
        std::shared_ptr<NetSession> session_by_address(std::string const &remote_addr, unsigned short port);

        std::shared_ptr<NetSession> session_by_domain(std::string const &remote_addr);

        void register_session_domain(std::string const &dom, NetSession &);

        std::shared_ptr<NetSession>
        connect(std::string const &fromd, std::string const &tod, std::string const &hostname, struct sockaddr *addr,
                unsigned short port, SESSION_TYPE stype, TLS_MODE tls_mode);

        std::shared_ptr<NetSession> session_by_stream_id(std::string const &stream_id);

        std::shared_ptr<NetSession> session_by_serial(long long int);

        void register_stream_id(std::string const &, NetSession &);

        void unregister_stream_id(std::string const &);

        void defer(std::function<void()> &&);

        void defer(std::function<void()> &&, long seconds);
        void defer(std::function<void()> &&, struct timeval seconds);

        void main(std::function<bool()> const &);

        void reload();

        void quit();

        struct event_base *event_base();
    }
}

#endif //METRE_CORE_H
