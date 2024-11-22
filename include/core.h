//
// Created by dwd on 13/04/19.
//


#ifndef METRE_CORE_H
#define METRE_CORE_H

#include "defs.h"

#include <functional>
#include <memory>
#include <string>

#include <covent/covent.h>

struct sockaddr;

namespace Metre::Router {
    std::shared_ptr<XMLStream> session_by_address(std::string const &remote_addr, unsigned short port);
    void register_session_address(std::string const &remote_addr, unsigned short port, XMLStream &);

    std::shared_ptr<XMLStream> session_by_domain(std::string const &remote_addr);

    void register_session_domain(std::string const &dom, covent::Session const &);

    std::shared_ptr<XMLStream> session_by_stream_id(std::string const &stream_id);

    std::shared_ptr<XMLStream> session_by_serial(covent::Session::id_type);

    void register_stream_id(std::string const &, XMLStream const &);

    void unregister_stream_id(std::string const &);
}

#endif //METRE_CORE_H
