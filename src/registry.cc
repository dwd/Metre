//
// Created by dwd on 11/22/24.
//

#include "core.h"
#include "xmlstream.h"

namespace {
    struct SessionRegistry {
        using map_type = std::map<std::string, std::weak_ptr<Metre::XMLStream>, std::less<>>;
        map_type by_domain;
        map_type by_stream_id;
        map_type by_hostport;
    };
    SessionRegistry & sessions() {
        static SessionRegistry sess;
        return sess;
    }
    std::shared_ptr<Metre::XMLStream> get(SessionRegistry::map_type & map, std::string const & key) {
        if (auto it = map.find(key); it != map.end()) {
            auto ret = it->second.lock();
            if (ret) {
                return ret;
            }
            map.erase(key);
        }
        return {};
    }
}

std::shared_ptr<Metre::XMLStream> Metre::Router::session_by_serial(covent::Session::id_type id) {
    auto & loop = covent::Loop::main_loop();
    auto sptr = loop.session(id);
    return std::dynamic_pointer_cast<Metre::XMLStream>(sptr);
}


void Metre::Router::register_session_domain(const std::string &dom, const covent::Session & session) {
    sessions().by_domain[dom] = Metre::Router::session_by_serial(session.id());
}

void Metre::Router::register_stream_id(const std::string & stream_id, const Metre::XMLStream & session) {
    sessions().by_stream_id[stream_id] = Metre::Router::session_by_serial(session.id());
}

void Metre::Router::unregister_stream_id(const std::string & stream_id) {
    if (sessions().by_stream_id.contains(stream_id)) {
        sessions().by_stream_id.erase(stream_id);
    }
}

std::shared_ptr<Metre::XMLStream> Metre::Router::session_by_domain(const std::string &remote_addr) {
    return get(sessions().by_domain, remote_addr);
}

std::shared_ptr<Metre::XMLStream> Metre::Router::session_by_stream_id(const std::string &stream_id) {
    return get(sessions().by_stream_id, stream_id);
}

std::shared_ptr<Metre::XMLStream> Metre::Router::session_by_address(const std::string &remote_addr,
                                                                    unsigned short port) {
    auto hostport = fmt::format("{}:{}", remote_addr, port);
    return get(sessions().by_hostport, hostport);
}

void Metre::Router::register_session_address(const std::string &remote_addr, unsigned short port, Metre::XMLStream & session) {
    auto hostport = fmt::format("{}:{}", remote_addr, port);
    sessions().by_hostport[hostport] = Metre::Router::session_by_serial(session.id());
}
