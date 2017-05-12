//
// Created by dwd on 11/05/17.
//

#include <endpoint.h>
#include <router.h>
#include <config.h>

using namespace Metre;

Endpoint::Endpoint(Jid const &jid) : m_jid(jid) {}

void Endpoint::process(Stanza const &stanza) {
    if (stanza.name() == Message::name) {
        process(dynamic_cast<Message const &>(stanza));
    } else if (stanza.name() == Presence::name) {
        process(dynamic_cast<Presence const &>(stanza));
    } else if (stanza.name() == Iq::name) {
        process(dynamic_cast<Iq const &>(stanza));
    } else {
        throw stanza_service_unavailable();
    }
}

void Endpoint::process(Presence const &presence) {
    throw stanza_service_unavailable();
}

void Endpoint::process(Message const &message) {
    throw stanza_service_unavailable();
}

void Endpoint::process(Iq const &iq) {
    switch (iq.type()) {
        case Iq::GET:
        case Iq::SET: {
            auto payload = iq.node()->first_node();
            if (payload) {
                std::string xmlns{payload->xmlns(), payload->xmlns_size()};
                std::string local{payload->name(), payload->name_size()};
                auto i = m_handlers.find(std::make_pair(xmlns, local));
                if (i != m_handlers.end()) {
                    (*i).second(iq);
                    return;
                }
            }
        }
        case Iq::RESULT:
        case Iq::ERROR:
            return;
    }
    throw stanza_service_unavailable();
}

Endpoint::~Endpoint() {}

void Endpoint::add_handler(std::string const &xmlns, std::string const &local,
                           const std::function<void(const Iq &)> &fn) {
    m_handlers.emplace(std::make_pair(xmlns, local), fn);
}

void Endpoint::add_capability(std::string const &name) {
    m_capabilities.emplace_back(Capability::create(name, *this));
}

void Endpoint::send(std::unique_ptr<Stanza> &&stanza) {
    RouteTable::routeTable(m_jid.domain()).route(stanza->to())->transmit(std::move(stanza));
}

#include "../src/endpoints/simple.cc"

Endpoint &Endpoint::endpoint(Jid const &jid) {
    static std::map<std::string, std::unique_ptr<Endpoint>> s_endpoints;
    if (Config::config().domain(jid.domain()).transport_type() == INT) {
        auto i = s_endpoints.find(jid.domain());
        if (i == s_endpoints.end()) {
            s_endpoints[jid.domain()].reset(new Simple(jid.domain()));
            return *s_endpoints[jid.domain()];
        }
        return *((*i).second);
    }
    throw std::runtime_error("Endpoint requested for external domain.");
}