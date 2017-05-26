//
// Created by dwd on 11/05/17.
//

#include <endpoint.h>
#include <router.h>
#include <config.h>
#include <algorithm>

using namespace Metre;

const char Endpoint::characters[] = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ@";

Endpoint::Endpoint(Jid const &jid) : m_jid(jid), m_random(std::random_device{}()), m_dist(0, sizeof(characters) - 2) {}

std::string Endpoint::random_identifier() {
    std::string id(id_len, char{});
    std::generate_n(id.begin(), id_len, [this]() { return characters[m_dist(m_random)]; });
    return std::move(id);
}

void Endpoint::process(Stanza const &stanza) {
    if (stanza.id()) {
        auto it = m_stanza_callbacks.find(*stanza.id());
        if (it != m_stanza_callbacks.end()) {
            (*it).second(stanza);
            return;
        }
    }
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
#ifdef METRE_TESTING
    sent_stanza(*stanza, m_jid, stanza->to());
#else
    RouteTable::routeTable(m_jid.domain()).route(stanza->to())->transmit(std::move(stanza));
#endif
}

void Endpoint::send(std::unique_ptr<Stanza> &&stanza, std::function<void(Stanza const &)> const &fn) {
    if (!stanza->id()) {
        stanza->id(random_identifier());
    }
    m_stanza_callbacks[stanza->id().value()] = fn;
    send(std::move(stanza));
}

#include "../src/endpoints/simple.cc"

Endpoint &Endpoint::endpoint(Jid const &jid) {
    static std::map<std::string, std::unique_ptr<Endpoint>> s_endpoints;
    auto i = s_endpoints.find(jid.domain());
    if (i == s_endpoints.end()) {
        s_endpoints[jid.domain()].reset(new Simple(jid.domain()));
        return *s_endpoints[jid.domain()];
    }
    return *((*i).second);
}