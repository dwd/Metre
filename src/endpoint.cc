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
    return id;
}

void Endpoint::process(std::unique_ptr<Stanza> &&stanza) {
    if (stanza->id()) {
        auto it = m_stanza_callbacks.find(*stanza->id());
        if (it != m_stanza_callbacks.end()) {
            (*it).second(std::move(stanza));
            return;
        }
    }
    if (stanza->name() == Message::name) {
        std::unique_ptr<Message> msg(dynamic_cast<Message *>(stanza.release()));
        process(std::move(msg));
    } else if (stanza->name() == Presence::name) {
        std::unique_ptr<Presence> pres(dynamic_cast<Presence *>(stanza.release()));
        process(std::move(pres));
    } else if (stanza->name() == Iq::name) {
        std::unique_ptr<Iq> iq(dynamic_cast<Iq *>(stanza.release()));
        process(std::move(iq));
    } else {
        throw stanza_service_unavailable();
    }
}

void Endpoint::process(std::unique_ptr<Presence> &&presence) {
    throw stanza_service_unavailable();
}

void Endpoint::process(std::unique_ptr<Message> &&message) {
    throw stanza_service_unavailable();
}

void Endpoint::process(std::unique_ptr<Iq> &&iq) {
    switch (iq->type()) {
        case Iq::GET:
        case Iq::SET: {
            auto payload = iq->node()->first_node();
            if (payload != nullptr) {
                std::string xmlns{payload->xmlns(), payload->xmlns_size()};
                std::string local{payload->name(), payload->name_size()};
                auto i = m_handlers.find(std::make_pair(xmlns, local));
                if (i != m_handlers.end()) {
                    (*i).second(std::move(iq));
                    return;
                }
            }
        }
        case Iq::RESULT:
        case Iq::STANZA_ERROR:
            return;
    }
    throw stanza_service_unavailable();
}

Endpoint::~Endpoint() = default;

void Endpoint::add_handler(std::string const &xmlns, std::string const &local,
                           std::function<void(std::unique_ptr<Iq> &&)> &&fn) {
    m_handlers.emplace(std::make_pair(xmlns, local), std::move(fn));
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

void Endpoint::send(std::unique_ptr<Stanza> &&stanza, std::function<void(std::unique_ptr<Stanza> &&)> const &fn) {
    if (!stanza->id()) {
        stanza->id(random_identifier());
    }
    m_stanza_callbacks[*(stanza->id())] = fn;
    send(std::move(stanza));
}

void Endpoint::node(std::string const &aname, std::function<void(Node &)> &&fn, bool create) {
    Router::defer([this, fn = std::move(fn), name = aname, create]() {
        auto it = m_nodes.find(name);
        if (it == m_nodes.end()) {
            if (create) {
                m_nodes.emplace(std::make_pair(name, std::make_unique<Node>(*this, name)));
                it = m_nodes.find(name);
            } else {
                throw std::runtime_error("Node not found");
            }
        }
        fn(*(it->second.get()));
    });
}

#include "../src/endpoints/simple.cc"

Endpoint &Endpoint::endpoint(Jid const &jid) {
    static std::map<std::string, std::unique_ptr<Endpoint>> s_endpoints;
    auto i = s_endpoints.find(jid.domain());
    if (i == s_endpoints.end()) {
        s_endpoints[jid.domain()] = std::make_unique<Simple>(jid.domain());
        return *s_endpoints[jid.domain()];
    }
    return *((*i).second);
}