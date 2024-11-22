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

covent::task<void> Endpoint::process(std::unique_ptr<Stanza> stanza_ptr) {
    if (stanza_ptr->id()) {
        auto it = m_stanza_callbacks.find(*stanza_ptr->id());
        if (it != m_stanza_callbacks.end()) {
            (*it).second(*stanza_ptr);
            co_return;
        }
    }
    try {
        if (stanza_ptr->name() == Message::name) {
            co_await process(dynamic_cast<Message &>(*stanza_ptr));
        } else if (stanza_ptr->name() == Presence::name) {
            co_await process(dynamic_cast<Presence &>(*stanza_ptr));
        } else if (stanza_ptr->name() == Iq::name) {
            co_await process(dynamic_cast<Iq &>(*stanza_ptr));
        } else {
            throw unsupported_stanza_type();
        }
    } catch (Metre::base::stanza_exception const &stanza_error) {
        send(stanza_ptr->create_bounce(stanza_error));
    }
}

covent::task<void> Endpoint::process(Presence & presence) {
    throw stanza_service_unavailable();
    co_return;
}

covent::task<void> Endpoint::process(Message & message) {
    co_await covent::own_promise<covent::task<void>::promise_type>();
    throw stanza_service_unavailable();
    co_return;
}

covent::task<void> Endpoint::process(Iq & iq) {
    switch (iq.type()) {
        using enum Iq::Type;
        case GET:
        case SET: {
            auto payload = iq.node()->first_node();
            if (payload != nullptr) {
                std::string xmlns{payload->xmlns()};
                std::string local{payload->name()};
                auto i = m_handlers.find(std::make_pair(xmlns, local));
                if (i != m_handlers.end()) {
                    co_await (*i).second(iq);
                    co_return;
                }
            }
        }
        case RESULT:
        case STANZA_ERROR:
            co_return;
    }
    throw stanza_service_unavailable();
}

Endpoint::~Endpoint() = default;

void Endpoint::add_handler(std::string const &xmlns, std::string const &local,
                           std::function<covent::task<void>(Iq const &)> &&fn) {
    m_handlers.emplace(std::make_pair(xmlns, local), std::move(fn));
}

void Endpoint::add_capability(std::string const &name) {
    m_capabilities.emplace(Capability::create(name, *this));
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
    m_stanza_callbacks[*(stanza->id())] = fn;
    send(std::move(stanza));
}

covent::task<Node *> Endpoint::node(std::string const &name, bool create) {
    auto it = m_nodes.find(name);
    if (it == m_nodes.end()) {
        if (create) {
            m_nodes.emplace(std::make_pair(name, std::make_unique<Node>(*this, name)));
            it = m_nodes.find(name);
        } else {
            throw stanza_service_unavailable("Node not found");
        }
    }
    co_return (*it).second.get();
}

#include "../src/endpoints/simple.cc"

Endpoint &Endpoint::endpoint(Jid const &jid) {
    static std::map<std::string, std::unique_ptr<Endpoint>> s_endpoints;
    auto i = s_endpoints.find(jid.domain());
    if (i == s_endpoints.end()) {
        s_endpoints[jid.domain()] = std::make_unique<Simple>(jid.domain_jid());
        return *s_endpoints[jid.domain()];
    }
    return *((*i).second);
}
