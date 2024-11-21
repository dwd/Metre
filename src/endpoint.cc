//
// Created by dwd on 11/05/17.
//

#include <endpoint.h>
#include <router.h>
#include <config.h>
#include <algorithm>
#include <utility>

using namespace Metre;

const std::string Endpoint::characters = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ@";

Endpoint::Endpoint(Jid jid) : m_jid(std::move(jid)), m_random(std::random_device{}()), m_dist(0, sizeof(characters) - 2) {}

std::string Endpoint::random_identifier() {
    std::string id;
    id.resize(id_len);
    std::generate_n(id.begin(), id_len, [this]() { return characters[m_dist(m_random)]; });
    return id;
}

void Endpoint::process(std::unique_ptr<Stanza> && stanza_ptr) {
    if (stanza_ptr->id()) {
        auto it = m_stanza_callbacks.find(*stanza_ptr->id());
        if (it != m_stanza_callbacks.end()) {
            (*it).second(*stanza_ptr);
            return;
        }
    }
    auto task = std::make_unique<process_task>();
    try {
        task->stanza = std::move(stanza_ptr);
        if (task->stanza->name() == Message::name) {
            task->task = process(dynamic_cast<Message &>(*(task->stanza)));
        } else if (task->stanza->name() == Presence::name) {
            task->task = process(dynamic_cast<Presence &>(*(task->stanza)));
        } else if (task->stanza->name() == Iq::name) {
            task->task = process(dynamic_cast<Iq &>(*(task->stanza)));
        } else {
            throw unsupported_stanza_type();
        }
        task->task.start();
        if (task->task.running()) {
            task->task.complete().connect(this, [this, t = task.get()]() {
                task_complete(t);
            });
            m_tasks.emplace_back(std::move(task));
        } else {
            task_complete(task.get());
        }
    } catch (Metre::base::stanza_exception const &stanza_error) {
        send(task->stanza->create_bounce(stanza_error));
    }
}

sigslot::tasklet<void> Endpoint::process(Presence & presence) {
    throw stanza_service_unavailable();
    co_return;
}

sigslot::tasklet<void> Endpoint::process(Message & message) {
    throw stanza_service_unavailable();
    co_return;
}

sigslot::tasklet<void> Endpoint::process(Iq & iq) {
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
                           std::function<sigslot::tasklet<void>(Iq const &)> &&fn) {
    m_handlers.try_emplace(std::make_pair(xmlns, local), std::move(fn));
}

void Endpoint::add_capability(std::string const &name) {
    m_capabilities.emplace(Capability::create(name, *this));
}

void Endpoint::send(std::unique_ptr<Stanza> &&stanza) const {
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

sigslot::tasklet<Node *> Endpoint::node(std::string name, bool create) {
    auto it = m_nodes.find(name);
    if (it == m_nodes.end()) {
        if (create) {
            auto const & [nit, ok] = m_nodes.try_emplace(name, std::make_unique<Node>(*this, name));
            if (ok) {
                it = nit;
            } else {
                throw stanza_service_unavailable("Node creation failed");
            }
        } else {
            throw stanza_service_unavailable("Node not found");
        }
    }
    co_return (*it).second.get();
}

#include "../src/endpoints/simple.cc"

Endpoint &Endpoint::endpoint(Jid const &jid) {
    static std::map<std::string, std::unique_ptr<Endpoint>, std::less<>> s_endpoints;
    auto i = s_endpoints.find(jid.domain());
    if (i == s_endpoints.end()) {
        s_endpoints[jid.domain()] = std::make_unique<Simple>(jid.domain_jid());
        return *s_endpoints[jid.domain()];
    }
    return *((*i).second);
}

void Endpoint::task_complete(Endpoint::process_task const * task) {
    try {
        task->task.get();
    } catch (Metre::base::stanza_exception & stanza_error) {
        std::unique_ptr<Stanza> st = task->stanza->create_bounce(stanza_error);
        send(std::move(st));
    } catch (std::runtime_error &e) {
        auto stanza_error = Metre::stanza_undefined_condition(e.what());
        std::unique_ptr<Stanza> st = task->stanza->create_bounce(stanza_error);
        send(std::move(st));
    }
    m_tasks.remove_if([task](auto & t) { return task == t.get(); });
}
