//
// Created by dave on 05/08/2024.
//
#include "send.h"
#include "router.h"
#include <random>
#include <map>

using namespace Metre;

namespace {
    std::map<std::string,sigslot::signal<Iq const &>> s_iq_waiting;
    const std::string s_id_prefix = "::metre::handle::";

    sigslot::signal<Iq const &> & send_low(std::unique_ptr<Iq> && iq) {
        auto handler_id = iq->id();
        if (!handler_id.has_value()) {
            throw std::logic_error("Must have id to send an IQ from Metre");
        }
        auto & ret = s_iq_waiting[handler_id.value()];
        auto route = RouteTable::routeTable(iq->from().domain()).route(iq->to().domain());
        route->transmit(std::move(iq));
        return ret;
    }
}

std::string Metre::Send::make_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist('A', 'Z');
    std::string new_id = s_id_prefix;
    for (int i = 0; i != 30; ++i) {
        new_id += static_cast<char>(dist(gen));
    }
    return new_id;
}

void Metre::Send::handle(Iq const & iq) {
    auto it = s_iq_waiting.find(iq.id().value());
    if (it != s_iq_waiting.end()) {
        (*it).second(iq);
        s_iq_waiting.erase(it);
    }
}

sigslot::tasklet<Iq const *> Metre::Send::send(std::shared_ptr<sentry::span> span, std::unique_ptr<Iq> iq) {
    auto const & ret = co_await send_low(std::move(iq));
    co_return &ret;
}

sigslot::tasklet<Iq const *> Metre::Send::ping(std::shared_ptr<sentry::span> span, Jid const & from, Jid const & to) {
    auto iq = std::make_unique<Iq>(from, to, Iq::Type::GET, make_id());
    iq->node()->append_element({"urn:xmpp:ping", "ping"});
    return send(std::move(span), std::move(iq));
}