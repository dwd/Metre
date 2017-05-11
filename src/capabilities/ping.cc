//
// Created by dwd on 11/05/17.
//

#include <capability.h>
#include <router.h>

using namespace Metre;

namespace {
    class Ping : public Capability {
    public:
        class Description : public Capability::Description<Ping> {
        public:
            Description(std::string const &name) : Capability::Description<Ping>(name) {
                m_disco.emplace_back("urn:xmpp:ping");
            }
        };

        Ping(BaseDescription const &descr, Jid const &jid) : Capability(descr, jid) {}

        bool handle(Iq const &iq) override {
            std::unique_ptr<Stanza> pong{new Iq(iq.to(), iq.from(), Iq::RESULT, iq.id())};
            std::shared_ptr<Route> route = RouteTable::routeTable(iq.to()).route(iq.from());
            route->transmit(std::move(pong));
            return true;
        }
    };

    DECLARE_CAPABILITY(Ping, "ping");
}