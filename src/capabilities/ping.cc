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
            explicit Description(std::string const &name) : Capability::Description<Ping>(name) {
                m_disco.emplace_back("urn:xmpp:ping");
            }
        };

        Ping(BaseDescription const &descr, Endpoint &jid) : Capability(descr, jid) {
            jid.add_handler("urn:xmpp:ping", "ping", [this](Iq const & iq) -> sigslot::tasklet<void> {
                std::unique_ptr<Stanza> pong{new Iq(iq.to(), iq.from(), Iq::RESULT, iq.id())};
                m_endpoint.send(std::move(pong));
                co_return;
            });
        }
    };

    DECLARE_CAPABILITY(Ping, "ping");
}