//
// Created by dwd on 11/05/17.
//

#include <endpoint.h>

using namespace Metre;

namespace {
    class Simple : public Endpoint {
    public:
        Simple(Jid const &jid) : Endpoint(jid) {
            add_capability("ping");
            add_capability("disco");
            add_capability("pubsub");
            add_capability("version");
        };

        sigslot::tasklet<void> process(Iq & iq) override {
            if (iq.to().full() != m_jid.domain()) {
                throw stanza_service_unavailable();
            }
            return Endpoint::process(iq);
        }
    };
}