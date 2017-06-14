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
        };

        void process(std::unique_ptr<Iq> &&iq) override {
            if (iq->to().full() != m_jid.domain()) {
                throw stanza_service_unavailable();
            }
            Endpoint::process(std::move(iq));
        }
    };
}