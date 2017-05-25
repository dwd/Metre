//
// Created by dwd on 23/05/17.
//

#include <capability.h>

using namespace Metre;

namespace {
    class Pubsub : public Capability {
    public:
        class Description : public Capability::Description<Pubsub> {
        public:
            Description(std::string const &name) : Capability::Description<Pubsub>(name) {
                m_disco.emplace_back("http://jabber.org/protocol/pubsub");
            }
        };

        Pubsub(BaseDescription const &descr, Endpoint &endpoint) : Capability(descr, endpoint) {
            endpoint.add_handler("http://jabber.org/protocol/pubsub", "pubsub", [this](Iq const &iq) {
                // Check second-level element and dispatch.
                return true;
            });
        }
    };
}