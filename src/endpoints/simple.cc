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
        };
    };
}