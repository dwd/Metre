//
// Created by dwd on 11/05/17.
//

#ifndef METRE_ENDPOINT_H
#define METRE_ENDPOINT_H

#include "jid.h"
#include "stanza.h"
#include "capability.h"

namespace Metre {
    class Capability;

    class Endpoint {
    protected:
        Jid m_jid;
        std::optional<std::string> m_node;

    public:
        static Endpoint &endpoint(Jid const &);

        Endpoint(Jid const &);

        Endpoint(Jid const &, std::string const &node);

        virtual void process(Presence const &presence);

        virtual void process(Message const &message);

        virtual void process(Iq const &iq);

        void process(Stanza const &stanza);

        void send(std::unique_ptr<Stanza> &&stanza);

        void send(std::unique_ptr<Stanza> &&stanza, std::function<void(Stanza const &)> const &);

        // Config API:
        void add_capability(std::string const &name);

        std::list<std::unique_ptr<Capability>> const &capabilities() const {
            return m_capabilities;
        }

        void add_handler(std::string const &xmlns, std::string const &local, std::function<void(Iq const &)> const &fn);

        virtual ~Endpoint();

    private:
        std::list<std::unique_ptr<Capability>> m_capabilities;
        std::map<std::pair<std::string, std::string>, std::function<void(Iq const &)>> m_handlers;
        std::map<std::string, std::function<void(Stanza const &)>> m_stanza_callbacks;
    };
}

#endif //METRE_ENDPOINT_H
