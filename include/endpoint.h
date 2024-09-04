//
// Created by dwd on 11/05/17.
//

#ifndef METRE_ENDPOINT_H
#define METRE_ENDPOINT_H

#include <random>
#include "sigslot.h"
#include <sigslot/tasklet.h>
#include "jid.h"
#include "stanza.h"
#include "capability.h"
#include "node.h"

namespace Metre {
    class Capability;

    class Endpoint: public sigslot::has_slots {
    public:
        static Endpoint &endpoint(Jid const &);

        explicit Endpoint(Jid const &);

        Jid const &jid() const {
            return m_jid;
        }

        virtual sigslot::tasklet<void> process(Presence & presence);

        virtual sigslot::tasklet<void> process(Message & message);

        virtual sigslot::tasklet<void> process(Iq & iq);

        void process(std::unique_ptr<Stanza> && stanza);

        std::string random_identifier();

        void send(std::unique_ptr<Stanza> &&stanza);

        void send(std::unique_ptr<Stanza> &&stanza, std::function<void(Stanza const &)> const &);

        // Config API:
        void add_capability(std::string const &name);

        std::set<std::unique_ptr<Capability>> const &capabilities() const {
            return m_capabilities;
        }

        void add_handler(std::string const &xmlns, std::string const &local,
                         std::function<sigslot::tasklet<void>(Iq const &)> &&fn);

        ~Endpoint() override;

        sigslot::tasklet<Node *> node(std::string const &name, bool create = false);

        std::map<std::string, std::unique_ptr<Node>, std::less<>> const &nodes() const {
            return m_nodes;
        };

        void nodes(std::function<void(std::map<std::string, std::unique_ptr<Node>, std::less<>> const &)> &&fn) const;

#ifdef METRE_TESTING
        sigslot::signal<Stanza &, Jid const &, Jid const &> sent_stanza;
#endif
    protected:
        struct process_task {
            std::unique_ptr<Stanza> stanza;
            sigslot::tasklet<void> task;
        };
        void task_complete(process_task *);

        Jid m_jid;
        static const size_t id_len = 16;
        static const char characters[];
        std::default_random_engine m_random;
        std::uniform_int_distribution<> m_dist;
        std::map<std::string, std::unique_ptr<Node>, std::less<>> m_nodes;


    private:
        std::list<std::unique_ptr<process_task>> m_tasks;
        std::set<std::unique_ptr<Capability>> m_capabilities;
        std::map<std::pair<std::string, std::string>, std::function<sigslot::tasklet<void>(Iq const &)>> m_handlers;
        std::map<std::string, std::function<void(Stanza const &)>, std::less<>> m_stanza_callbacks;
    };
}

#endif //METRE_ENDPOINT_H
