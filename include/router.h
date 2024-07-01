/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/

#ifndef ROUTER__H
#define ROUTER__H

#include "defs.h"
#include "jid.h"
#include "stanza.h"
#include "core.h"
#include "sigslot.h"
#include "sigslot/tasklet.h"

#include <string>
#include <memory>
#include <queue>
#include <map>
#include <spdlog/logger.h>

namespace Metre {
    class NetSession;

    class Route : public sigslot::has_slots {
    private:
        std::weak_ptr<NetSession> m_to;
        sigslot::tasklet<bool> m_to_task;
        std::weak_ptr<NetSession> m_vrfy;
        sigslot::tasklet<bool> m_verify_task;
        std::list<std::unique_ptr<Stanza>> m_stanzas;
        std::list<std::unique_ptr<DB::Verify>> m_dialback;
        Jid const m_local;
        Jid const m_domain;
        std::shared_ptr<spdlog::logger> m_logger;
    public:
        Route(Jid const &from, Jid const &to);

        std::string const &domain() const {
            return m_domain.domain();
        }

        Jid const & domain_jid() const {
            return m_domain;
        }

        std::string const &local() const {
            return m_local.domain();
        }

        Jid const & local_jid() const {
            return m_local;
        }

        sigslot::tasklet<bool> init_session_vrfy();

        sigslot::tasklet<bool> init_session_to();

        void outbound(NetSession *ns);

        void transmit(std::unique_ptr<Stanza> &&);

        void transmit(std::unique_ptr<DB::Verify> &&);

        // Slots
        void SessionClosed(NetSession &);

        // Risky : Only used internally and by components.
        void set_to(std::shared_ptr<NetSession> & to);

    protected:
        void bounce_stanzas(Stanza::Error);

        void bounce_dialback(bool timeout);

        void queue(std::unique_ptr<Stanza> &&);

        void queue(std::unique_ptr<DB::Verify> &&);

        void set_vrfy(std::shared_ptr<NetSession> & vrfy);
    };

    class RouteTable {
    private:
        std::map<std::string, std::shared_ptr<Route>, std::less<>> m_routes;
        std::string m_local_domain;

    public:
        explicit RouteTable(std::string const &);

        std::shared_ptr<Route> &route(Jid const &to);
        std::shared_ptr<Route> &route(std::string const &to);

        static RouteTable &routeTable(std::string const &);

        static RouteTable &routeTable(Jid const &);
    };

}

#endif
