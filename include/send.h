//
// Created by dave on 05/08/2024.
//

#ifndef METRE_SEND_H
#define METRE_SEND_H

#include "stanza.h"
#include "sigslot.h"
#include "sigslot/tasklet.h"
#include "sentry-wrap.h"


namespace Metre::Send {
    std::string make_id();
    void handle(const Metre::Iq &iq);
    sigslot::tasklet<const Metre::Iq *> send(std::shared_ptr<sentry::span> span, std::unique_ptr<Metre::Iq> iq);
    sigslot::tasklet<const Metre::Iq *> ping(std::shared_ptr<sentry::span> span, Jid const & from, Jid const & to);
}

#endif //METRE_SEND_H
