//
// Created by dave on 05/08/2024.
//

#ifndef METRE_SEND_H
#define METRE_SEND_H

#include "stanza.h"
#include "sentry-wrap.h"
#include <covent/coroutine.h>


namespace Metre::Send {
    std::string make_id();
    void handle(const Metre::Iq &iq);
    covent::task<const Metre::Iq *> send(std::shared_ptr<sentry::span> span, std::unique_ptr<Metre::Iq> iq);
    covent::task<const Metre::Iq *> ping(std::shared_ptr<sentry::span> span, Jid const & from, Jid const & to);
}

#endif //METRE_SEND_H
