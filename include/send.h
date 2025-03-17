//
// Created by dave on 05/08/2024.
//

#ifndef METRE_SEND_H
#define METRE_SEND_H

#include "stanza.h"
#include <covent/coroutine.h>


namespace Metre::Send {
    std::string make_id();
    void handle(const Metre::Iq &iq);
    covent::task<const Metre::Iq *> send(std::unique_ptr<Metre::Iq> iq);
    covent::task<const Metre::Iq *> ping(Jid const & from, Jid const & to);
}

#endif //METRE_SEND_H
