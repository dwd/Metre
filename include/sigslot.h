//
// Created by dwd on 13/04/19.
//

#ifndef METRE_SIGSLOT_H
#define METRE_SIGSLOT_H

#include <coroutine>
#include "core.h"

namespace sigslot {
    void resume(std::coroutine_handle<> coro);
    void register_coro(std::coroutine_handle<> coro);
    void deregister_coro(std::coroutine_handle<> coro);
}

#include <sigslot/sigslot.h>

#endif //METRE_SIGSLOT_H
