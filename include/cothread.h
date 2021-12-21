//
// Created by dwd on 21/12/2021.
//

#ifndef METRE_COTHREAD_H
#define METRE_COTHREAD_H

#include <thread>
#include "sigslot.h"
#include "sigslot/tasklet.h"

namespace Metre {
    template<typename Result, class... Args>
    class CoThread {
        sigslot::signal<Result> m_completed;
        std::function<Result()> m_fn;

    public:
        CoThread(std::function<Result()> && fn) : m_fn(fn) {}

        sigslot::tasklet<Result> run(Args&&... args) {
            auto wrapped_fn = [cothread=this](Args... a) {
                auto result = cothread->m_fn(a...);
                cothread->m_completed(result);
            };
            std::jthread thread(wrapped_fn, args...);
            auto result = co_await m_completed;
            co_return result;
        }
    };
}

#endif //METRE_COTHREAD_H
