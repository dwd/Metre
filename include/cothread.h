//
// Created by dwd on 21/12/2021.
//

#ifndef METRE_COTHREAD_H
#define METRE_COTHREAD_H

#include <thread>
#include "sigslot.h"
#include "sigslot/tasklet.h"
#include "log.h"

namespace Metre {
    template<typename Result, class... Args>
    class CoThread {
    public:
        // Single argument version uses a bare T
        struct awaitable {
            std::coroutine_handle<> awaiting = nullptr;
            CoThread & wait_for;

            explicit awaitable(CoThread & t) : wait_for(t) {}

            bool await_ready() {
                return wait_for.has_payload();
            }

            void await_suspend(std::coroutine_handle<> h) {
                // The awaiting coroutine is already suspended.
                awaiting = h;
                wait_for.await(this);
            }

            auto await_resume() {
                return wait_for.payload();
            }

            void resolve() {
                std::coroutine_handle<> a = nullptr;
                std::swap(a, awaiting);
                METRE_LOG(Metre::Log::DEBUG, "Awaitable resolved, posting resumption.");
                if (a) sigslot::resume(a);
            }
        };
    private:
        std::function<Result(Args...)> m_fn;
        std::optional<std::jthread> m_thread;
        std::optional<Result> m_payload;
        std::recursive_mutex m_mutex;
        awaitable * m_awaitable = nullptr;

    public:

        explicit CoThread(std::function<Result(Args...)> && fn) : m_fn(std::move(fn)) {}

        CoThread & run(Args&&... args) {
            auto wrapped_fn = [this](Args... a) {
                auto result = m_fn(a...);
                {
                    std::lock_guard l_(m_mutex);
                    m_payload.emplace(result);
                    METRE_LOG(Metre::Log::DEBUG, "CoThread run complete, emplaced result.");
                    if (m_awaitable) {
                        METRE_LOG(Metre::Log::DEBUG, "CoThread run complete, resolving awaitable.");
                        m_awaitable->resolve();
                    }
                }
            };
            m_thread.emplace(wrapped_fn, args...);
            return *this;
        }

        awaitable operator co_await() {
            if (!m_thread.has_value()) throw std::logic_error("No thread started");
            return awaitable(*this);
        }

        bool has_payload() {
            if (!m_thread.has_value()) throw std::logic_error("No thread started");
            std::lock_guard l_(m_mutex);
            return m_payload.has_value();
        }

        auto payload() {
            if (!m_thread.has_value()) throw std::logic_error("No thread started");
            m_thread->join();
            m_thread.reset();
            return *m_payload;
        }

        void await(awaitable * a) {
            if (!m_thread.has_value()) throw std::logic_error("No thread started");
            std::lock_guard l_(m_mutex);
            m_awaitable = a;
            if (m_payload.has_value()) {
                a->resolve();
            }
        }
    };
}

#endif //METRE_COTHREAD_H
