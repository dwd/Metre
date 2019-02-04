//
// Created by Dave Cridland on 2019-01-23.
//

#ifndef METRE_TASKLET_H
#define METRE_TASKLET_H

#include <sigslot/sigslot.h>
#include <experimental/coroutine>

namespace Metre {

    template<typename T>
    struct tasklet {
        struct promise_type;
        using handle_type = std::experimental::coroutine_handle<promise_type>;
        handle_type coro;

        explicit tasklet() : coro(nullptr) {
        }

        tasklet(handle_type h) : coro(h) {
        }
        tasklet(tasklet && other) : coro(other.coro) {
            other.coro = nullptr;
        }
        tasklet &operator = (tasklet && other) {
            coro = other.coro;
            other.coro = nullptr;
            return *this;
        }
        tasklet(tasklet const &) = delete;
        tasklet & operator = (tasklet const &) = delete;

        ~tasklet() {
            if (coro) coro.destroy();
        }

        T get() {
            return coro.promise().value;
        }

        void start() {
            if (!coro) throw std::logic_error("No coroutine to start");
            if (coro.done()) throw std::logic_error("Already run");
            coro.resume();
        }

        bool running() {
            if (!coro) return false;
            return !coro.done();
        }

        sigslot::signal<T> & complete() {
            return coro.promise().complete;
        }

        sigslot::signal<std::exception_ptr const &> & exception() {
            return coro.promise().exception;
        }

        struct promise_type {
            T value;
            sigslot::signal<T> complete;
            sigslot::signal<std::exception_ptr const &> exception;
            promise_type() : value() {
            }
            auto get_return_object() {
                return tasklet<T>{handle_type::from_promise(*this)};
            }
            auto return_value(T v) {
                value = v;
                complete(value);
                return std::experimental::suspend_never{};
            }
            auto final_suspend() {
                return std::experimental::suspend_always{};
            }
            auto initial_suspend() {
                return std::experimental::suspend_always{};
            }
            void unhandled_exception() {
                exception(std::current_exception());
            }
        };
    };
}

#endif //METRE_TASKLET_H
