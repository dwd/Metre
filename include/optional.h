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

#ifndef OPTIONAL__H
#define OPTIONAL__H

#include <stdexcept>
#include <optional>

namespace std {
    template<typename T>
    class optional {
        char m_void_spc[sizeof(T)];
        char * m_void;
        bool m_engaged = false;
    private:
        void doset(T const &t) {
            new(reinterpret_cast<T *>(m_void)) T(t);
            m_engaged = true;
        }

        void dounset() {
            reinterpret_cast<T *>(m_void)->~T();
            m_engaged = false;
        }

        T *real() {
            if (!m_engaged) throw std::runtime_error("Deref when unengaged");
            return reinterpret_cast<T *>(m_void);
        }

        T const *real() const {
            if (!m_engaged) throw std::runtime_error("Deref when unengaged");
            return reinterpret_cast<T const *>(m_void);
        }

    public:
        optional(T const &t) : m_void(m_void_spc) {
            doset(t);
        }

        optional() : m_void(m_void_spc) {
        }

        optional(optional<T> const &t) : m_void(m_void_spc) {
            if (t.m_engaged) doset(t.value());
        }

        template<class... Args>
        void emplace(Args &&... args) {
            if (m_engaged) {
                dounset();
            }
            new(m_void) T(args...);
            m_engaged = true;
        }

        T &operator*() {
            return *real();
        }

        T *operator->() {
            return real();
        }

        T &value() {
            return *real();
        }

        T const &operator*() const {
            return *real();
        }

        T const *operator->() const {
            return real();
        }

        T const &value() const {
            return *real();
        }

        explicit operator bool() const {
            return m_engaged;
        }

        optional<T> &operator=(T const &t) {
            if (m_engaged) dounset();
            doset(t);
            return *this;
        }

        optional<T> &operator=(optional<T> const &t) {
            if (m_engaged) dounset();
            doset(t.value());
            return *this;
        }

        bool operator==(optional<T> const &t) const {
            if (t.m_engaged) {
                if (m_engaged) return true;
                return (t.value() == value());
            }
            return !m_engaged;
        }

        bool operator!=(optional<T> const &t) const {
            if (t.m_engaged) {
                if (m_engaged) return false;
                return (t.value() != value());
            }
            return m_engaged;
        }

        bool operator==(T const &t) const {
            if (!m_engaged) return false;
            return value() == t;
        }

        bool operator!=(T const &t) const {
            if (!m_engaged) return true;
            return value() != t;
        }
    };
}

#endif
