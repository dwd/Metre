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

#ifndef JID__H
#define JID__H

#include <string>
#include <optional>

#include <spdlog/common.h>

namespace Metre {
    class Jid {
        std::optional<std::string> m_local;
        std::string m_domain;
        std::optional<std::string> m_resource;

        mutable std::optional<std::string> m_full;
        mutable std::optional<std::string> m_bare;
    public:
        explicit Jid(std::string const &jid) {
            parse(jid);
        }

        Jid(std::string const &local, std::string const &domain, nullptr_t=nullptr)
                : m_local(local), m_domain(domain) {
        }

        Jid(std::string const &local, std::string const &domain, std::string const &resource)
                : m_local(local), m_domain(domain), m_resource(resource) {
        }

        Jid(nullptr_t, std::string const &domain, nullptr_t=nullptr)
                : m_domain(domain) {
        }

        Jid(nullptr_t, std::string const &domain, std::string const &resource)
                : m_domain(domain), m_resource(resource) {
        }

        Jid(Jid const &jid)
                : m_local(jid.m_local), m_domain(jid.m_domain), m_resource(jid.m_resource) {
        }

        std::string const &full() const;

        std::string const &bare() const;

        std::string const &domain() const {
            return m_domain;
        }

        Jid full_jid() const;

        Jid bare_jid() const;

        Jid domain_jid() const;

        std::string const &local() const {
            return *m_local;
        }
        std::optional<std::string> const &local_part() const {
            return m_local;
        }
        std::string const &resource() const {
            return *m_resource;
        }
        std::optional<std::string> const &resource_part() const {
            return m_resource;
        }

    protected:
        void parse(std::string const &s);
    };

    inline spdlog::string_view_t to_string_view(const Jid &jid) {
        auto const& full = jid.full();
        return {full.data(), full.length()};
    }

}

#endif
