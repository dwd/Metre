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

#ifndef JID_H
#define JID_H

#include <string>
#include <optional>
#include <utility>

#include <spdlog/common.h>

namespace Metre {
    class Jid {
        std::optional<std::string> m_local;
        std::string m_domain;
        std::optional<std::string> m_resource;

        mutable std::optional<std::string> m_full;
        mutable std::optional<std::string> m_bare;
    public:
        explicit Jid(std::string_view const &jid) {
            parse(jid);
        }

        Jid(std::string const &local, std::string domain, nullptr_t=nullptr)
                : m_local(local), m_domain(std::move(domain)) {
        }

        Jid(std::string const &local, std::string domain, std::string const &resource)
                : m_local(local), m_domain(std::move(domain)), m_resource(resource) {
        }

        Jid(nullptr_t, std::string domain, nullptr_t=nullptr)
                : m_domain(std::move(domain)) {
        }

        Jid(nullptr_t, std::string domain, std::string const &resource)
                : m_domain(std::move(domain)), m_resource(resource) {
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
        void parse(std::string_view const &s);
    };

}

template <>
struct fmt::formatter<Metre::Jid> : fmt::formatter<std::string> {
    auto format(const Metre::Jid& c, fmt::format_context& ctx) const {
        return fmt::formatter<std::string>::format(c.full(), ctx);
    }
};


#endif
