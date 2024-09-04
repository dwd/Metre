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

#include <stanza.h>
#include "filter.h"
#include <rapidxml.hpp>
#include <router.h>

using namespace Metre;
using namespace rapidxml;

namespace {
    class Disco : public Filter {
    public:
        class Description : public Filter::Description<Disco> {
        public:
            Description(std::string &&name) : Filter::Description<Disco>(std::move(name)) {};
        };

        Disco(BaseDescription &b, Config::Domain &domain, YAML::Node const & config) : Filter(b) {
        }

        virtual sigslot::tasklet<FILTER_RESULT> apply(std::shared_ptr<sentry::span>, FILTER_DIRECTION dir, Stanza &s) override {
            using enum FILTER_RESULT;
            if (dir == FILTER_DIRECTION::FROM) {
                co_return PASS;
            }
            if (s.name() == Presence::name) {
                auto caps = s.node()->first_node("c", "http://jabber.org/protocol/caps");
                if (!caps) co_return PASS;
                auto hash = caps->first_attribute("hash");
                if (hash) {
                    // Translate to the new caps, if available.
                    auto ver = caps->first_attribute("ver");
                    if (!ver) {
                        // s.node()->remove_node(caps); // Maybe??
                        co_return PASS;
                    }
                    auto it = m_caps_translation.find(std::string{ver->value()});
                    if (it == m_caps_translation.end()) {
                        // Freeze the stream (?) and do a disco query.
                        // Probably need to return false here?
                        co_return PASS; // Pass it for now.
                    }
                    // We cool. Replace the old caps with the new one.
                    caps->remove_attribute(ver.get());
                    caps->append_attribute(caps->document()->allocate_attribute("ver", (*it).second.c_str()));
                } else {
                    // For security, we'll need to back-calculate the hash.
                }
            }
            co_return PASS;
        }

    private:
        std::set<std::string> m_allowed;
        std::set<std::string> m_prohibited;
        std::map<std::string, std::string> m_caps_translation;  // For boundary filtering.
    };

    // bool something = Filter::declare<Disco>("disco-filter");
}