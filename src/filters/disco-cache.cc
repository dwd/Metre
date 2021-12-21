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
#include <log.h>
#include "cothread.h"

using namespace Metre;
using namespace rapidxml;

namespace {
    class DiscoCache : public Filter {
    public:
        class Description : public Filter::Description<DiscoCache> {
        public:
            Description(std::string &&name) : Filter::Description<DiscoCache>(std::move(name)) {};
        };

        DiscoCache(BaseDescription &b, Config::Domain &, rapidxml::xml_node<> *) : Filter(b) {
        }

        virtual sigslot::tasklet<FILTER_RESULT> apply(SESSION_DIRECTION dir, Stanza &s) override {
            auto fn = []() -> bool {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                return true;
            };
            CoThread<bool> cothread(fn);
            co_await cothread.run();
            if (dir == OUTBOUND) {
                co_return PASS;
            }
            if (s.name() == Iq::name) {
                Iq &iq = dynamic_cast<Iq &>(s);
                if (iq.type() == Iq::GET) {
                    auto disco = iq.node()->first_node("query", "http://jabber.org/protocol/disco#info");
                    if (disco) { // It's a disco#info request.
                        auto node = disco->first_attribute("node");
                        if (!node) co_return PASS;
                        auto it = caps_cache().find(std::string{node->value(), node->value_size()});
                        if (it != caps_cache().end()) {
                            std::unique_ptr<Stanza> response(new Iq(iq.to(), iq.from(), Iq::RESULT, iq.id()));
                            response->payload((*it).second);
                            auto route = RouteTable::routeTable(iq.from()).route(iq.to());
                            route->transmit(std::move(response));
                            co_return DROP;
                        }
                    }
                } else if (iq.type() == Iq::RESULT) {
                    auto disco = iq.node()->first_node("query", "http://jabber.org/protocol/disco#info");
                    if (disco) { // It's a disco#info request.
                        auto node = disco->first_attribute("node");
                        if (!node) co_return PASS;
                        bool client = false;
                        for (auto identity = disco->first_node("identity"); identity; identity = identity->next_sibling(
                                "identity")) {
                            auto category = identity->first_attribute("category");
                            if (category && category->value() &&
                                std::string{category->value(), category->value_size()} == "client") {
                                client = true;
                                break;
                            }
                        }
                        if (client) {
                            std::string nodestr{node->value(), node->value_size()};
                            caps_cache()[nodestr] = std::string{disco->contents(), disco->contents_size()};
                            METRE_LOG(Log::INFO, "Cached disco#info for " << nodestr);
                        }
                    }
                }
            }
            co_return PASS;
        }

    private:
        static std::map<std::string /*node*/, std::string /*disco#info xml*/> &caps_cache() {
            static std::map<std::string, std::string> s_caps;
            return s_caps;
        }  // For responding to disco requests.
    };

    bool something = Filter::declare<DiscoCache>("disco-cache");
}