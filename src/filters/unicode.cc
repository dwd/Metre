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
#include <unicode/usprep.h>
#include <unicode/ucnv.h>
#include <unicode/unorm2.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace Metre;
using namespace rapidxml;


namespace {
    UConverter *utf8() {
        static UConverter *c = 0;
        UErrorCode error = U_ZERO_ERROR;
        if (!c) c = ucnv_open("utf-8", &error);
        return c;
    }

    UNormalizer2 const *normalizer() {
        static const UNormalizer2 *c = 0;
        UErrorCode error = U_ZERO_ERROR;
        if (!c) c = unorm2_getNFKDInstance(&error);
        return c;
    }

    UChar parse_uchar(rapidxml::xml_attribute<> *attr) {
        std::string val(attr->value());
        if (val.find("U+") == 0) {
            val = val.substr(2);
        }
        std::istringstream ss(val);
        unsigned long charcode = 0;
        ss >> std::hex >> charcode;
        if (ss.bad()) throw std::runtime_error("Bad unicode codepoint (U+ABCD)");
        return static_cast<UChar>(charcode);
    }
}

namespace {
    class Unicode : public Filter {
    public:
        class Description : public Filter::Description<Unicode> {
        public:
            Description(std::string &&name) : Filter::Description<Unicode>(std::move(name)) {};
        };

        Unicode(BaseDescription &b, Config::Domain &, rapidxml::xml_node<> *config) : Filter(b) {
            for (auto block = config->first_node("banned-block"); block; block = block->next_sibling("banned-block")) {
                auto start = block->first_attribute("start");
                std::pair<UChar, UChar> b;
                if (start && start->value()) {
                    b.first = parse_uchar(start);
                } else {
                    throw std::runtime_error("banned-block requires start attribute");
                }
                auto end = block->first_attribute("end");
                if (end && end->value()) {
                    b.second = parse_uchar(end);
                } else {
                    b.second = b.first;
                }
                m_banned_blocks.emplace(b);
            }
            auto m = config->first_node("max-chars");
            if (m && m->value()) {
                std::istringstream ss(m->value());
                ss >> m_max;
            }
        }

        virtual void do_dump_config(rapidxml::xml_document<> &doc, rapidxml::xml_node<> *config) override {
            for (auto const &block : m_banned_blocks) {
                auto b = doc.allocate_node(node_element, "banned-block");
                std::ostringstream start_ss;
                start_ss << "U+" << std::hex << std::setw(4) << block.first;
                b->append_attribute(doc.allocate_attribute("start", doc.allocate_string(start_ss.str().c_str())));
                start_ss.str("");
                start_ss << "U+" << std::hex << std::setw(4) << block.second;
                b->append_attribute(doc.allocate_attribute("end", doc.allocate_string(start_ss.str().c_str())));
                config->append_node(b);
            }
            std::ostringstream ss;
            ss << m_max;
            auto b = doc.allocate_node(node_element, "max-chars");
            b->value(doc.allocate_string(ss.str().c_str()));
            config->append_node(b);
        }

        virtual FILTER_RESULT apply(SESSION_DIRECTION dir, Stanza &s) override {
            if (dir == OUTBOUND) {
                return PASS;
            }
            if (s.name() == Message::name) {
                Message &msg = dynamic_cast<Message &>(s);
                if (msg.type() == Message::GROUPCHAT) {
                    return PASS; // Dropping groupchat messages would lead to confusion in MUCs.
                }
                auto bodytag = msg.node()->first_node("body");
                if (!bodytag || !bodytag->value()) return PASS;
                std::string body{bodytag->value(), bodytag->value_size()};
                if (std::find_if(body.begin(), body.end(), [](const char c) { return c & (1 << 7); }) == body.end()) {
                    // ASCII only.
                    return PASS;
                }
                // Decode from UTF-8
                std::unique_ptr<UChar[]> output{new UChar[body.size() + 1]};
                UChar *ptr = output.get();
                const char *data = body.data();
                UErrorCode error = U_ZERO_ERROR;
                ucnv_toUnicode(utf8(), &ptr, output.get() + body.size(), &data, data + body.size(), nullptr, TRUE,
                               &error);
                std::unique_ptr<UChar[]> norm{new UChar[2 * (ptr - output.get())]};
                int32_t sz = unorm2_normalize(normalizer(), output.get(), ptr - output.get(), norm.get(),
                                              2 * (ptr - output.get()), &error);
                std::size_t count = 0;
                for (int32_t i{0}; i < sz; ++i) {
                    for (auto const &block : m_banned_blocks) {
                        if (block.first <= norm[i] && norm[i] <= block.second) {
                            ++count;
                        }
                    }
                }
                if (count > m_max) {
                    return DROP;
                }
            }
            return PASS;
        }

    private:
        std::set<std::pair<UChar, UChar>> m_banned_blocks;
        std::size_t m_max = 8;
    };

    bool something = Filter::declare<Unicode>("unicode");
}