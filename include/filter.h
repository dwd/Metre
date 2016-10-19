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

#ifndef METRE_FILTER__H
#define METRE_FILTER__H

#include "defs.h"
#include "config.h"

#include <map>
#include <string>
#include <memory>
#include <set>
#include <rapidxml.hpp>

namespace Metre {
    class Filter {
    public:
        class BaseDescription {
        protected:
            BaseDescription(std::string &&aname) : name(std::move(aname)) {}

        public:
            virtual void config(rapidxml::xml_node<> *config);

            virtual rapidxml::xml_node<> *config(rapidxml::xml_document<> &doc);

            virtual std::unique_ptr<Filter> create(Config::Domain &domain, rapidxml::xml_node<> *config) = 0;

        public:
            std::string const name;
        };

        template<typename T>
        class Description : public BaseDescription {
        public:
            Description(std::string &&name) : BaseDescription(std::move(name)) {}

            virtual std::unique_ptr<Filter> create(Config::Domain &domain, rapidxml::xml_node<> *config) override {
                return std::unique_ptr<Filter>(new T(*this, domain, config));
            }
        };

    public:
        static std::map<std::string, BaseDescription *> &all_filters();

    public:
        Filter(BaseDescription &b) : m_description(b) {}

        /* Interface */
        /* Actually do the filter. Tinkering with the stanza is fine. */
        virtual FILTER_RESULT apply(SESSION_DIRECTION dir, Stanza &) = 0;

    protected:
        /* Node will be an element of the filter name. */
        virtual void do_dump_config(rapidxml::xml_node<> *) {}

        BaseDescription const &m_description;

    public:
        virtual ~Filter() {}

        template<typename T>
        static bool declare(const char *name) {
            BaseDescription *bd = new typename T::Description(name);
            all_filters().insert(std::make_pair(bd->name, bd));
            return true;
        }

        rapidxml::xml_node<> *dump_config(rapidxml::xml_document<> &doc);
    };
}

#endif
