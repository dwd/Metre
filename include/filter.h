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

#include <map>
#include <string>
#include <memory>
#include <set>

namespace Metre {
    class Filter {
    public:
        class BaseDescription {
        protected:
            BaseDescription(std::string &&name);

        public:
            std::string const name;
        protected:
            std::set<std::string> m_suppress_features;
        public:
            std::set<std::string> m_namespaces;
        };

        template<typename T>
        class Description : public BaseDescription {
        public:
            Description(std::string &&name) : BaseDescription(std::move(name)) {};

            std::unique_ptr<T> create(XMLStream &);
        };

    protected:
        static std::multimap<std::string, BaseDescription *> &all_filters();

    public:
        Filter(XMLStream &);

        virtual bool apply(bool inbound, Stanza &) = 0;

        virtual ~Filter();

        template<typename T>
        static bool declare(const char *name) {
            BaseDescription *bd = new typename T::Description(name);
            for (auto &ns : bd->m_namespaces) {
                all_filters().insert(std::make_pair(ns, bd));
            }
            return true;
        }

        static void instantiate(std::string const &xmlns, XMLStream &);

    protected:
        XMLStream &m_stream;
    };
}

#endif
