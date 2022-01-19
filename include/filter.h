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
#include <yaml-cpp/yaml.h>

namespace Metre {
    class Filter {
    public:
        class BaseDescription {
        protected:
            explicit BaseDescription(std::string &&aname) : name(std::move(aname)) {}

            virtual void do_config(YAML::Node & config) {
                // No config by default.
            }

        public:
            virtual void config(YAML::Node const &);

            YAML::Node config();

            virtual std::unique_ptr<Filter> create(Config::Domain &domain, YAML::Node const & config) = 0;

            virtual ~BaseDescription() = default;

            std::string const name;
        };

        template<typename T>
        class Description : public BaseDescription {
        public:
            explicit Description(std::string &&name) : BaseDescription(std::move(name)) {}

            std::unique_ptr<Filter> create(Config::Domain &domain, YAML::Node const & config) override {
                return std::unique_ptr<Filter>(new T(*this, domain, config));
            }
        };

        using filter_map = std::map<std::string, Filter::BaseDescription *, std::less<>>;
        static filter_map &all_filters();

        explicit Filter(BaseDescription const &b) : m_description(b) {}

        /* Interface */
        /* Actually do the filter. Tinkering with the stanza is fine. */
        virtual sigslot::tasklet<FILTER_RESULT> apply(SESSION_DIRECTION dir, Stanza &) = 0;

        std::string const & name() const {
            return m_description.name;
        }
    protected:
        /* Node will be an element of the filter name. */
        virtual void do_dump_config(YAML::Node &) {
            // No config to write by default
        }

        BaseDescription const &m_description;

    public:
        virtual ~Filter() = default;

        template<typename T>
        static bool declare(const char *name) {
            // Bare pointer as this is premain and the object is never freed by design.
            BaseDescription *bd = new typename T::Description(name);
            all_filters().try_emplace(bd->name, bd);
            return true;
        }

        YAML::Node dump_config();
    };
}

#endif
