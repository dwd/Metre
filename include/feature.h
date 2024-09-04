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

#ifndef FEATURE__HPP
#define FEATURE__HPP

#include "defs.h"
#include "rapidxml.hpp"
#include "xmlstream.h"
#include "sentry-wrap.h"
#include "sigslot/tasklet.h"
#include <list>

namespace Metre {
    class Feature {
    public:
        enum class Type {
            FEAT_NONE = 0, FEAT_POSTAUTH, FEAT_COMP, FEAT_AUTH_FALLBACK, FEAT_AUTH, FEAT_PREAUTH, FEAT_SECURE
        };

        class BaseDescription {
        private:
            std::string const &m_xmlns;
            Feature::Type const m_type;
        public:
            BaseDescription(std::string const &, Feature::Type);

            virtual sigslot::tasklet<bool> offer(std::shared_ptr<sentry::span>, rapidxml::optional_ptr<rapidxml::xml_node<>> node, XMLStream &s) {
                co_return false;
            }

            std::string const &xmlns() const;

            virtual std::unique_ptr<Feature> instantiate(XMLStream &) = 0;

            virtual Feature::Type type(XMLStream &) {
                return m_type;
            }

            virtual ~BaseDescription();
        };

    protected:
        XMLStream &m_stream;

        static std::list<std::unique_ptr<Feature::BaseDescription>> &all_features(SESSION_TYPE);

    public:
        explicit Feature(XMLStream &);

        template<typename T>
        class Description : public BaseDescription {
        public:
            Description(std::string const &ns, Feature::Type t) : BaseDescription(ns, t) {}

            /// offer!
            std::unique_ptr<Feature> instantiate(XMLStream &s) override {
                return std::make_unique<T>(s);
            }
        };


        virtual sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction>, rapidxml::optional_ptr<rapidxml::xml_node<>>) = 0;

        virtual bool negotiate(rapidxml::optional_ptr<rapidxml::xml_node<>>) { return false; }

        static std::unique_ptr<Feature> feature(std::string_view const &xmlns, XMLStream &);

        static std::list<std::unique_ptr<Feature::BaseDescription>> const &features(SESSION_TYPE);

        template<typename T>
        static bool declare(SESSION_TYPE t) {
            Feature::all_features(t).push_back(std::make_unique<typename T::Description>());
            return true;
        }

        static Feature::Type type(std::string_view const &xmlns, XMLStream &t);

        virtual ~Feature();
    };
}

#ifdef METRE_UNIX
#define DECLARE_FEATURE(cls, typ) bool declare_##cls##_##typ __attribute__((unused)) { Metre::Feature::declare<cls>(SESSION_TYPE::typ) }
#else
#define DECLARE_FEATURE(cls, typ) bool declare_##cls##_##typ { Metre::Feature::declare<cls>(typ) }
#endif

#endif
