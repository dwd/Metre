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

#include "feature.h"

using namespace Metre;

Feature::Feature(XMLStream &s) : m_stream(s) {}

Feature::~Feature() = default;

Feature::BaseDescription::BaseDescription(std::string const &ns, Feature::Type type) : m_xmlns(ns), m_type(type) {}

std::string const &Feature::BaseDescription::xmlns() const {
    return m_xmlns;
}

Feature::BaseDescription::~BaseDescription() {}

std::list<Feature::BaseDescription *> &Feature::all_features(SESSION_TYPE t) {
    static std::map<SESSION_TYPE, std::list<Feature::BaseDescription *>> ls;
    return ls[t];
}

std::list<Feature::BaseDescription *> const &Feature::features(SESSION_TYPE t) {
    return Feature::all_features(t);
}

Feature *Feature::feature(std::string const &xmlns, XMLStream &stream) {
    for (auto f : Feature::features(stream.type())) {
        if (f->xmlns() == xmlns) {
            return f->instantiate(stream);
        }
    }
    return nullptr;
}

Feature::Type Feature::type(std::string const &xmlns, XMLStream &stream) {
    for (auto f : Feature::features(stream.type())) {
        if (f->xmlns() == xmlns) {
            return f->type(stream);
        }
    }
    return FEAT_NONE;
}
