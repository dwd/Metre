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

#include "jid.h"
#include <unicode/usprep.h>
#include <unicode/ucnv.h>
#include <memory>
#include <log.h>
#include <algorithm>

using namespace Metre;

namespace {
#if defined(HAVE_ICU2) || defined(HAVE_ICU)
    UStringPrepProfile *nameprep() {
        static UStringPrepProfile *p = 0;
        if (!p) {
            UErrorCode error = U_ZERO_ERROR;
            p = usprep_openByType(USPREP_RFC3491_NAMEPREP, &error);
        }
        return p;
    }

    UConverter *utf8() {
        static UConverter *c = 0;
        UErrorCode error = U_ZERO_ERROR;
        if (!c) c = ucnv_open("utf-8", &error);
        return c;
    }

    std::string stringprep(UStringPrepProfile *p, std::string const &input) {
        if (std::find_if(input.begin(), input.end(), [](const char c) { return c & (1 << 7); }) == input.end()) {
            std::string ret = input;
            std::transform(ret.begin(), ret.end(), ret.begin(),
                           [](const char c) { return static_cast<char>(tolower(c)); });
            return ret;
        }
        auto output = std::make_unique<UChar[]>(input.size() + 1);
        UChar *ptr = output.get();
        const char *data = input.data();
        UErrorCode error = U_ZERO_ERROR;
        ucnv_toUnicode(utf8(), &ptr, output.get() + input.size(), &data, data + input.size(), nullptr, TRUE, &error);
        auto prepped = std::make_unique<UChar[]>(2 * (ptr - output.get()));
        UParseError parse_error;
        int32_t sz = usprep_prepare(p, output.get(), ptr - output.get(), prepped.get(), ptr - output.get(),
                                    USPREP_DEFAULT, &parse_error, &error);
        std::string ret;
        ret.resize(2 * input.size());
        data = ret.data();
        const UChar *prepped_data = prepped.get();
        ucnv_fromUnicode(utf8(), const_cast<char **>(&data), ret.data() + ret.capacity(), &prepped_data,
                         prepped.get() + sz, nullptr, TRUE, &error);
        ret.resize(data - ret.data());
        return ret;
    }
#else

    void *nameprep() {
        return nullptr;
    }

    std::string stringprep(void *, std::string const &input) {
        if (std::find_if(input.begin(), input.end(), [](const char c) { return c & (1 << 7); }) == input.end()) {
            std::string ret = input;
            std::transform(ret.begin(), ret.end(), ret.begin(),
                           [](const char c) { return static_cast<char>(tolower(c)); });
            return ret;
        }
        throw std::runtime_error("IDNA encountered without unicode support");
    }

#endif
}

void Jid::parse(std::string const &s) {
    ssize_t at_pos{-1};
    ssize_t slash_pos{-1};
    for (size_t c{0}; c != s.length(); ++c) {
        switch (s[c]) {
            case '@':
                if (at_pos < 0) {
                    at_pos = c;
                }
                break;
            case '/':
                slash_pos = c;
                goto loop_exit;
        }
    }
    loop_exit:
    if (at_pos >= 0) {
        m_local.emplace(s.data(), at_pos);
    }
    if (slash_pos >= 0) {
        m_resource.emplace(s.data() + slash_pos + 1, s.length() - slash_pos - 1);
    }
    if (at_pos < 0) {
        at_pos = 0;
    } else {
        ++at_pos;
    }
    if (at_pos == 0 && slash_pos < 0) {
        m_domain = stringprep(nameprep(), s);
    } else {
        if (slash_pos < 0) {
            slash_pos = s.length();
        }
        slash_pos -= at_pos;
        m_domain.assign(stringprep(nameprep(), std::string{s.data() + at_pos, static_cast<std::size_t>(slash_pos)}));
    }
}

std::string const &Jid::full() const {
    if (!m_resource) {
        return bare();
    }
    if (!m_full) {
        m_full.emplace();
        if (m_local) {
            *m_full += *m_local;
            *m_full += "@";
        }
        *m_full += m_domain;
        if (m_resource) {
            *m_full += "/";
            *m_full += *m_resource;
        }
    }
    return *m_full;
}

std::string const &Jid::bare() const {
    if (!m_bare) {
        m_bare.emplace();
        if (m_local) {
            *m_bare += *m_local;
            *m_bare += "@";
        }
        m_bare.value() += m_domain;
    }
    return *m_bare;
}
