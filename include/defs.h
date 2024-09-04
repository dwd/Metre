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

#ifndef DEFS_HPP
#define DEFS_HPP

namespace Metre {
    enum class SESSION_TYPE {
        C2S,
        S2S,
        X2X,
        COMP,
        INTERNAL
    };


    enum class SESSION_DIRECTION {
        INBOUND,
        OUTBOUND
    };

    enum class TLS_MODE {
        IMMEDIATE,
        STARTTLS
    };

    enum class TLS_PREFERENCE {
        PREFER_IMMEDIATE,
        PREFER_STARTTLS,
        PREFER_ANY
    };

    enum class FILTER_RESULT {
        PASS,
        DROP
    };

    enum class FILTER_DIRECTION {
        FROM,
        TO
    };

    class Feature;

    class Filter;

    class Stanza;

    class XMLStream;

    class Route;

    class NetSession;
}

#ifndef SIGSLOT_PURE_ISO
#define SIGSLOT_PURE_ISO
#endif
#ifndef SIGSLOT_RESUME_OVERRIDE
#define SIGSLOT_RESUME_OVERRIDE
#endif
#if defined(_WIN32) || defined(_WIN64)
#define __attribute(x) /* Nothing */
#pragma warning(disable : 4514)
typedef signed long long ssize_t;
#endif
#endif
