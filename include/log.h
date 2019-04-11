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

#ifndef METRE_LOG__HPP
#define METRE_LOG__HPP

#include <ostream>
#include <sstream>
#include <memory>
#include <ctime>
#include "spdlog/spdlog.h"

namespace Metre {
    namespace Log {
        typedef enum {
            EMERG,
            ALERT,
            CRIT,
            ERR,
            WARNING,
            NOTICE,
            INFO,
            DEBUG,
            TRACE
        } LEVEL;

        void log(Log::LEVEL lvlm, std::string const &filename, int line, std::string const &stuff);
    }
}

#define METRE_LOG(l, x) {  std::ostringstream ss; ss << x; Metre::Log::log(l, __FILE__, __LINE__, ss.str()); } (void) 0

#endif
