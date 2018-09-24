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

#include "log.h"
#include <fstream>
#include <iostream>

void Metre::Log::log(Log::LEVEL lvlm, std::string const &filename, int line, std::string const &stuff) {
    const char *lvl = "UNKNOWN";
    switch (lvlm) {
        case EMERG:
            lvl = "EMERG";
            break;
        case ALERT:
            lvl = "ALERT";
            break;
        case CRIT:
            lvl = "CRIT";
            break;
        case ERR:
            lvl = "ERR";
            break;
        case WARNING:
            lvl = "WARNING";
            break;
        case NOTICE:
            lvl = "NOTICE";
            break;
        case INFO:
            lvl = "INFO";
            break;
        case DEBUG:
            lvl = "DEBUG";
            break;
        case TRACE:
            lvl = "TRACE";
    }
    std::cerr << lvl << " : " << filename << ":" << line << " :: " << stuff << std::endl;
}
