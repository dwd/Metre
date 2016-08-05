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
#include <memory>
#include <ctime>

namespace Metre {
    class Log {
    public:
        typedef enum {
            EMERG,
            ALERT,
            CRIT,
            ERR,
            WARNING,
            NOTICE,
            INFO,
            DEBUG
        } LEVEL;

        Log(std::string const &);

        bool active() const {
            return m_active;
        }

        std::ostream &stream() const;

        static Log &log() {
            return *s_log;
        }

        std::string timestamp() {
            if (m_file) {
                std::string tmp;
                const std::size_t l = 24;
                tmp.resize(l);
                std::time_t t = std::time(nullptr);
                std::size_t res = std::strftime(&(tmp[0]), l, "%Y-%m-%dT%H:%M:%S ", std::gmtime(&t));
                tmp.resize(res);
                return std::move(tmp);
            } else {
                return "";
            }
        }

        const char *level(LEVEL x) {
            if (m_file) {
                switch (x) {
                    case EMERG:
                        return "EMERGENCY ";
                    case ALERT:
                        return "ALERT ";
                    case CRIT:
                        return "CRITICAL ";
                    case ERR:
                        return "ERROR ";
                    case WARNING:
                        return "WARNING ";
                    case NOTICE:
                        return "NOTICE ";
                    case INFO:
                        return "INFO ";
                    default:
                        return "DEBUG ";
                }
            } else {
                switch (x) {
                    case EMERG:
                        return "<0> ";
                    case ALERT:
                        return "<1> ";
                    case CRIT:
                        return "<2> ";
                    case ERR:
                        return "<3> ";
                    case WARNING:
                        return "<4> ";
                    case NOTICE:
                        return "<5> ";
                    case INFO:
                        return "<6> ";
                    default:
                        return "<7> ";
                }
            }
        }

    private:
        bool m_file;
        bool m_active;
        std::unique_ptr<std::ostream> m_stream;
        static Log *s_log;
    };


}

/**
 // Can't get these to work.
template<typename T> Metre::Log & operator << (Metre::Log & log, T const & t) {
  if (log.active()) {
    log.stream() << t;
  }
  return log;
}
template<typename T> Metre::Log & operator << (Metre::Log & log, T const * t) {
  if (log.active()) {
    log.stream() << t;
  }
  return log;
}
*/

#define METRE_LOG(l, x) if (Metre::Log::log().active()) { Metre::Log::log().stream() << Metre::Log::log().level( l ) << Metre::Log::log().timestamp() << __FILE__ << ':' << __LINE__ << " : " << x << std::endl; } (void) 0

#endif
