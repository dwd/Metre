#ifndef METRE_LOG__HPP
#define METRE_LOG__HPP

#include <ostream>
#include <memory>
#include <ctime>

namespace Metre {
  class Log {
  public:
    Log(std::string const &);
    bool active() const {
      return m_active;
    }
    std::ostream & stream() {
      return *m_stream;
    }
    static Log & log() {
      return *s_log;
    }
    static std::string timestamp() {
      std::string tmp;
      const std::size_t l = 24;
      tmp.resize(l);
      std::time_t t = std::time(nullptr);
      std::size_t res = std::strftime(&(tmp[0]), l, "%Y-%m-%dT%H:%M:%S", std::gmtime(&t));
      tmp.resize(res);
      return std::move(tmp);
    }
  private:
    bool m_active;
    std::unique_ptr<std::ostream> m_stream;
    static Log * s_log;
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

#define METRE_LOG(x) if (Metre::Log::log().active()) { Metre::Log::log().stream() << Metre::Log::timestamp() << ' ' << __FILE__ << ':' << __LINE__ << " : " << x << std::endl; } (void) 0

#endif
