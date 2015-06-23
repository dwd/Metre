#include "log.h"
#include <fstream>

using namespace Metre;

Log * Log::s_log = nullptr;

Log::Log(std::string const & filename)
  : m_active(true), m_stream(new std::ofstream(filename, std::ios_base::app)) {
  s_log = this;
}
