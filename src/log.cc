#include "log.h"
#include <fstream>
#include <iostream>

using namespace Metre;

Log * Log::s_log = nullptr;

Log::Log(std::string const & filename)
  : m_file(false), m_active(true) {
  if (!filename.empty()) {
    m_stream.reset(new std::ofstream(filename, std::ios_base::app));
    m_file = true;
  }
  s_log = this;
}

std::ostream & Log::stream() const {
  if (m_file) {
    return *m_stream;
  } else {
    return std::cerr;
  }
}
