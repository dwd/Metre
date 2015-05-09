#include "config.h"

#include <fstream>

using namespace Metre;
using namespace rapidxml;

Config::Config(std::string const & filename) : m_config_str(), m_doc() {
  load(filename);
}

void Config::load(std::string const & filename) {
  std::ifstream file(filename);
  std::string str{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
  m_config_str = std::move(str);
  m_doc.parse<parse_full>(const_cast<char *>(m_config_str.c_str()));
}
