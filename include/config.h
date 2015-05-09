#ifndef METRE_CONFIG__HPP
#define METRE_CONFIG__HPP

#include <string>
#include <map>
#include <optional>

#include <rapidxml.hpp>
#include "defs.hpp"

namespace Metre {
  class Config {
  public:
    class Forwarding {
    public:
      std::string const & domain() const;
      SESSION_TYPE transport_type() const;
      std::optional<std::string> const & override_srv() const;
      std::optional<std::string> const & override_host() const;
      unsigned short override_port() const;

      Forwarding(rapidxml::xml_node<> * node);
    };
    class Security {
    public:
      std::string const & domain() const;
      bool require_tls() const;
      bool require_pki() const;
      std::optional<std::string> const & secret() const;

      Security(rapidxml::xml_node<> * node);
    };
    Config(std::string const & filename);

    std::string asString();

    std::string const & default_domain() const;
    std::string const & runtime_dir() const;

    void load(std::string const & filename);

  private:
    std::string m_config_str;
    rapidxml::xml_document<> m_doc;

    std::string m_default_domain;
    std::string m_runtime_dir;
  };
}

#endif
