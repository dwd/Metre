#ifndef METRE_FILTER__H
#define METRE_FILTER__H

#include "defs.h"

#include <map>
#include <string>
#include <memory>
#include <set>

namespace Metre {
  class Filter {
  public:
    class BaseDescription {
    protected:
      BaseDescription(std::string && name);
    public:
      std::string const name;
    protected:
      std::set<std::string> m_suppress_features;
      std::set<std::string> m_namespaces;
    };
    template<typename T> class Description : public BaseDescription {
    public:
      Description(std::string && name) : BaseDescription(std::move(name)) {};

      std::unique_ptr<T> create(XMLStream &);
    };
  protected:
    static std::multimap<std::string, BaseDescription *> & all_filters();
  public:
    Filter(XMLStream &);
    virtual bool apply(bool inbound, Stanza &) = 0;

    virtual ~Filter();

    template<typename T> static bool declare(const char * name) {
      BaseDescription * bd = new typename T::Description(name);
      for (auto & ns : bd->m_namespaces) {
        all_filters().insert(std::make_pair(ns,bd));
      }
      return true;
    }
    static void instantiate(std::string const & xmlns, XMLStream &);

  protected:
    XMLStream & m_stream;
  };
}

#endif
