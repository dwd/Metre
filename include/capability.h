//
// Created by dwd on 11/05/17.
//

#ifndef METRE_CAPABILITY_H
#define METRE_CAPABILITY_H

#include <string>
#include <list>
#include <map>
#include "jid.h"
#include "stanza.h"
#include "endpoint.h"

namespace Metre {
    class Endpoint;
    class Capability {
    public:
        class BaseDescription {
        protected:
            std::list<std::string> m_disco;
        private:
            std::string const &m_name;
        public:
            explicit BaseDescription(std::string const &);

            std::list<std::string> const &disco() const {
                return m_disco;
            }

            virtual Capability *instantiate(Endpoint &endpoint) = 0;

            virtual ~BaseDescription();
        };

    protected:
        BaseDescription const &m_description;
        Endpoint &m_endpoint;

        static std::map<std::string, BaseDescription *> &all_capabilities();

    public:
        Capability(BaseDescription const &, Endpoint &);

        BaseDescription const &description() const {
            return m_description;
        }

        template<typename T>
        class Description : public BaseDescription {
        public:
            explicit Description(std::string const &name) : BaseDescription(name) {}

            Capability *instantiate(Endpoint &endpoint) override {
                return new T(*this, endpoint);
            }
        };


        static std::unique_ptr<Capability> create(std::string const &name, Endpoint &jid);

        template<typename T>
        static bool declare(std::string const &name) {
            Capability::all_capabilities()[name] = new typename T::Description(name);
            return true;
        }

        virtual ~Capability();
    };
}

#define DECLARE_CAPABILITY(cls, name) bool declare_cap_##cls __attribute__((unused)) { Metre::Capability::declare<cls>(name) }
#endif //METRE_CAPABILITY_H
