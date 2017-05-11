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

namespace Metre {
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

            virtual Capability *instantiate(Jid const &endpoint) = 0;

            virtual ~BaseDescription();
        };

    protected:
        BaseDescription const &m_description;
        Jid m_endpoint;

        static std::map<std::string, BaseDescription *> &all_capabilities();

    public:
        Capability(BaseDescription const &, Jid const &);

        template<typename T>
        class Description : public BaseDescription {
        public:
            explicit Description(std::string const &name) : BaseDescription(name) {}

            Capability *instantiate(Jid const &endpoint) override {
                return new T(*this, endpoint);
            }
        };


        virtual bool handle(Iq const &) = 0;

        static std::unique_ptr<Capability> create(std::string const &name, Jid const &jid);

        template<typename T>
        static bool declare(std::string const &name) {
            Capability::all_capabilities()[name] = new typename T::Description(name);
            return true;
        }

        virtual ~Capability();
    };
}

#define DECLARE_CAPABILITY(cls, name) bool declare_##cls __attribute__((unused)) { Metre::Capability::declare<cls>(name) }
#endif //METRE_CAPABILITY_H
