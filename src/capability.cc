//
// Created by dwd on 11/05/17.
//

#include "capability.h"

Metre::Capability::BaseDescription::BaseDescription(std::string const &name) : m_name(name) {}

Metre::Capability::BaseDescription::~BaseDescription() {}

std::map<std::string, Metre::Capability::BaseDescription *> &Metre::Capability::all_capabilities() {
    static std::map<std::string, Metre::Capability::BaseDescription *> s_capabilities;
    return s_capabilities;
}

Metre::Capability::Capability(BaseDescription const &d, Endpoint &jid) : m_description(d), m_endpoint(jid) {}

Metre::Capability::~Capability() {}

std::unique_ptr<Metre::Capability> Metre::Capability::create(std::string const &name, Endpoint &jid) {
    auto i = all_capabilities().find(name);
    if (i == all_capabilities().end()) {
        throw std::runtime_error("No such capability " + name);
    }
    return std::unique_ptr<Capability>((*i).second->instantiate(jid));
}