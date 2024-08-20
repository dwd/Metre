//
// Created by dave on 14/08/2024.
//

#include "filter.h"
#include "stanza.h"

using namespace Metre;

namespace {
    const std::string MUC_NS = "http://jabber.org/protocol/muc";

    struct UserMuc {
        Jid muc_jid; // Including nickname
        std::set<Jid> joined; // Tracks which resources of this user have joined, expressed as full jid.
    };

    class Minimix : public Filter {
    private:
        std::map<std::pair<std::string,std::string>, UserMuc> m_mucs;
    public:
        class Description : public Filter::Description<Minimix> {
        public:
            Description(std::string && name) : Filter::Description<Minimix>(std::move(name)) {}
        };

        Minimix(BaseDescription &b, Config::Domain &, YAML::Node const &) : Filter(b) {}

        sigslot::tasklet<FILTER_RESULT> apply(std::shared_ptr<sentry::span>, Metre::FILTER_DIRECTION dir, Metre::Stanza & s) override {
            if (dir == Metre::FILTER_DIRECTION::FROM) {
                // Does this look like a MUC Join?
                if (s.name() == Presence::name) {
                    if (s.node()->first_node("x", MUC_NS)) {
                        auto it = m_mucs.find(std::make_pair(s.to().bare(), s.from().bare()));
                        if (it == m_mucs.end()) {
                            auto [it_added, ok] = m_mucs.emplace(std::make_pair(std::make_pair(s.to().bare(), s.from().bare()), s.to().full_jid()));
                            if (ok) it = it_added;
                        }
                    }
                }
            }
            co_return PASS;
        }
    };

    bool something = Metre::Filter::declare<Minimix>("minimix");
}
