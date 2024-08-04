#include "filter.h"
#include "jid.h"
#include "stanza.h"

using namespace Metre;

namespace {
    class DomainTranslation : public Filter {
    public:
        class Description : public Filter::Description<DomainTranslation> {
        public:
            Description(std::string &&name) : Filter::Description<DomainTranslation>(std::move(name)) {}
            void do_config(YAML::Node & config) override {
                for (auto const & [from, to] : m_switcheroo) {
                    config[from] = to;
                }
            }

            void config(YAML::Node const & config) override {
                for (auto const & item : config) {
                    auto const& a_from = item.first;
                    auto const& a_to = item.second;
                    if (a_from && a_to) {
                        insert_mapping(a_from.as<std::string>(), a_to.as<std::string>());
                    }
                }
            }

            void insert_mapping(std::string const & froma, std::string const & toa) {
                Jid from{froma};
                Jid to{toa};
                m_switcheroo[from.domain()] = to.domain();
                m_switcheroo[to.domain()] = from.domain();
            }

            [[nodiscard]] std::map<std::string,std::string,std::less<>> const & translation_table() const {
                return m_switcheroo;
            };

        private:
            std::map<std::string,std::string,std::less<>> m_switcheroo;
        };


        DomainTranslation(BaseDescription &b, Config::Domain &, YAML::Node const &) : Filter(b) {
        }

        sigslot::tasklet<FILTER_RESULT> apply(std::shared_ptr<sentry::span>, FILTER_DIRECTION dir, Stanza &s) override {
            if (dir == FILTER_DIRECTION::FROM) {
                co_return PASS;
            }
            auto descr = dynamic_cast<DomainTranslation::Description const &>(m_description);
            // Step 1: Rewrite from.
            {
                Jid const & f = s.from();
                auto i = descr.translation_table().find(f.domain());
                if (i != descr.translation_table().end()) {
                    // Replace here.
                }
            }
            // Step 2: Rewrite to.
            co_return PASS;
        }
    };

    bool something = Filter::declare<DomainTranslation>("domain-translation");
}