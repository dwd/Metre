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
            void do_config(rapidxml::xml_document<> & doc, rapidxml::xml_node<> * config) override {
                for (auto const & mapping : m_switcheroo) {
                    auto map = doc.allocate_node(rapidxml::node_element, "map");
                    map->append_attribute(doc.allocate_attribute("from", doc.allocate_string(mapping.first.c_str())));
                    map->append_attribute(doc.allocate_attribute("to", doc.allocate_string(mapping.second.c_str())));
                    config->append_node(map);
                }
            }

            void config(rapidxml::xml_node<> * config) override {
                for (auto n = config->first_node("map"); n; n = n->next_sibling("map")) {
                    auto a_from = n->first_attribute("from");
                    auto a_to = n->first_attribute("to");
                    if (a_from && a_to) {
                        if (a_from->value() && a_to->value()) {
                            insert_mapping(a_from->value(), a_to->value());
                        }
                    }
                }
            }

            void insert_mapping(std::string const & froma, std::string const & toa) {
                Jid from{froma};
                Jid to{toa};
                m_switcheroo[from.domain()] = to.domain();
                m_switcheroo[to.domain()] = from.domain();
            }

            std::map<std::string,std::string> const & translation_table() const {
                return m_switcheroo;
            };

        private:
            std::map<std::string,std::string> m_switcheroo;
        };


        DomainTranslation(BaseDescription &b, Config::Domain &, rapidxml::xml_node<> *) : Filter(b) {
        }

        virtual FILTER_RESULT apply(SESSION_DIRECTION dir, Stanza &s) override {
            if (dir == OUTBOUND) {
                return PASS;
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
            return PASS;
        }
    };

    bool something = Filter::declare<DomainTranslation>("domain-translation");
}