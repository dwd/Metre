/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/

#include "filter.h"
#include "jid.h"
#include "stanza.h"
#include <spiffing/spiffing.h>
#include <spiffing/clearance.h>
#include <fstream>

using namespace Metre;

namespace {
    class Spiffing : public Filter {
    public:
        class Description : public Filter::Description<Spiffing> {
            Description(std::string &&name) : Filter::Description<Spiffing>(std::move(name)) {};

            void do_config(rapidxml::xml_document<> &doc, rapidxml::xml_node<> *config) override {
                for (auto const &fname : m_policy_filenames) {
                    auto policy = doc.allocate_node(rapidxml::node_element, "policy");
                    policy->value(doc.allocate_string(fname.c_str()));
                    config->append_node(policy);
                }
            }

            void config(rapidxml::xml_node<> *config) override {
                for (auto policy = config->first_node("policy"); policy; policy = policy->next_sibling("policy")) {
                    if (!policy->value()) throw std::runtime_error("Policy requires a filename as value");
                    std::string fname{policy->value(), policy->value_size()};
                    m_policy_filenames.emplace(fname);
                    std::ifstream ifs(fname);
                    m_site.load(ifs);
                }
            }

            std::set<std::string> m_policy_filenames;
            ::Spiffing::Site m_site;
        };

        Spiffing(BaseDescription &b, Config::Domain &s, rapidxml::xml_node<> *config) : Filter(b) {
            for (auto policy = config->first_node("allowed-policy"); policy; policy->next_sibling("allowed-policy")) {
                auto att = policy->first_attribute("id");
                if (!att) {
                    policy->first_attribute("name");
                }
                if (!att) throw std::runtime_error("Allowed-policy requires an id or a name attribute");
                std::string oid{att->value(), att->value_size()};
                std::shared_ptr<::Spiffing::Spif> spif;
                try {
                    spif = ::Spiffing::Site::site().spif(oid);
                } catch (std::runtime_error &e) {
                    spif = ::Spiffing::Site::site().spif_by_name(oid);
                }
                m_allowed_policies.emplace(spif->policy_id());
            }
            for (auto clearance = config->first_node("clearance"); clearance; clearance->next_sibling("clearance")) {
                std::shared_ptr<::Spiffing::Clearance> clr{
                        new ::Spiffing::Clearance(std::string{clearance->contents(), clearance->contents_size()},
                                                  ::Spiffing::Format::ANY)};
                m_clearances[clr->policy_id()] = clr;
            }
            // Load config (clearances and default label, and allowed policies)
        }

        virtual void do_dump_config(rapidxml::xml_document<> &doc, rapidxml::xml_node<> *config) override {
            // Dump config.
        }

        virtual FILTER_RESULT apply(SESSION_DIRECTION dir, Metre::Stanza &s) override {
            if (dir == OUTBOUND) {
                return PASS;
            }
            // Check inbound ACDF.
            // Check outbound ACDF.
            return PASS;
        }

        std::set<std::string> m_allowed_policies;
        std::map<std::string, std::shared_ptr<::Spiffing::Clearance>> m_clearances;
    };
}