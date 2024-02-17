//
// Created by dwd on 24/05/17.
//

#include <capability.h>

using namespace Metre;

namespace {
    class Disco : public Capability {
    public:
        class Description : public Capability::Description<Disco> {
        public:
            Description(std::string const &name) : Capability::Description<Disco>(name) {
                m_disco.emplace_back("http://jabber.org/protocol/disco#info");
                m_disco.emplace_back("http://jabber.org/protocol/disco#items");
            }
        };

        Disco(BaseDescription const &descr, Endpoint &endpoint) : Capability(descr, endpoint) {
            endpoint.add_handler("http://jabber.org/protocol/disco#items", "query", [this](Iq const &iq) {
                return items(iq);
            });
            endpoint.add_handler("http://jabber.org/protocol/disco#info", "query", [this](Iq const &iq) {
                return info(iq);
            });
        }

        sigslot::tasklet<void> items(Iq const &iq) {
            auto &query = iq.query();
            auto node = query.first_attribute("node");
            if (node) {
                // We don't know what to do here yet!
                // TODO : dispatch to node endpoint.
                auto bounce = iq.create_bounce(Stanza::Error::service_unavailable);
                m_endpoint.send(std::move(bounce));
            } else {
                rapidxml::xml_document<> doc;
                auto container = doc.allocate_node(rapidxml::node_element, "root");
                auto response = doc.allocate_node(rapidxml::node_element, "query");
                container->append_node(response);
                response->append_attribute(doc.allocate_attribute("xmlns", "http://jabber.org/protocol/disco#items"));
                for (auto const &node : m_endpoint.nodes()) {
                    auto item = doc.allocate_node(rapidxml::node_element, "item");
                    item->append_attribute(doc.allocate_attribute("jid", m_endpoint.jid().full().c_str()));
                    item->append_attribute(doc.allocate_attribute("node", node.second->name().c_str()));
                    item->append_attribute(doc.allocate_attribute("name", node.second->title().c_str()));
                    response->append_node(item);
                }
                std::unique_ptr<Iq> result{new Iq(iq.to(), iq.from(), Metre::Iq::RESULT, iq.id())};
                result->payload(container);
                m_endpoint.send(std::move(result));
            }
            co_return;
        }

        sigslot::tasklet<void> info(Iq const &iq) {
            auto &query = iq.query();
            auto node = query.first_attribute("node");
            if (node) {
                // We don't know what to do here yet!
                // TODO : dispatch to node endpoint.
                auto bounce = iq.create_bounce(Stanza::Error::service_unavailable);
                m_endpoint.send(std::move(bounce));
            } else {
                rapidxml::xml_document<> doc;
                auto container = doc.allocate_node(rapidxml::node_element, "root");
                auto response = doc.allocate_node(rapidxml::node_element, "query");
                container->append_node(response);
                response->append_attribute(doc.allocate_attribute("xmlns", "http://jabber.org/protocol/disco#info"));
                for (auto const &cap : m_endpoint.capabilities()) {
                    for (auto const &feature : cap->description().disco()) {
                        auto feat = doc.allocate_node(rapidxml::node_element, "feature");
                        feat->append_attribute(doc.allocate_attribute("var", feature.c_str()));
                        response->append_node(feat);
                    }
                }
                std::unique_ptr<Iq> result{new Iq(iq.to(), iq.from(), Metre::Iq::RESULT, iq.id())};
                result->payload(container);
                m_endpoint.send(std::move(result));
            }
            co_return;
        }
    };

    DECLARE_CAPABILITY(Disco, "disco");
}