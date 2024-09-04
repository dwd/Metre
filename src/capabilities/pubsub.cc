//
// Created by dwd on 23/05/17.
//

#include <capability.h>
#include "node.h"

using namespace Metre;

namespace {
    namespace {
        std::string const pubsub_items = "pubsub=items";
    }
    class Pubsub : public Capability {
    public:
        class Description : public Capability::Description<Pubsub> {
        public:
            Description(std::string const &name) : Capability::Description<Pubsub>(name) {
                m_disco.emplace_back("http://jabber.org/protocol/pubsub");
            }
        };

        void publish(const Iq &iq, Node &node, std::shared_ptr<Node::Item> const &item) {
            auto facet = node.facet(pubsub_items);
            if (!facet) {
                facet = node.add_facet(
                        std::make_unique<Node::Facet>(*this, pubsub_items, true));
            }
            facet->add_item(item, true);
            std::unique_ptr<Stanza> reply = std::make_unique<Iq>(iq.to(), iq.from(), Iq::Type::RESULT, iq.id());
            m_endpoint.send(std::move(reply));
        }

        // Operations.

        sigslot::tasklet<void> publish(Iq const &iq, rapidxml::optional_ptr<rapidxml::xml_node<>> operation) {
            auto node_attr = operation->first_attribute("node");
            std::string node_name(node_attr->value());
            // Auto-create the node if it doesn't exist.
            auto itemxml = operation->first_node("item");
            if (!itemxml) throw std::runtime_error("Missing item");
            auto item_idattr = itemxml->first_attribute("id");
            std::string item_id(item_idattr->value());
            Node & node = *co_await m_endpoint.node(node_name, true);
            auto item = std::make_shared<Node::Item>(item_id, "");
            publish(iq, node, item);
            co_return;
        }

        sigslot::tasklet<void> unknown(Iq const & iq) {
            auto error = iq.create_bounce(Stanza::Error::feature_not_implemented);
            m_endpoint.send(std::move(error));
            co_return;
        }

        Pubsub(BaseDescription const &descr, Endpoint &endpoint) : Capability(descr, endpoint) {
            endpoint.add_handler("http://jabber.org/protocol/pubsub", "pubsub", [this](Iq const & iq) {
                auto operation = iq.query().first_node();
                std::string op_name{operation->name()};
                if (op_name == "publish") {
                    return publish(iq, operation);
                } else {
                    // Not known.
                    return unknown(iq);
                }
            });
        }
    };

    DECLARE_CAPABILITY(Pubsub, "pubsub");
}