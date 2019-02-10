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
            std::unique_ptr<Stanza> pong = std::make_unique<Iq>(iq.to(), iq.from(), Iq::RESULT, iq.id());
            m_endpoint.send(std::move(pong));
        }

        // Operations.

        void publish(Iq const &iq, rapidxml::xml_node<> *operation) {
            auto node_attr = operation->first_attribute("node");
            if (!node_attr) {
                throw Metre::stanza_bad_format("Missing node attribute");
            }
            std::string node_name{node_attr->value(), node_attr->value_size()};
            // Auto-create the node if it doesn't exist.
            auto itemxml = operation->first_node("item");
            if (!itemxml) throw std::runtime_error("Missing item");
            auto item_idattr = itemxml->first_attribute("id");
            std::string item_id{item_idattr->value(), item_idattr->value_size()};
            auto item = std::make_shared<Node::Item>(item_id, "");
            auto siq = std::shared_ptr<Iq>(std::move(iq));
            m_endpoint.node(node_name,
                            [this, item, siq](Node &node) {
                                publish(*siq, node, item);
                            },
                            true // Auto-create.
            );
        }

        Pubsub(BaseDescription const &descr, Endpoint &endpoint) : Capability(descr, endpoint) {
            endpoint.add_handler("http://jabber.org/protocol/pubsub", "pubsub", [this](Iq const & iq) {
                iq.freeze();
                auto operation = iq.query().first_node();
                std::string op_name{operation->name(), operation->name_size()};
                if (op_name == "publish") {
                    publish(iq, operation);
                    return true;
                } else {
                    // Not known.
                    auto error = iq.create_bounce(Stanza::Error::feature_not_implemented);
                    m_endpoint.send(std::move(error));
                }
                return true;
            });
        }
    };

    DECLARE_CAPABILITY(Pubsub, "pubsub");
}