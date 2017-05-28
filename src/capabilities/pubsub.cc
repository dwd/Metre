//
// Created by dwd on 23/05/17.
//

#include <capability.h>
#include "node.h"

using namespace Metre;

namespace {
    class Pubsub : public Capability {
    public:
        class Description : public Capability::Description<Pubsub> {
        public:
            Description(std::string const &name) : Capability::Description<Pubsub>(name) {
                m_disco.emplace_back("http://jabber.org/protocol/pubsub");
            }
        };

        Pubsub(BaseDescription const &descr, Endpoint &endpoint) : Capability(descr, endpoint) {
            endpoint.add_handler("http://jabber.org/protocol/pubsub", "pubsub", [this](Iq const &iq) {
                auto operation = iq.query().first_node();
                std::string op_name{operation->name(), operation->name_size()};
                if (op_name == "publish") {
                    // Do publish.
                    auto node_attr = operation->first_attribute("node");
                    if (!node_attr) {
                        throw Metre::stanza_bad_format("Missing node attribute");
                    }
                    std::string node_name{node_attr->value(), node_attr->value_size()};
                    // Auto-create the node if it doesn't exist.
                    auto &node = m_endpoint.node(node_name, true);
                    auto facet = node.facet("pubsub-items");
                    if (!facet) {
                        facet = node.add_facet(
                                std::unique_ptr<Node::Facet>(new Node::Facet(*this, "pubsub-items", true)));
                    }
                    //// facet->add_item(std::unique_ptr<Node::Item>(new Node::Item()))
                    // TODO : Extract payload and metadata and give in gracelessly.
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