//
// Created by dwd on 28/05/17.
//

#include <endpoint.h>
#include <node.h>

using namespace Metre;

Node::Node(Endpoint &endpoint, std::string const &aname) : m_endpoint(endpoint), m_name(aname) {
}

Node::~Node() {}

Node::Facet *Node::facet(std::string const &name) {
    auto it = m_facets.find(name);
    if (it == m_facets.end()) return nullptr;
    return it->second.get();
}

Node::Facet::Facet(Capability &a_capability, std::string const &a_name, bool a_visible)
        : capability(a_capability), name(a_name), visible(a_visible) {
}

Node::Facet *Node::add_facet(std::unique_ptr<Facet> &&facet) {
    auto r = m_facets.emplace(facet->name, std::move(facet));
    return r.first->second.get();
}

Node::Facet::~Facet() = default;

const Node::Item &Node::Facet::add_item(const std::shared_ptr<Item> &item, bool allow_override) {
    auto old = m_item_ids.find(item->id());
    if (old != m_item_ids.end()) {
        if (!allow_override) {
            throw std::runtime_error("Item exists");
        }
        m_items.erase((*old).second);
        m_item_ids.erase(old);
    }
    m_items.push_front(item);
    auto it = m_items.begin();
    m_item_ids.emplace(std::make_pair((*it)->id(), it));
    return *(*it);
}

Node::Subscription::Subscription(Jid &ajid) : jid(ajid) {
}

Node::Item::Item(std::string const &item_id, std::string const &payload)
        : m_item_id(item_id), m_payload(payload) {
}