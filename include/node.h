//
// Created by dwd on 28/05/17.
//

#ifndef METRE_NODE_H
#define METRE_NODE_H

#include <string>

namespace Metre {
    class Endpoint;

    class Capability;

    class Node {
    public:
        class Item {
            std::string const m_item_id;
            std::string const m_payload;
        public:
            Item(std::string const &item_id, std::string const &payload);

            [[nodiscard]] std::string const &id() const {
                return m_item_id;
            }
        };

        class Facet {
        public:
            Capability &capability;  // Capability which owns this.
            std::string const &name; // Facet name.
            bool const visible;        // Causes node visibility in disco.

            Facet(Capability &a_capability, std::string const &a_name, bool visible);

            virtual ~Facet();

            Item const &add_item(const std::shared_ptr<Item> &item, bool allow_override = false);

        private:
            std::list<std::shared_ptr<Item>> m_items;
            std::map<std::string, std::list<std::shared_ptr<Item>>::const_iterator, std::less<>> m_item_ids;
        };

        class Subscription {
        public:
            explicit Subscription(Jid &jid);

            Jid const jid;
        };

        Node(Endpoint &endpoint, std::string const &name);

        virtual ~Node();

        Facet *facet(std::string const &name);

        void remove_facet(std::string const &name);

        Facet *add_facet(std::unique_ptr<Facet> &&facet);

        [[nodiscard]] std::string const &name() const {
            return m_name;
        }

        [[nodiscard]] std::string const &title() const {
            return m_title;
        }

        std::set<std::unique_ptr<Subscription>> const &subscriptions() const {
            return m_subscriptions;
        }

    private:
        Endpoint &m_endpoint;
        std::map<std::string, std::unique_ptr<Facet>, std::less<>> m_facets;
        std::set<std::unique_ptr<Subscription>> m_subscriptions;
        std::string const m_name;
        std::string m_title;
    };
}

#endif //METRE_NODE_H
