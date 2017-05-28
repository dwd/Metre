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
            std::string const m_payload;
            std::string const m_item_id;
        public:
            Item(std::string const &item_id, std::string const &payload);
        };

        class Facet {
        public:
            Capability &capability;  // Capability which owns this.
            std::string const &name; // Facet name.
            bool const visible;        // Causes node visibility in disco.

            Facet(Capability &a_capability, std::string const &a_name, bool visible);

            virtual ~Facet();

            void add_item(std::unique_ptr<Item> &&item, bool allow_override = false);

        private:
            std::list<std::unique_ptr<Item>> m_items;
            std::map<std::string, std::list<std::unique_ptr<Item>>::const_iterator> m_item_ids;
        };

        Node(Endpoint &endpoint, std::string const &name);

        virtual ~Node();

        Facet *facet(std::string const &name);

        void remove_facet(std::string const &name);

        Facet *add_facet(std::unique_ptr<Facet> &&facet);

        std::string const &name() const {
            return m_name;
        }

        std::string const &title() const {
            return m_title;
        }

    private:
        Endpoint &m_endpoint;
        std::map<std::string, std::unique_ptr<Facet>> m_facets;
        std::string const m_name;
        std::string m_title;
    };
}

#endif //METRE_NODE_H
