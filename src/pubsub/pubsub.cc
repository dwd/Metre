//
// Created by dwd on 11/05/17.
//

#include <stanza.h>
#include <map>
#include <spiffing/label.h>

namespace Metre {
    class Pubsub {
        enum class AFFILIATION {
            OUTCAST,
            NONE,
            MEMBER,
            ADMINISTRATOR,
            PUBLISHER,
            OWNER
        };

        class Item {
            std::string m_id;
            std::string m_payload;
            Spiffing::Label m_label;
            Jid m_publisher;
        };

        class Node {
            std::list<std::string> m_items_id;
            std::map<std::string, std::unique_ptr<Item>> m_items; // PERSIST

            std::map<Jid, AFFILIATION> m_affiliation; // PERSIST

            void publish(Jid const &publisher, std::unique_ptr<Item>);

        };

        std::map<std::string, Metre::Pubsub::Node> m_nodes;

        void handle(Message &msg);

        void handle(Iq &iq);

        void handle(Presence &pres);
    };
}