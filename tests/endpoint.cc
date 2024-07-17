//
// Created by dwd on 25/05/17.
//

#include "sigslot.h"
#include "endpoint.h"
#include "gtest/gtest.h"
#include <iostream>
#include <rapidxml_print.hpp>

using namespace Metre;

namespace {
    rapidxml::xml_document<> doc;

}

namespace Metre {
    namespace Router {
        std::list<std::function<void()>> pending;

        void defer(std::function<void()> &&fn) {
            std::cout << "Deferring call" << std::endl;
            pending.emplace_back(fn);
        }

        void run_pending() {
            while (!pending.empty()) {
                std::list<std::function<void()>> tmp(std::move(pending));
                for (auto &fn : tmp) {
                    fn();
                }
            }
        }
    }
}

namespace sigslot {
    void resume(std::coroutine_handle<> coro) {
        std::cout << "Deferring resumption for " << coro.address() << std::endl;
        Metre::Router::defer([=]() {
            std::coroutine_handle<> c = coro;
            std::cout << "Resuming (deferred) " << c.address() << std::endl;
            c.resume();
            std::cout << "Resumption (deferred completed) " << c.address() << std::endl;
        });
    }
}

class EndpointTest : public ::testing::Test, public sigslot::has_slots {
public:
    bool stanza_seen = false;
    rapidxml::xml_document<> doc;
    Endpoint *endpoint;

    void SetUp() override {
        endpoint = &Endpoint::endpoint(Jid("domain.example"));
    }

    // Utility function
    template<typename S>
    std::unique_ptr<Stanza> parse_stanza(std::string const &s) {
        doc.clear();
        doc.parse<rapidxml::parse_fastest|rapidxml::parse_parse_one>(s);
        return std::make_unique<S>(doc.first_node());
    }

    // Callbacks

    void check_msg_bounce(Stanza &stanza, Jid const &endpoint_jid, Jid const &stanza_to) {
        stanza_seen = true;
        ASSERT_EQ(stanza.id(), "qwerty");
        ASSERT_EQ(stanza.name(), Message::name);
        ASSERT_EQ(stanza.to().full(), std::string("dwd@dave.cridland.net/90210"));
        ASSERT_EQ(stanza.type_str(), std::string("error"));
        // Now reparse the stanza.
        std::string xml;
        {
            rapidxml::xml_document<> doc;
            stanza.render(doc);
            rapidxml::print(std::back_inserter(xml), doc, rapidxml::print_no_indenting);
        }
        rapidxml::xml_document<> doc;
        doc.parse<rapidxml::parse_full>(const_cast<char *>(xml.c_str()));
        auto msg = doc.first_node("message");
        ASSERT_TRUE(msg);
        auto err = msg->first_node("error");
        ASSERT_TRUE(err);
        ASSERT_EQ(err->first_attribute("type")->value(), std::string("cancel"));
        ASSERT_TRUE(err->first_node("service-unavailable", "urn:ietf:params:xml:ns:xmpp-stanzas"));
    }

    void check_ping_response(Stanza &stanza, Jid const &endpoint_jid, Jid const &stanza_to) {
        stanza_seen = true;
        ASSERT_EQ(stanza.id(), "5678");
        ASSERT_EQ(stanza.name(), Iq::name);
        ASSERT_EQ(stanza.to().full(), std::string("dwd@dave.cridland.net/90210"));
        ASSERT_EQ(stanza.type_str(), std::string("result"));
    }

    void check_discoinfo_response(Stanza &stanza, Jid const &endpoint_jid, Jid const &stanza_to) {
        stanza_seen = true;
        ASSERT_EQ(stanza.id(), "1234");
        ASSERT_EQ(stanza.name(), Iq::name);
        //ASSERT_EQ(stanza.to(), stanza_to,);
        ASSERT_EQ(stanza.to().full(), std::string("dwd@dave.cridland.net/90210"));
        ASSERT_EQ(stanza.type_str(), std::string("result"));
        // Now reparse the stanza.
        std::string xml;
        {
            rapidxml::xml_document<> doc;
            stanza.render(doc);
            rapidxml::print(std::back_inserter(xml), doc, rapidxml::print_no_indenting);
        }
        rapidxml::xml_document<> doc;
        doc.parse<rapidxml::parse_full>(const_cast<char *>(xml.c_str()));
        std::unique_ptr<Iq> iq{new Iq(doc.first_node())};
        auto const &response = iq->query();
        ASSERT_EQ(response.name(), std::string("query"));
        ASSERT_EQ(response.xmlns(), std::string("http://jabber.org/protocol/disco#info"));
        std::set<std::string> m_features;
        for (auto feature = response.first_node(); feature; feature = feature->next_sibling()) {
            ASSERT_EQ(feature->type(), rapidxml::node_element);
            ASSERT_EQ(feature->name(), std::string("feature"));
            ASSERT_EQ(feature->xmlns(), std::string("http://jabber.org/protocol/disco#info"));
            auto var = feature->first_attribute("var");
            m_features.emplace(var->value());
        }
        ASSERT_EQ(m_features.size(), 5u);
    }

    void check_discoitems_response(Stanza &stanza, Jid const &endpoint_jid, Jid const &stanza_to, bool added) {
        stanza_seen = true;
        ASSERT_EQ(stanza.id(), "12345");
        ASSERT_EQ(stanza.name(), Iq::name);
        //ASSERT_EQ(stanza.to(), stanza_to, "Stanza to matches target");
        ASSERT_EQ(stanza.to().full(), std::string("dwd@dave.cridland.net/90210"));
        ASSERT_EQ(stanza.type_str(), std::string("result"));
        // Now reparse the stanza.
        std::string xml;
        {
            rapidxml::xml_document<> doc;
            stanza.render(doc);
            rapidxml::print(std::back_inserter(xml), doc, rapidxml::print_no_indenting);
        }
        rapidxml::xml_document<> doc;
        doc.parse<rapidxml::parse_full>(const_cast<char *>(xml.c_str()));
        std::unique_ptr<Iq> iq{new Iq(doc.first_node())};
        auto const &response = iq->query();
        ASSERT_EQ(response.name(), std::string("query"));
        ASSERT_EQ(response.xmlns(), std::string("http://jabber.org/protocol/disco#items"));
        unsigned features = 0;
        for (auto feature = response.first_node(); feature; feature = feature->next_sibling()) {
            ASSERT_EQ(feature->type(), rapidxml::node_element);
            ASSERT_EQ(feature->name(), std::string("item"));
            ASSERT_EQ(feature->xmlns(), std::string("http://jabber.org/protocol/disco#items"));
            auto jid = feature->first_attribute("jid");
            auto node = feature->first_attribute("node");
            ASSERT_FALSE(jid == nullptr) << "JID missing from item";
            ASSERT_FALSE(node == nullptr) << "Node missing from item";
            Jid item_jid(jid->value());
            ASSERT_EQ(item_jid.full(), endpoint_jid.bare());
            ASSERT_EQ(node->value(), "pubsub_node");
            ++features;
        }
        ASSERT_EQ(features, added ? 1u : 0u) << "Correct number of nodes";
    }
};

TEST_F(EndpointTest, Ping) {
    // Send a ping. Should get one back.
    std::string iq_xml = "<iq from='dwd@dave.cridland.net/90210' to='domain.example' id='5678' type='get'><ping xmlns='urn:xmpp:ping'/></iq>";
    endpoint->sent_stanza.connect(dynamic_cast<EndpointTest *>(this), &EndpointTest::check_ping_response);
    endpoint->process(parse_stanza<Iq>(iq_xml));
    Router::run_pending();
    endpoint->sent_stanza.disconnect(this);
    ASSERT_TRUE(stanza_seen) << "No stanza response!";
    stanza_seen = false;
}

TEST_F(EndpointTest, DiscoInfo) {
    // Send a disco#info query. Should get response with features.
    std::string iq_xml = "<iq from='dwd@dave.cridland.net/90210' to='domain.example' id='1234' type='get'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>";
    endpoint->sent_stanza.connect(dynamic_cast<EndpointTest *>(this), &EndpointTest::check_discoinfo_response);
    endpoint->process(parse_stanza<Iq>(iq_xml));
    Router::run_pending();
    endpoint->sent_stanza.disconnect(this);
    ASSERT_TRUE(stanza_seen) << "No stanza response!";
    stanza_seen = false;
}

TEST_F(EndpointTest, DiscoItems) {
    // Send a disco#items query. Should get response with no items.
    std::string iq_xml = "<iq from='dwd@dave.cridland.net/90210' to='domain.example' id='12345' type='get'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>";
    endpoint->sent_stanza.connect(dynamic_cast<EndpointTest *>(this),
                                  [this](Stanza &stanza, Jid const &from, Jid const &to) {
                                      check_discoitems_response(stanza, from, to, false);
                                  });
    endpoint->process(parse_stanza<Iq>(iq_xml));
    Router::run_pending();
    endpoint->sent_stanza.disconnect(this);
    ASSERT_TRUE(stanza_seen) << "No stanza response!";
    stanza_seen = false;
}

TEST_F(EndpointTest, Publish) {
    // Send a pubsub publish query. Should get empty response, maybe.
    std::string iq_xml = "<iq from='dwd@dave.cridland.net/90210' to='domain.example' id='5678' type='get'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='pubsub_node'><item id='item_id_here'><payload xmlns='https://surevine.com/protocol/test'/></item></publish></pubsub></iq>";
    endpoint->sent_stanza.connect(dynamic_cast<EndpointTest *>(this), &EndpointTest::check_ping_response);
    endpoint->process(parse_stanza<Iq>(iq_xml));
    Router::run_pending();
    endpoint->sent_stanza.disconnect(this);
    ASSERT_TRUE(stanza_seen) << "No response to publish!";
    stanza_seen = false;
    // Send a disco#items query. Should get response with one items.
    std::string iq2_xml = "<iq from='dwd@dave.cridland.net/90210' to='domain.example' id='12345' type='get'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>";
    endpoint->sent_stanza.connect(dynamic_cast<EndpointTest *>(this),
                                  [this](Stanza &stanza, Jid const &from, Jid const &to) {
                                      check_discoitems_response(stanza, from, to, true);
                                  });
    endpoint->process(parse_stanza<Iq>(iq2_xml));
    Router::run_pending();
    endpoint->sent_stanza.disconnect(this);
    ASSERT_TRUE(stanza_seen) << "No stanza response to disco#items!";
    stanza_seen = false;
}

TEST_F(EndpointTest, MessageFail) {
    std::string msg_xml = "<message from='dwd@dave.cridland.net/90210' to='domain.example' type='chat' id='qwerty'><body>Testing</body></message>";
    endpoint->sent_stanza.connect(dynamic_cast<EndpointTest *>(this), &EndpointTest::check_msg_bounce);
    endpoint->process(parse_stanza<Message>(msg_xml));
    Router::run_pending();
    endpoint->sent_stanza.disconnect(this);
    ASSERT_TRUE(stanza_seen) << "No stanza response to message!";
    stanza_seen = false;
}