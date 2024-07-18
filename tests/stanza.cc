#include "stanza.h"
#include "gtest/gtest.h"
#include <iostream>
#include "rapidxml_print.hpp"

using namespace Metre;

class MessageTest : public ::testing::Test {
public:
    std::unique_ptr<Message> msg;
    rapidxml::xml_document<> doc;
    rapidxml::xml_document<> pdoc;
    const std::string stream_xml = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='from.example' to='to.example'>";
    const std::string msg_xml = "<message from='foo@example.org/lmas' to='bar@example.net/laks' type='chat' id='1234'><body>This is the body &amp; stuff</body></message>";

    void SetUp() override {
        pdoc.parse<rapidxml::parse_fastest | rapidxml::parse_open_only>(stream_xml);
        doc.parse<rapidxml::parse_fastest|rapidxml::parse_parse_one>(msg_xml, &pdoc);
        msg = std::make_unique<Message>(doc.first_node());
    }

    static std::string print(Stanza & s) {
        rapidxml::xml_document<> tmp_doc;
        std::string tmp_buffer;
        s.render(tmp_doc);
        rapidxml::print(std::back_inserter(tmp_buffer), *(tmp_doc.first_node()), rapidxml::print_no_indenting);
        return tmp_buffer;
    }
};

TEST_F(MessageTest, IdMatches) {
    ASSERT_EQ(msg->id(), std::string("1234"));
}

TEST_F(MessageTest, Reprint) {
    auto output = print(*msg);
    EXPECT_EQ(output, "<message to=\"bar@example.net/laks\" from=\"foo@example.org/lmas\" type=\"chat\" id=\"1234\"><body>This is the body &amp; stuff</body></message>");
}

TEST_F(MessageTest, MessageType) {
    ASSERT_EQ(msg->type(), Message::Type::CHAT);
}

TEST_F(MessageTest, MessageFrom) {
    ASSERT_EQ(msg->from().full(), "foo@example.org/lmas");
}

TEST_F(MessageTest, MessageTo) {
    ASSERT_EQ(msg->to().full(), "bar@example.net/laks");
}

TEST_F(MessageTest, MessageXMLNS) {
    ASSERT_EQ(msg->node()->xmlns(), "jabber:server");
}

TEST_F(MessageTest, MessageChildXMLNS) {
    ASSERT_EQ(msg->node()->first_node()->xmlns(), "jabber:server");
}

TEST_F(MessageTest, MessageBodyConst) {
    const auto * msgc = msg.get();
    auto body = msgc->node()->first_node("body");
    ASSERT_EQ(body->value(), "This is the body & stuff");
}

TEST_F(MessageTest, MessageBodyNonConst) {
    auto body = msg->node()->first_node("body");
    ASSERT_EQ(body->value(), "This is the body & stuff");
}

TEST_F(MessageTest, MessageBodyUpdate) {
    auto body = msg->node()->first_node("body");
    ASSERT_EQ(body->value(), "This is the body & stuff");
}

TEST_F(MessageTest, MessageBodyFreeze) {
    msg->freeze();
    auto body = msg->node()->first_node("body");
    ASSERT_EQ(body->value(), "This is the body & stuff");
}

TEST_F(MessageTest, MessageReplaceBody) {
    auto body = msg->node()->first_node("body");
    std::string replacement("Replacement body");
    body->value(replacement);
    auto body2 = msg->node()->first_node("body");
    ASSERT_TRUE(body2);
    ASSERT_EQ(body2->value(), "Replacement body");
}

TEST_F(MessageTest, MessageReplaceBodyDynamicDouble) {
    Stanza * stanza = msg.get();
    {
        auto msg2 = dynamic_cast<Message *>(stanza);
        auto body = msg2->node()->first_node("body");
        std::string replacement("Replacement body");
        body->value(replacement);
        auto body2 = msg2->node()->first_node("body");
        EXPECT_TRUE(body2);
        EXPECT_EQ(body2->value(), std::string("Replacement body"));
        msg->freeze();
        auto body3 = msg2->node()->first_node("body");
        EXPECT_TRUE(body3);
        EXPECT_EQ(body3->value(), std::string("Replacement body"));
    }
    {
        auto msg3 = dynamic_cast<Message *>(stanza);
        auto body3 = msg3->node()->first_node("body");
        EXPECT_EQ(body3->value(), "Replacement body");
        std::string replacement("New replacement body");
        body3->value(replacement);
        auto body4 = msg3->node()->first_node("body");
        EXPECT_TRUE(body4);
        EXPECT_EQ(body4->value(), "New replacement body");
    }
}

TEST_F(MessageTest, MessageReplaceBodyDouble) {
    {
        auto body = msg->node()->first_node("body");
        std::string replacement("Replacement body");
        body->value(replacement);
        auto body2 = msg->node()->first_node("body");
        EXPECT_TRUE(body2);
        EXPECT_EQ(body2->value(), "Replacement body");
        msg->freeze();
        auto body3 = msg->node()->first_node("body");
        EXPECT_TRUE(body3);
        EXPECT_EQ(body3->value(), std::string("Replacement body"));
    }
    {
        auto body3 = msg->node()->first_node("body");
        EXPECT_EQ(body3->value(), "Replacement body");
        std::string replacement("New replacement body");
        body3->value(replacement);
        auto body4 = msg->node()->first_node("body");
        EXPECT_TRUE(body4);
        EXPECT_EQ(body4->value(), "New replacement body");
    }
}

TEST_F(MessageTest, MessageReplaceBodyDoubleQuotes) {
    {
        auto body = msg->node()->first_node("body");
        std::string replacement("Replacement 'body'");
        body->value(replacement);
        msg->freeze();
        auto body2 = msg->node()->first_node("body");
        EXPECT_TRUE(body2);
        EXPECT_EQ(body2->value(), "Replacement 'body'");
    }
    {
        auto body2 = msg->node()->first_node("body");
        EXPECT_TRUE(body2);
        EXPECT_EQ(body2->value(), "Replacement 'body'");
    }
    {
        auto body3 = msg->node()->first_node("body");
        EXPECT_EQ(body3->value(), std::string("Replacement 'body'"));
        std::string replacement("New replacement & '\"body'");
        body3->value(replacement);
        auto body4 = msg->node()->first_node("body");
        EXPECT_TRUE(body4);
        EXPECT_EQ(body4->value(), replacement);
        msg->freeze();
    }
    std::string tmp_buffer = print(*msg);
    std::string expected = R"(<message to="bar@example.net/laks" from="foo@example.org/lmas" type="chat" id="1234"><body>New replacement &amp; &apos;&quot;body&apos;</body></message>)";
    EXPECT_EQ(tmp_buffer, expected);
}

TEST_F(MessageTest, ChangeType) {
    EXPECT_EQ(msg->type(), Message::Type::CHAT);
    EXPECT_EQ(msg->type_str(), "chat");
    msg->type(Message::Type::NORMAL);
    EXPECT_EQ(msg->type(), Message::Type::NORMAL);
    EXPECT_FALSE(msg->type_str().has_value());
    std::string tmp_buffer = print(*msg);
    std::string expected = R"(<message to="bar@example.net/laks" from="foo@example.org/lmas" id="1234"><body>This is the body &amp; stuff</body></message>)";
    EXPECT_EQ(tmp_buffer, expected);
}

TEST_F(MessageTest, Receipt) {
    auto receipt = msg->create_response();
    ASSERT_NE(receipt->node().ptr_unsafe(), nullptr);
    EXPECT_EQ(receipt->node()->name(), "message");
    receipt->node()->append_element({"urn:xmpp:receipts", "receipt"});
    ASSERT_NE(receipt->node()->first_node().ptr_unsafe(), nullptr);
    std::string tmp_buffer = print(*receipt);
    std::string expected = R"(<message to="foo@example.org/lmas" from="bar@example.net/laks" type="chat" id="1234"><receipt xmlns="urn:xmpp:receipts"/></message>)";
    EXPECT_EQ(tmp_buffer, expected);
}

TEST_F(MessageTest, Create)
{
    auto s = std::make_unique<Stanza>(Message::name, Jid{"from@example.org"}, Jid{"to@example.org"}, "chat", std::optional<std::string>());
    s->node()->append_element("hello");

    std::string tmp_buffer = print(*s);
    std::string expected = R"(<message to="to@example.org" from="from@example.org" type="chat"><hello/></message>)";
    EXPECT_EQ(tmp_buffer, expected);
}

TEST_F(MessageTest, Create2)
{
    auto s = std::make_unique<Stanza>(Message::name, Jid{"from@example.org"}, Jid{"to@example.org"}, "chat", "fish");
    s->node()->append_element({"urn:xmpp:hello", "hello"});

    {
        std::string tmp_buffer = print(*s);
        std::string expected = R"(<message to="to@example.org" from="from@example.org" type="chat" id="fish"><hello xmlns="urn:xmpp:hello"/></message>)";
        EXPECT_EQ(tmp_buffer, expected);
    }

    auto el = s->node()->first_node("hello", "urn:xmpp:hello");

    s->node()->remove_node(el);
    {
        std::string tmp_buffer = print(*s);
        std::string expected = R"(<message to="to@example.org" from="from@example.org" type="chat" id="fish"/>)";
        EXPECT_EQ(tmp_buffer, expected);
    }
}

TEST_F(MessageTest, Create3)
{
    auto s = std::make_unique<Stanza>(Message::name, Jid{"from@example.org"}, Jid{"to@example.org"}, "chat", "fish");
    auto el = s->node()->append_element({"urn:xmpp:hello", "hello"});
    el->append_element("furry");

    {
        std::string tmp_buffer = print(*s);
        std::string expected = R"(<message to="to@example.org" from="from@example.org" type="chat" id="fish"><hello xmlns="urn:xmpp:hello"><furry/></hello></message>)";
        EXPECT_EQ(tmp_buffer, expected);
    }

    auto el2 = s->node()->first_node("hello", "urn:xmpp:hello");

    s->node()->remove_node(el2);
    {
        std::string tmp_buffer = print(*s);
        std::string expected = R"(<message to="to@example.org" from="from@example.org" type="chat" id="fish"/>)";
        EXPECT_EQ(tmp_buffer, expected);
    }
}

TEST_F(MessageTest, Encapsulate) {
    rapidxml::xml_document<> tmp_doc;
    auto saved = tmp_doc.clone_node(msg->node(), true);
    saved->append_attribute(tmp_doc.allocate_attribute("xmlns", "jabber:client"));
    msg->node()->remove_all_nodes();
    auto container = msg->node()->append_element({"urn:xmpp:container", "container"});
    container->append_node(msg->node()->document()->clone_node(saved, true));
    auto tmp_buffer = print(*msg);
    std::string expected = "<message to=\"bar@example.net/laks\" from=\"foo@example.org/lmas\" type=\"chat\" id=\"1234\"><container xmlns=\"urn:xmpp:container\"><message from=\"foo@example.org/lmas\" to=\"bar@example.net/laks\" type=\"chat\" id=\"1234\" xmlns=\"jabber:client\"><body>This is the body &amp; stuff</body></message></container></message>";
    EXPECT_EQ(tmp_buffer, expected);
}

class IqTest : public ::testing::Test {
public:
    std::unique_ptr<Iq> iq;
    rapidxml::xml_document<> doc;
    std::string iq_xml = "<iq xmlns='jabber:server' from='foo@example.org/lmas' to='bar@example.net/laks' type='get' id='1234'><query xmlns='urn:xmpp:ping'/></iq>";

    void SetUp() override {
        doc.parse<rapidxml::parse_fastest|rapidxml::parse_parse_one>(const_cast<char *>(iq_xml.c_str()));
        iq = std::make_unique<Iq>(doc.first_node());
    }
};

TEST_F(IqTest, Id) {
    EXPECT_EQ(iq->id(), "1234");
}

TEST_F(IqTest, Type) {
    EXPECT_EQ(iq->type(), Iq::Type::GET);
}

TEST_F(IqTest, From) {
    EXPECT_EQ(iq->from().full(), "foo@example.org/lmas");
}

TEST_F(IqTest, To) {
    EXPECT_EQ(iq->to().full(), "bar@example.net/laks");
}

TEST_F(IqTest, Name) {
    EXPECT_EQ(iq->node()->first_node()->name(), "query");
}

TEST_F(IqTest, Namespace) {
    EXPECT_EQ(iq->node()->first_node()->xmlns(), "urn:xmpp:ping");
}

#if 0
class IqGenTest : public Test {
public:
    IqGenTest() : Test("Iq Gen") {}

    bool run() {
        Iq iq(std::string("foo@example.org/lmas"), std::string("bar@example.net/laks"), Iq::GET, std::string("1234"));
        iq.payload("<ping xmlns='urn:xmpp:ping'/>");
        rapidxml::xml_document<> doc;
        iq.render(doc);
        std::string tmp;
        rapidxml::print(std::back_inserter(tmp), doc, rapidxml::print_no_indenting);
        assert::equal(tmp,
                      "<iq to=\"bar@example.net/laks\" from=\"foo@example.org/lmas\" type=\"get\" id=\"1234\"><ping xmlns='urn:xmpp:ping'/></iq>",
                      "iq/render");
        return true;
    }
};

namespace {
    MessageTest messagetest;
    IqTest iqtest;
    IqGenTest iqgentest;
}
#endif