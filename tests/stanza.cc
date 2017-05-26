#include "stanza.h"
#include "tests.h"
#include <iostream>
#include "rapidxml_print.hpp"

using namespace Metre;

class MessageTest : public Test {
public:
    MessageTest() : Test("Message") {}

    bool run() {
        std::string msg_xml = "<message xmlns='jabber:server' from='foo@example.org/lmas' to='bar@example.net/laks' type='chat' id='1234'><body>This is the body</body></message>";
        rapidxml::xml_document<> doc;
        doc.parse<rapidxml::parse_full>(const_cast<char *>(msg_xml.c_str()));
        Message msg(doc.first_node());
        assert::equal(msg.id(), std::string("1234"), "message/id");
        assert::equal(msg.type(), Message::Type::CHAT, "message/type");
        assert::equal(msg.from().full(), "foo@example.org/lmas", "message/from");
        assert::equal(msg.to().full(), "bar@example.net/laks", "message/to");
        assert::equal(msg.node()->first_node("body")->value(), std::string("This is the body"), "message/body");
        return true;
    }
};

class IqTest : public Test {
public:
    IqTest() : Test("Iq") {}

    bool run() {
        std::string iq_xml = "<iq xmlns='jabber:server' from='foo@example.org/lmas' to='bar@example.net/laks' type='get' id='1234'><query xmlns='urn:xmpp:ping'/></iq>";
        rapidxml::xml_document<> doc;
        doc.parse<rapidxml::parse_full>(const_cast<char *>(iq_xml.c_str()));
        Iq iq(doc.first_node());
        assert::equal(iq.id(), "1234", "iq/id");
        assert::equal(iq.type(), Iq::Type::GET, "iq/type");
        assert::equal(iq.from().full(), "foo@example.org/lmas", "iq/from");
        assert::equal(iq.to().full(), "bar@example.net/laks", "iq/to");
        assert::equal(iq.node()->first_node()->name(), std::string("query"), "iq/node-name");
        assert::equal(iq.node()->first_node()->xmlns(), std::string("urn:xmpp:ping"), "iq/node-ns");
        return true;
    }
};


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
        assert::equal(tmp, "<iq to=\"bar@example.net/laks\" from=\"foo@example.org/lmas\" type=\"get\" id=\"1234\"><ping xmlns='urn:xmpp:ping'/></iq>", "iq/render");
        return true;
    }
};

namespace {
    MessageTest messagetest;
    IqTest iqtest;
    IqGenTest iqgentest;
}
