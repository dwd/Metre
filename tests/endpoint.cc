//
// Created by dwd on 25/05/17.
//

#include "endpoint.h"
#include "tests.h"
#include <iostream>
#include <rapidxml_print.hpp>

using namespace Metre;

class EndpointTest : public Test, public sigslot::has_slots<> {
public:
    EndpointTest() : Test("Endpoint") {}

    bool stanza_seen = false;

    void check_ping_response(Stanza &stanza, Jid const &endpoint_jid, Jid const &stanza_to) {
        stanza_seen = true;
        assert::equal(stanza.id(), "5678", "Ping response id");
        assert::equal(stanza.name(), Iq::name, "IQ name for node");
        //assert::equal(stanza.to(), stanza_to, "Stanza to matches target");
        assert::equal(stanza.to().full(), std::string("dwd@dave.cridland.net/90210"), "Stanza to to right jid");
        assert::equal(stanza.type_str(), std::string("result"), "type is result");
    }

    void check_discoinfo_response(Stanza &stanza, Jid const &endpoint_jid, Jid const &stanza_to) {
        stanza_seen = true;
        assert::equal(stanza.id(), "1234", "Disco response id");
        assert::equal(stanza.name(), Iq::name, "IQ name for node");
        //assert::equal(stanza.to(), stanza_to, "Stanza to matches target");
        assert::equal(stanza.to().full(), std::string("dwd@dave.cridland.net/90210"), "Stanza to to right jid");
        assert::equal(stanza.type_str(), std::string("result"), "type is result");
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
        assert::equal(response.name(), std::string("query"), "IQ payload name is query");
        assert::equal(response.xmlns(), std::string("http://jabber.org/protocol/disco#info"),
                      "IQ payload XMLNS is right");
        std::set<std::string> m_features;
        for (auto feature = response.first_node(); feature; feature = feature->next_sibling()) {
            assert::equal(feature->type(), rapidxml::node_element, "Node is element");
            assert::equal(feature->name(), std::string("feature"), "Element is feature");
            assert::equal(feature->xmlns(), std::string("http://jabber.org/protocol/disco#info"), "XMLNS is right");
            auto var = feature->first_attribute("var");
            m_features.emplace(var->value(), var->value_size());
        }
        assert::equal(m_features.size(), 4u, "4 features advertised");
    }

    bool run() {
        {
            Endpoint &endpoint = Endpoint::endpoint(Jid("domain.example"));
            {
                // Send a ping. Should get one back.
                std::string iq_xml = "<iq from='dwd@dave.cridland.net/90210' to='domain.example' id='5678' type='get'><ping xmlns='urn:xmpp:ping'/></iq>";
                rapidxml::xml_document<> doc;
                doc.parse<rapidxml::parse_full>(const_cast<char *>(iq_xml.c_str()));
                std::unique_ptr<Stanza> stanza{new Iq(doc.first_node())};
                endpoint.sent_stanza.connect(this, &EndpointTest::check_ping_response);
                endpoint.process(*stanza);
                endpoint.sent_stanza.disconnect(this);
                if (!stanza_seen) throw std::runtime_error("No stanza response!");
                stanza_seen = false;
            }
            {
                // Send a disco#info query. Should get response with features.
                std::string iq_xml = "<iq from='dwd@dave.cridland.net/90210' to='domain.example' id='1234' type='get'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>";
                rapidxml::xml_document<> doc;
                doc.parse<rapidxml::parse_full>(const_cast<char *>(iq_xml.c_str()));
                std::unique_ptr<Stanza> stanza{new Iq(doc.first_node())};
                endpoint.sent_stanza.connect(this, &EndpointTest::check_discoinfo_response);
                endpoint.process(*stanza);
                endpoint.sent_stanza.disconnect(this);
                if (!stanza_seen) throw std::runtime_error("No stanza response!");
                stanza_seen = false;
            }
        }
        return true;
    }
};

namespace {
    EndpointTest endpointtest;
}
