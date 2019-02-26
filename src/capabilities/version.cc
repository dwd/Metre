//
// Created by dwd on 11/05/17.
//

#include <capability.h>
#include <router.h>

using namespace Metre;

namespace {
    class Version : public Capability {
    public:
        class Description : public Capability::Description<Version> {
        public:
            explicit Description(std::string const &name) : Capability::Description<Version>(name) {
                m_disco.emplace_back("jabber:iq:version");
            }
        };

        Version(BaseDescription const &descr, Endpoint &jid) : Capability(descr, jid) {
            jid.add_handler("jabber:iq:version", "query", [this](Iq const & iq) -> sigslot::tasklet<void> {
                std::unique_ptr<Stanza> response{new Iq(iq.to(), iq.from(), Iq::RESULT, iq.id())};
                rapidxml::xml_document<>  doc;
                auto query = doc.allocate_node(rapidxml::node_element, "query");
                query->append_attribute(doc.allocate_attribute("xmlns", "jabber:iq:version"));
                auto name = doc.allocate_node(rapidxml::node_element, "name");
                name->value(doc.allocate_string("Metre"));
                query->append_node(name);
                auto version = doc.allocate_node(rapidxml::node_element, "version");
                version->value(doc.allocate_string("0.0.1"));
                query->append_node(version);
                auto os = doc.allocate_node(rapidxml::node_element, "os");
                os->value(doc.allocate_string("ZX Spectrum 48K"));
                query->append_node(os);
                response->payload(query);
                m_endpoint.send(std::move(response));
                co_return;
            });
        }
    };

    DECLARE_CAPABILITY(Version, "version");
}