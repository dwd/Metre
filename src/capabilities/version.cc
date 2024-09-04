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
                auto response = std::make_unique<Iq>(iq.to(), iq.from(), Iq::Type::RESULT, iq.id());

                auto query = response->node()->append_element({"jabber:iq:version", "query"});
                query->append_element("name", "Metre");
                query->append_element("version", "0.0.1");
                query->append_element("os", "ZX Spectrum 48K");
                m_endpoint.send(std::move(response));
                co_return;
            });
        }
    };

    DECLARE_CAPABILITY(Version, "version");
}
