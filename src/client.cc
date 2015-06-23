#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include <memory>

using namespace Metre;
using namespace rapidxml;

namespace {
	const std::string sasl_ns = "jabber:client";

	class Client : public Feature {
	public:
		Client(XMLStream & s) : Feature(s) {}
		class Description : public Feature::Description<Client> {
		public:
			Description() : Feature::Description<Client>(sasl_ns, FEAT_POSTAUTH) {};
			virtual void offer(xml_node<> *, XMLStream &) {
				// No feature advertised.
			}
		};

		bool handle(rapidxml::xml_node<> * node) {
			if (!m_stream.user()) {
				throw Metre::not_authorized();
			}
			xml_document<> * d = node->document();
			d->fixup<parse_default>(node, false); // Just terminate the header.
			std::string stanza = node->name();
			std::shared_ptr<Stanza> s;
			if (stanza == "message") {
				s = std::shared_ptr<Stanza>(new Message(node, m_stream));
			} else if (stanza == "iq") {
				s = std::shared_ptr<Stanza>(new Iq(node, m_stream));
			} else if (stanza == "presence") {
				s = std::shared_ptr<Stanza>(new Presence(node, m_stream));
			} else {
				throw Metre::unsupported_stanza_type(stanza);
			}
			Jid const & to = s->to();
			// Lookup endpoint.
			return true;
		}
	};

	bool declared = Feature::declare<Client>(C2S);
}
