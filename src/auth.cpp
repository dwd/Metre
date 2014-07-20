#include "feature.hpp"
#include "xmppexcept.hpp"
#include <iostream>

using namespace Metre;
using namespace rapidxml;

namespace {
	const std::string sasl_ns = "urn:ietf:params:xml:ns:xmpp-sasl";

	class Auth : public Feature {
	public:
		Auth(XMLStream & s) : Feature(s) {}
		class Description : public Feature::Description<Auth> {
		public:
			Description() : Feature::Description<Auth>(sasl_ns, FEAT_AUTH) {};
			virtual void offer(xml_node<> * node, XMLStream & s) {
				if (s.user()) {
					return;
				}
				xml_document<> * d = node->document();
				auto feature = d->allocate_node(node_element, "mechanisms");
				feature->append_attribute(d->allocate_attribute("xmlns", sasl_ns.c_str()));
				for (auto mech_name : {"PLAIN", "X-VIOLENT_BANANA"}) {
					auto mechanism = d->allocate_node(node_element, "mechanism", mech_name);
					feature->append_node(mechanism);
				}
				node->append_node(feature);
			}
		};

		bool handle(xml_node<> * node) {
			if (m_stream.user()) {
				throw Metre::not_authorized("It's best if you don't login twice");
			}
			std::cout << "Auth is handling something." << std::endl;
			xml_document<> * d = node->document();
			d->fixup<parse_default>(node, true); // Easier if we terminate it.
			std::cout << "Element is {" << node->xmlns() << "}" << node->name() << std::endl;
			if (node->name() == std::string("auth")) {
				auto attr = node->first_attribute("mechanism");
				std::cout << "Mechanism is '" << attr->value() << "'" << std::endl;
				if (attr->value() == std::string("PLAIN")) {
					std::cout << "Sending success." << std::endl;
					xml_document<> res;
					auto success = res.allocate_node(node_element, "success");
					success->append_attribute(res.allocate_attribute("xmlns", sasl_ns.c_str()));
					res.append_node(success);
					m_stream.send(res);
					m_stream.user("someone@domain.com");
					m_stream.restart();
					return true;
				}
			}
		}
	};

	bool declared = Feature::declare<Auth>(C2S);
}
