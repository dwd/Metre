#include "feature.hpp"
#include "stanza.hpp"
#include "xmppexcept.hpp"
#include "router.hpp"
#include <memory>

using namespace Metre;
using namespace rapidxml;

namespace {
	const std::string sasl_ns = "jabber:server:dialback";

	class Dialback : public Feature {
	public:
		Dialback(XMLStream & s) : Feature(s) {}
		class Description : public Feature::Description<Dialback> {
		public:
			Description() : Feature::Description<Dialback>(sasl_ns, FEAT_AUTH) {};
			virtual void offer(xml_node<> * node, XMLStream &) {
				xml_document<> * d = node->document();
				auto feature = d->allocate_node(node_element, "dialback");
				feature->append_attribute(d->allocate_attribute("xmlns", "urn:xmpp:features:dialback"));
				auto errors = d->allocate_node(node_element, "errors");
				feature->append_node(errors);
				node->append_node(feature);
			}
		};

		/**
		 * Inbound handling.
		 */

		void result(rapidxml::xml_node<> * node) {
			/*
			 * This is a request to authenticate, using the current key.
			 * We can shortcut this in a number of ways, but for now, let's do it longhand.
			 */
			// Should be a key here:
			const char * key = node->value();
			if (!key || !key[0]) {
				throw Metre::unsupported_stanza_type("Missing key");
			}
			// And a from/to:
			auto from = node->first_attribute("from");
			auto to = node->first_attribute("to");
			if (!(from && to)) {
				throw Metre::unsupported_stanza_type("Missing mandatory attributes");
			}
			Jid fromjid(from->value());
			Jid tojid(to->value());
			// With syntax done, we should send the key:
			std::shared_ptr<Route> route(RouteTable::routeTable().route(Jid(from->value())));
			route->transmit(Verify(fromjid, tojid, m_stream.stream_id(), key, m_stream));
		}

		void result_valid(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		void result_invalid(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		void result_error(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		void verify(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		void verify_valid(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		void verify_invalid(rapidxml::xml_node<> * node) {
			throw std::runtime_error("Unimplemented");
		}

		bool handle(rapidxml::xml_node<> * node) {
			xml_document<> * d = node->document();
			d->fixup<parse_default>(node, true);
			std::string stanza = node->name();
			std::optional<std::string> type;
			if (auto type_str = node->first_attribute("type")) {
				type.emplace(type_str->value());
			}
			if (stanza == "result") {
				if (type) {
					if (*type == "valid") {
						result_valid(node);
					} else if(*type == "invalid") {
						result_invalid(node);
					} else if(*type == "error") {
						result_error(node);
					} else {
						throw Metre::unsupported_stanza_type("Unknown type attribute to db:result");
					}
				} else {
					result(node);
				}
			} else if (stanza == "verify") {
				if (type) {
					if (*type == "valid") {
						verify_valid(node);
					} else if (*type == "invalid") {
						verify_invalid(node);
					} else {
						throw Metre::unsupported_stanza_type("Unknown type attribute to db:verify");
					}
				} else {
					verify(node);
				}
			}  else {
				throw Metre::unsupported_stanza_type("Unknown dialback element");
			}
			return true;
		}
	};

	bool declared = Feature::declare<Dialback>(S2S);
}
