#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include "router.h"
#include "config.h"
#include <memory>

using namespace Metre;
using namespace rapidxml;

namespace {
	const std::string sasl_ns = "jabber:server";

	class JabberServer : public Feature {
	public:
		JabberServer(XMLStream & s) : Feature(s) {}
		class Description : public Feature::Description<JabberServer> {
		public:
			Description() : Feature::Description<JabberServer>(sasl_ns, FEAT_POSTAUTH) {};
			virtual void offer(xml_node<> *, XMLStream &) {
				// No feature advertised.
			}
		};

		bool handle(rapidxml::xml_node<> * node) {
			xml_document<> * d = node->document();
			d->fixup<parse_default>(node, false); // Just terminate the header.
			std::string stanza = node->name();
			std::unique_ptr<Stanza> s;
			if (stanza == "message") {
				s = std::move(std::unique_ptr<Stanza>(new Message(node, m_stream)));
			} else if (stanza == "iq") {
				s = std::move(std::unique_ptr<Stanza>(new Iq(node, m_stream)));
			} else if (stanza == "presence") {
				s = std::move(std::unique_ptr<Stanza>(new Presence(node, m_stream)));
			} else {
				throw Metre::unsupported_stanza_type(stanza);
			}
			try {
				try {
					Jid const & to = s->to();
					Jid const & from = s->from();
					// Check auth state.
					if (m_stream.s2s_auth_pair(to.domain(), from.domain(), INBOUND) != XMLStream::AUTHORIZED) {
						throw Metre::not_authorized();
					}
					if (Config::config().domain(to.domain()).transport_type() == INT) {
						// For now, bounce everything.
						bool ping = false;
						if (stanza == "iq" && to.full() == to.domain()) {
							auto query = node->first_node();
							if (query) {
								std::string xmlns{query->xmlns(), query->xmlns_size()};
								if (xmlns == "urn:xmpp:ping") {
									ping = true;
								}
							}
						}
						if (ping) {
							std::string id;
							auto id_att = node->first_attribute("id");
							if (id_att && id_att->value()) id = id_att->value();
							std::unique_ptr<Stanza> pong{new Iq(to, from, Iq::RESULT, id, m_stream)};
							std::shared_ptr<Route> route = RouteTable::routeTable(to).route(from);
							route->transmit(std::move(pong));
						} else {
							throw stanza_service_unavailable();
						}
					} else {
                        std::shared_ptr<Route> route = RouteTable::routeTable(from).route(to);
						route->transmit(std::move(s));
					}
					// Lookup endpoint.
				} catch(Metre::base::xmpp_exception) {
					throw;
				} catch(Metre::base::stanza_exception) {
					throw;
				} catch(std::runtime_error & e) {
					throw Metre::stanza_undefined_condition(e.what());
				}
			} catch (Metre::base::stanza_exception const & stanza_error) {
				std::unique_ptr<Stanza> st = s->create_bounce(stanza_error, m_stream);
				std::shared_ptr<Route> route = RouteTable::routeTable(st->from()).route(st->to());
				route->transmit(std::move(st));
			}
			return true;
		}
	};

	bool declared = Feature::declare<JabberServer>(S2S);
}
