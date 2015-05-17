#include "feature.hpp"
#include "stanza.hpp"
#include "router.hpp"
#include "xmppexcept.hpp"
#include "log.h"
#include <rapidxml.hpp>
#include <openssl/sha.h>

using namespace rapidxml;
using namespace Metre;

namespace {
  const std::string sasl_ns = "jabber:component:accept";

  class Component : public Feature, public sigslot::has_slots<> {
  public:
    Component(XMLStream & s) : Feature(s) {}
    class Description : public Feature::Description<Component> {
    public:
      Description() : Feature::Description<Component>(sasl_ns, FEAT_POSTAUTH) {};
      virtual void offer(xml_node<> *, XMLStream &) {
        // No feature advertised.
      }
    };

    std::string handshake_content() const {
        std::string const key("component-secret");
        std::string concat = m_stream.stream_id() + key;
        std::string binoutput;
        binoutput.resize(20);
        SHA1(reinterpret_cast<const unsigned char *>(concat.data()), concat.length(), const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(binoutput.data())));
        std::string hexoutput;
        for (unsigned char c : binoutput) {
          int low = c & 0x0F;
          int high = (c & 0xF0) >> 4;
          hexoutput += ((high < 0x0A) ? '0' : ('a' - 10)) + high;
          hexoutput += ((low < 0x0A) ? '0' : ('a' - 10)) + low;
        }
        assert(hexoutput.length() == 40);
        return hexoutput;
    }

    void send_handshake(XMLStream & s) {
      std::string hexoutput(handshake_content());
      xml_document<> d;
      auto node = d.allocate_node(node_element, "handshake");
      node->value(hexoutput.c_str(), hexoutput.length());
      d.append_node(node);
      m_stream.send(d);
    }

    bool negotiate(rapidxml::xml_node<> *) override {
      m_stream.onAuthReady.connect(this, &Component::send_handshake);
    }

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
      } else if (stanza == "handshake") {
        std::string const handshake_offered{node->value(), node->value_size()};
        std::string const handshake_expected{handshake_content()};
        if (handshake_offered != handshake_expected) {
          METRE_LOG("RX: '" << handshake_offered << "'");
          METRE_LOG("TX: '" << handshake_expected << "'");
          throw not_authorized("Component handshake failure");
        }

        m_stream.user(m_stream.local_domain());
        Router::register_session_domain(m_stream.local_domain(), m_stream.session());
        xml_document<> d;
        auto node = d.allocate_node(node_element, "handshake");
        d.append_node(node);
        m_stream.send(d);
        return true;
      } else {
        throw Metre::unsupported_stanza_type(stanza);
      }
      try {
        try {
          Jid const & from = s->from();
          Jid const & to = s->to();
          // Check auth state.
          if (m_stream.s2s_auth_pair(to.domain(), from.domain(), INBOUND) != XMLStream::AUTHORIZED) {
            throw not_authorized();
          }
          // Forward everything.
          std::unique_ptr<Stanza> copy(s->create_forward(m_stream));
          std::shared_ptr<Route> route = RouteTable::routeTable(from).route(to);
          route->transmit(std::move(copy));
        } catch(Metre::base::xmpp_exception) {
          throw;
        } catch(Metre::base::stanza_exception) {
          throw;
        } catch(std::runtime_error & e) {
          throw Metre::stanza_undefined_condition(e.what());
        }
      } catch (Metre::base::stanza_exception const & stanza_error) {
        std::unique_ptr<Stanza> st = s->create_bounce(stanza_error, m_stream);
        std::shared_ptr<Route> route = RouteTable::routeTable(st->to()).route(st->to());
        route->transmit(std::move(st));
      }
      return true;
    }
  };

  bool declared = Feature::declare<Component>(COMP);
}
