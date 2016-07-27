#include "stanza.h"
#include "xmlstream.h"
#include "rapidxml_print.hpp"

using namespace Metre;

Stanza::Stanza(const char * name, rapidxml::xml_node<> const * node, XMLStream & s) : m_name(name), m_stream_id(s.stream_id()), m_payload{nullptr}, m_payload_l{0}  {
  auto to = node->first_attribute("to");
  if (to) m_to = Jid(to->value());
  auto from = node->first_attribute("from");
  if (from) m_from = Jid(from->value());
  auto typestr = node->first_attribute("type");
  if (typestr) m_type_str = typestr->value();
  auto id = node->first_attribute("id");
  if (id) m_id = id->value();
  m_payload = node->contents();
  m_payload_l = node->contents_size();
}
Stanza::Stanza(const char * name, XMLStream & s) : m_name(name), m_stream_id(s.stream_id()), m_payload_str(), m_payload{nullptr}, m_payload_l{0} {
}
Stanza::Stanza(const char * name, Jid const & from, Jid const & to, std::string const & type_str, std::string const & id, XMLStream & s) : m_name(name), m_stream_id(s.stream_id()), m_from(from), m_to(to), m_type_str(type_str), m_id(id), m_payload{nullptr}, m_payload_l{0} {
}

void Stanza::render(rapidxml::xml_document<> & d) {
  auto hdr = d.allocate_node(rapidxml::node_element, m_name);
  if (m_to) {
    auto att = d.allocate_attribute("to", m_to->full().c_str());
    hdr->append_attribute(att);
  }
  if (m_from) {
    auto att = d.allocate_attribute("from", m_from->full().c_str());
    hdr->append_attribute(att);
  }
  if (!m_type_str.empty()) {
    auto att = d.allocate_attribute("type", m_type_str.c_str());
    hdr->append_attribute(att);
  }
  if (!m_id.empty()) {
    auto att = d.allocate_attribute("id", m_id.c_str());
    hdr->append_attribute(att);
  }
  if (m_payload && m_payload_l) {
    auto lit = d.allocate_node(rapidxml::node_literal);
    lit->value(m_payload, m_payload_l);
    hdr->append_node(lit);
  }
  d.append_node(hdr);
}

std::unique_ptr<Stanza> Stanza::create_bounce(base::stanza_exception const & ex, XMLStream & s) {
  std::unique_ptr<Stanza> stanza{new Stanza(m_name, s)};
  stanza->m_from = m_to;
  stanza->m_to = m_from;
  stanza->m_id = m_id;
  stanza->m_type_str = "error";
  // Render the error
  rapidxml::xml_document<> d;
  auto error = d.allocate_node(rapidxml::node_element, "error");
  error->append_attribute(d.allocate_attribute("type", ex.error_type()));
  d.append_node(error);
  auto condition = d.allocate_node(rapidxml::node_element, ex.element_name());
  condition->append_attribute(d.allocate_attribute("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"));
  error->append_node(condition);
  auto text = d.allocate_node(rapidxml::node_element, "text");
  text->append_attribute(d.allocate_attribute("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"));
  text->value(ex.what());
  error->append_node(text);
  rapidxml::print(std::back_inserter(stanza->m_payload_str), d, rapidxml::print_no_indenting);
  if (m_payload && m_payload_l) {
    stanza->m_payload_str.append(m_payload, m_payload_l);
    stanza->m_payload = stanza->m_payload_str.c_str();
    stanza->m_payload_l = stanza->m_payload_str.length();
  }
  return stanza;
}

std::unique_ptr<Stanza> Stanza::create_forward(XMLStream & s) {
  std::unique_ptr<Stanza> stanza{new Stanza(m_name, s)};
  stanza->m_from = m_from;
  stanza->m_to = m_to;
  stanza->m_id = m_id;
  stanza->m_type_str = m_type_str;
  if (m_payload && m_payload_l) {
    stanza->m_payload_str.append(m_payload, m_payload_l);
    stanza->m_payload = stanza->m_payload_str.c_str();
    stanza->m_payload_l = stanza->m_payload_str.length();
  }
  return stanza;
}

Iq::Iq(Jid const & from, Jid const & to, Type t, std::string const & id, XMLStream & s) : Stanza("iq", from, to, Iq::type_toString(t), id, s) {}

const char * Iq::name = "iq";
const char * Message::name = "message";
const char * Presence::name = "presence";
const char * Verify::name = "db:verify";
