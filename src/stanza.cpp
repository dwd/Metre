#include "stanza.hpp"
#include "xmlstream.hpp"

using namespace Metre;

Stanza::Stanza(rapidxml::xml_node<> const * node, XMLStream & s) : m_stream_id(s.stream_id())  {
  m_name = node->name();
  auto to = node->first_attribute("to");
}
Stanza::Stanza(const char * name, XMLStream & s) : m_name(name), m_stream_id(s.stream_id()) {
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
    hdr->value(m_payload, m_payload_l);
  }
  d.append_node(hdr);
}
