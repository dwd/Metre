#include "rapidxml.hpp"
#include "xmlstream.hpp"
#include "xmppexcept.hpp"
#include "server.hpp"
#include "netsession.hpp"
#include "feature.hpp"

#include <iostream>

using namespace Metre;

XMLStream::XMLStream(NetSession * n, Server * s, SESSION_TYPE t)
	: m_session(n), m_server(s), m_type(t) {
}

void XMLStream::process(std::string & buf) {
	using namespace rapidxml;
	try {
		try {
			if (buf.empty()) return;
			if (m_stream.first_node() == NULL) {
				/**
				 * We need to grab the stream open. Do so by parsing the main buffer to find where the open
				 * finishes, and copy that segment over to another buffer. Then reparse, this time properly.
				 */
				char * end = m_stream.parse<parse_open_only|parse_fastest>(const_cast<char *>(buf.c_str()));
				auto test = m_stream.first_node();
				if (!test || !test->name()) {
					std::cout << "Cannot parse an element, yet." << std::endl;
					return;
				}
				m_stream_buf.assign(buf.data(), end - buf.data());
				buf.erase(0, end - buf.data());
				m_stream.parse<parse_open_only>(const_cast<char *>(m_stream_buf.c_str()));
				stream_open();
				auto stream_open = m_stream.first_node();
				std::cout << "Stream open with {" << stream_open->xmlns() << "}" << stream_open->name() << std::endl;
			}
			while(!buf.empty()) {
				char * end = m_stanza.parse<parse_fastest|parse_parse_one>(const_cast<char *>(buf.c_str()), m_stream);
				auto element = m_stanza.first_node();
				if (!element || !element->name()) return;
				std::cout << "TLE {" << element->xmlns() << "}" << element->name() << std::endl;
				handle(element);
				buf.erase(0, end - buf.data());
				m_stanza.clear();
			}
		} catch(Metre::base::xmpp_exception) {
			throw;
		} catch(std::exception & e) {
			throw Metre::undefined_condition(e.what());
		} catch(...) {
			throw Metre::undefined_condition();
		}
	} catch(Metre::base::xmpp_exception & e) {
		xml_document<> d;
		auto error = d.allocate_node(node_element, "stream:error");
		auto specific = d.allocate_node(node_element, e.element_name());
		specific->append_attribute(d.allocate_attribute("xmlns", "urn:ietf:params:xml:ns:xmpp-streams"));
		auto text = d.allocate_node(node_element, "text", e.what());
		specific->append_node(text);
		if (dynamic_cast<Metre::undefined_condition *>(&e)) {
			auto other = d.allocate_node(node_element, "unhandled-exception");
			other->append_attribute(d.allocate_attribute("xmlns", "http://cridland.im/xmlns/metre"));
			specific->append_node(other);
		}
		error->append_node(specific);
		if (m_opened) {
			d.append_node(error);
			m_session->send(d);
			m_session->send("</stream:stream>");
		} else {
			auto node = d.allocate_node(node_element, "stream:stream");
			node->append_attribute(d.allocate_attribute("xmlns:stream", "http://etherx.jabber.org/streams"));
			node->append_attribute(d.allocate_attribute("version", "1.0"));
			node->append_attribute(d.allocate_attribute("xmlns", content_namespace()));
			node->append_node(error);
			d.append_node(node);
			m_session->send("<?xml version='1.0'?>");
			m_session->send(d);
		}
		m_closed = true;
	}
}
	
	
const char * XMLStream::content_namespace() const {
	const char * p;
	switch (m_type) {
	case C2S:
		p = "jabber:client";
		break;
	default:
	case S2S:
		p = "jabber:server";
		break;
	}
	return p;
}

void XMLStream::stream_open() {
	/**
	 * We may be able to change our minds on what stream type this is, here,
	 * by looking at the default namespace.
	 */
	auto stream = m_stream.first_node();
	auto xmlns = stream->first_attribute("xmlns");
	if (xmlns && xmlns->value()) {
		std::string default_xmlns(xmlns->value(), xmlns->value_size());
		if (default_xmlns == "jabber:client") {
			m_type = C2S;
		} else if (default_xmlns == "jabber:server") {
			m_type = S2S;
		} else {
			std::cout << "Unidentified connection." << std::endl;
		}
	}
	auto domainat = stream->first_attribute("to");
	std::string domainname;
	if (domainat && domainat->value()) {
		domainname.assign(domainat->value(), domainat->value_size());
		std::cout << "Requested contact domain {" << domainname << "}" << std::endl;
	} else {
		domainname = "jekyll.dave.cridland.net"; // TODO : Default //
	}
	auto domain = this->m_server->domain(domainname);
	if (!stream->xmlns()) {
		throw Metre::bad_format("Missing namespace for stream");
	}
	if (stream->name() != std::string("stream") ||
		stream->xmlns() != std::string("http://etherx.jabber.org/streams")) {
		throw Metre::bad_namespace_prefix("Need a stream open");
	}
	// Assume we're good here.
	/*
	 *   We write this out as a string, to avoid trying to make rapidxml 
	 * write out only the open tag.
	 */
	m_session->send("<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='");
	if (m_type == C2S) {
		m_session->send("jabber:client' from='");
	} else {
		m_session->send("jabber:server' xmlns:db='jabber:server:dialback' to='");
		m_session->send("'from='");
	}
	m_session->send(domain.domain() + "' id='");
	m_session->send("id-goes-here");
	m_session->send("'");
	auto version = stream->first_attribute("version");
	std::string ver = "1.0";
	if (version->value() &&
		version->value_size() == 3 &&
		ver.compare(0, 3, version->value(), version->value_size()) == 0) {
		m_session->send(" version='1.0'>");
		rapidxml::xml_document<> doc;
		auto features = doc.allocate_node(rapidxml::node_element, "stream:features");
		doc.append_node(features);
		for (auto f : Feature::features(m_type)) {
			f->offer(features, *this);
		}
		m_session->send(doc);
	} else {
		m_session->send(">");
	}
	m_opened = true;
}

void XMLStream::send(rapidxml::xml_document<> & d) {
	m_session->send(d);
}

void XMLStream::handle(rapidxml::xml_node<> * element) {
	std::string xmlns(element->xmlns(), element->xmlns_size());
	auto fit = m_features.find(xmlns);
	Feature * f = 0;
	std::cout << "Hunting handling feature for {" << xmlns << "}" << std::endl;
	if (fit != m_features.end()) {
		f = (*fit).second;
	} else {
		f = Feature::feature(xmlns, *this);
		m_features[xmlns] = f;
	}
	
	bool handled = false;
	if (f) {
		handled = f->handle(element);
	}
	if (!handled) {
		throw Metre::unsupported_stanza_type();
	}
}

void XMLStream::restart() {
	for (auto f : m_features) {
		delete f.second;
	}
	m_features.clear();
	m_stream.clear();
	m_stanza.clear();
}

XMLStream::~XMLStream() {
	for (auto f : m_features) {
		delete f.second;
	}
}
