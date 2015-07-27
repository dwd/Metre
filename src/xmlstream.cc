#include "rapidxml.hpp"
#include "xmlstream.h"
#include "xmppexcept.h"
#include "server.h"
#include "netsession.h"
#include "feature.h"
#include "filter.h"
#include "router.h"
#include "config.h"
#include "log.h"

#ifdef VALGRIND
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(ptr,len) 0
#endif

using namespace Metre;

XMLStream::XMLStream(NetSession * n, Server * s, SESSION_DIRECTION dir, SESSION_TYPE t)
	: m_session(n), m_server(s), m_dir(dir), m_type(t), m_closed(false), m_secured(false), m_authready(false), m_compressed(false) {
}

XMLStream::XMLStream(NetSession * n, Server * s, SESSION_DIRECTION dir, SESSION_TYPE t, std::string const & stream_local, std::string const & stream_remote)
	: m_session(n), m_server(s), m_dir(dir), m_type(t), m_stream_local(stream_local), m_stream_remote(stream_remote), m_closed(false), m_secured(false), m_authready(false), m_compressed(false) {
}

size_t XMLStream::process(unsigned char * p, size_t len) {
	using namespace rapidxml;
	if (len == 0) return 0;
	VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(p, len);
	size_t spaces = 0;
	for (unsigned char * sp{p}; len != 0; ++sp, --len, ++spaces) {
		switch (*sp) {
		default:
			break;
		case ' ':
		case '\r':
		case '\n':
			continue;
		}
		break;
	}
	if (len == 0) return 0;
	std::string buf{reinterpret_cast<char *>(p + spaces), len};
	METRE_LOG("Got [" << len << "] : " << buf);
	try {
		try {
			if (m_stream_buf.empty()) {
				/**
				 * We need to grab the stream open. Do so by parsing the main buffer to find where the open
				 * finishes, and copy that segment over to another buffer. Then reparse, this time properly.
				 */
				char * end = m_stream.parse<parse_open_only|parse_fastest>(const_cast<char *>(buf.c_str()));
				auto test = m_stream.first_node();
				if (test && test->name()) {
					m_stream_buf.assign(buf.data(), end - buf.data());
					m_session->used(end - buf.data());
					buf.erase(0, end - buf.data());
					m_stream.parse<parse_open_only>(const_cast<char *>(m_stream_buf.c_str()));
					stream_open();
					auto stream_open = m_stream.first_node();
					METRE_LOG("Stream open with {" << stream_open->xmlns() << "}" << stream_open->name());
				} else {
					m_stream_buf.clear();
				}
			}
			while(!buf.empty()) {
				char * end = m_stanza.parse<parse_fastest|parse_parse_one>(const_cast<char *>(buf.c_str()), m_stream);
				auto element = m_stanza.first_node();
				if (!element || !element->name()) return len - buf.length();
				//std::cout << "TLE {" << element->xmlns() << "}" << element->name() << std::endl;
				m_session->used(end - buf.data());
				handle(element);
				buf.erase(0, end - buf.data());
				m_stanza.clear();
			}
		} catch(Metre::base::xmpp_exception) {
			throw;
		} catch(rapidxml::eof_error & e) {
			return spaces + len - buf.length();
		} catch(std::runtime_error & e) {
			throw Metre::undefined_condition(e.what());
		}
	} catch(Metre::base::xmpp_exception & e) {
		METRE_LOG("Raising error: " << e.what());
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
	return spaces + len - buf.length();
}


const char * XMLStream::content_namespace() const {
	const char * p;
	switch (m_type) {
	case C2S:
		p = "jabber:client";
		break;
	case COMP:
		p = "jabber:component:accept";
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
			METRE_LOG("C2S stream detected.");
			m_type = C2S;
		} else if (default_xmlns == "jabber:server") {
			METRE_LOG("S2S stream detected.");
			m_type = S2S;
		} else if (default_xmlns == "jabber:component:accept") {
			METRE_LOG("114 stream detected.");
			m_type = COMP;
		} else {
			METRE_LOG("Unidentified connection.");
		}
	}
	auto domainat = stream->first_attribute("to");
	std::string domainname;
	if (domainat && domainat->value()) {
		domainname.assign(domainat->value(), domainat->value_size());
		METRE_LOG("Requested contact domain {" << domainname << "}");
	} else {
		domainname = Config::config().default_domain();
	}
	std::string from;
	if (auto fromat = stream->first_attribute("from")) {
		from.assign(fromat->value(), fromat->value_size());
	}
	METRE_LOG("Requesting domain is " << from);
	Config::Domain const & domain = Config::config().domain(domainname);
	if (domain.block()) {
		throw Metre::host_unknown("Requested domain is blocked.");
	}
	if (m_type == COMP && domain.transport_type() != COMP) {
		throw Metre::host_unknown("That would be me.");
	}
	Config::Domain const & from_domain = Config::config().domain(from);
	if (!from.empty()) {
		if (from_domain.block()) {
			throw Metre::host_unknown("Requesting domain is blocked");
		}
		if (from_domain.forward() != domain.forward()) {
			throw Metre::host_unknown("Will not forward between those domains");
		}
		if (from_domain.transport_type() == COMP) {
			if (m_type != COMP) {
				throw Metre::host_unknown("Seems unlikely.");
			}
		}
	}
	if (!stream->xmlns()) {
		throw Metre::bad_format("Missing namespace for stream");
	}
	if (stream->name() != std::string("stream") ||
		stream->xmlns() != std::string("http://etherx.jabber.org/streams")) {
		throw Metre::bad_namespace_prefix("Need a stream open");
	}
	// Assume we're good here.
	auto version = stream->first_attribute("version");
	std::string ver = "1.0";
	bool with_ver = false;
	if (version &&
			version->value() &&
			version->value_size() == 3 &&
			ver.compare(0, 3, version->value(), version->value_size()) == 0) {
		with_ver = true;
	}
	if (m_dir == INBOUND) {
		m_stream_local = domainname;
		m_stream_remote = from;
		if (m_stream_remote == m_stream_local) {
			throw std::runtime_error("That's me, you fool");
		}
		send_stream_open(with_ver, true);
		if (with_ver) {
			rapidxml::xml_document<> doc;
			auto features = doc.allocate_node(rapidxml::node_element, "stream:features");
			doc.append_node(features);
			for (auto f : Feature::features(m_type)) {
				f->offer(features, *this);
			}
			m_session->send(doc);
		}
	} else if (m_dir == OUTBOUND) {
		return;
		auto so = m_stream.first_node();
		auto dbatt = so->first_attribute("xmlns:db");
		if (dbatt && dbatt->value() == std::string("jabber:server:dialback")) {
			std::string feature_xmlns = "urn:xmpp:features:dialback";
			Feature * f = Feature::feature(feature_xmlns, *this);
			assert(f);
			f->negotiate(nullptr);
			m_features[feature_xmlns] = f;
		}
	}
}

void XMLStream::send_stream_open(bool with_version, bool with_id) {
	/*
	*   We write this out as a string, to avoid trying to make rapidxml
	* write out only the open tag.
	*/
	m_session->send("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='");
	m_session->send(content_namespace());
	if (m_type == S2S) {
		m_session->send("' xmlns:db='jabber:server:dialback");
		if (m_stream_remote != "") {
			m_session->send("' to='");
			m_session->send(m_stream_remote);
		}
	}
	m_session->send("' from='");
	m_session->send(m_stream_local);
	if (with_id) {
		m_session->send("' id='");
		generate_stream_id();
		m_session->send(m_stream_id);
	}
	if (with_version) {
		m_session->send("' version='1.0'>");
	} else {
		m_session->send("'>");
	}
	m_opened = true;
}

void XMLStream::send(rapidxml::xml_document<> & d) {
	m_session->send(d);
}

void XMLStream::send(std::unique_ptr<Stanza> s) {
	rapidxml::xml_document<> d;
	s->render(d);
	m_session->send(d);
}

void XMLStream::handle(rapidxml::xml_node<> * element) {
	if (element->prefix() && element->prefix()[0] == '/') {
		// Odd case; it's a closing stream tag. Probably. Actually any closing tag will do this.
		m_session->send("</stream:stream>");
		m_session->close();
		m_closed = true;
		return;
	}
	std::string xmlns(element->xmlns(), element->xmlns_size());
	if (xmlns == "http://etherx.jabber.org/streams") {
		std::string elname(element->name(), element->name_size());
		if (elname == "features") {
			METRE_LOG("It's features!");
			for(;;) {
				rapidxml::xml_node<> * feature_offer = nullptr;
				Feature::Type feature_type = Feature::Type::FEAT_NONE;
				std::string feature_xmlns;
				for (auto feat_ad = element->first_node(); feat_ad; feat_ad = feat_ad->next_sibling()) {
					std::string offer_name(feat_ad->name(), feat_ad->name_size());
					std::string offer_ns(feat_ad->xmlns(), feat_ad->xmlns_size());
					METRE_LOG("Got feature offer: {" << offer_ns << "}" << offer_name);
					if (m_features.find(offer_ns) != m_features.end()) continue; // Already negotiated.
					Feature::Type offer_type = Feature::type(offer_ns, *this);
					METRE_LOG("Offer type seems to be " << offer_type);
					switch(offer_type) {
					case Feature::Type::FEAT_NONE:
						continue;
					case Feature::Type::FEAT_SECURE:
						if (m_secured) continue;
					case Feature::Type::FEAT_COMP:
						if (m_compressed) continue;
					}
					if (feature_type < offer_type) {
						METRE_LOG("I'll keep {" << offer_ns << "} instead of {" << feature_xmlns << "}");
						feature_offer = feat_ad;
						feature_xmlns = offer_ns;
						feature_type = offer_type;
					}
				}
				if (feature_type == Feature::Type::FEAT_NONE) {
					if (m_features.find("urn:xmpp:features:dialback") == m_features.end()) {
						auto so = m_stream.first_node();
						auto dbatt = so->first_attribute("xmlns:db");
						if (dbatt && dbatt->value() == std::string("jabber:server:dialback")) {
							feature_xmlns = "urn:xmpp:features:dialback";
						} else {
							return;
						}
					} else {
						return;
					}
				}
				Feature * f = Feature::feature(feature_xmlns, *this);
				assert(f);
				try {
					bool escape = f->negotiate(feature_offer);
					m_features[feature_xmlns] = f;
					if (escape) return; // We've done a stream restart or something.
				} catch(...) {
					delete f;
				}
			}
		} else if (elname == "error") {
			METRE_LOG("It's a stream error!");
			throw std::runtime_error("Actually, I have a bag of shite for error handling.");
		} else {
			METRE_LOG("It's something weird.");
			throw Metre::unsupported_stanza_type("Unknown stream element");
		}
	} else {
		auto fit = m_features.find(xmlns);
		Feature * f = 0;
		METRE_LOG("Hunting handling feature for {" << xmlns << "}");
		if (fit != m_features.end()) {
			f = (*fit).second;
		} else {
			f = Feature::feature(xmlns, *this);
			if (f) m_features[xmlns] = f;
		}

		bool handled = false;
		if (f) {
			handled = f->handle(element);
		}
		if (!handled) {
			throw Metre::unsupported_stanza_type();
		}
	}
}

void XMLStream::restart() {
	if (!m_stream_id.empty()) {
		Router::unregister_stream_id(m_stream_id);
		m_stream_id.clear();
	}
	for (auto f : m_features) {
		delete f.second;
	}
	m_features.clear();
	m_stream.clear();
	m_stanza.clear();
	m_stream_buf.clear();
	if (m_dir == OUTBOUND) {
		send_stream_open(true, false);
	}
}

XMLStream::~XMLStream() {
	for (auto f : m_features) {
		delete f.second;
	}
}

void XMLStream::generate_stream_id() {
	if (!m_stream_id.empty()) {
		Router::unregister_stream_id(m_stream_id);
	}
	m_stream_id = Config::config().random_identifier();
	Router::register_stream_id(m_stream_id, *m_session);
}

XMLStream::AUTH_STATE XMLStream::s2s_auth_pair(std::string const & local, std::string const & remote, SESSION_DIRECTION dir) const {
	if (m_type == COMP) {
		if (m_user) {
			if (dir == OUTBOUND && *m_user == remote) {
				return AUTHORIZED;
			} else if (dir == INBOUND && *m_user == remote) {
				return AUTHORIZED;
			}
		}
	}
	auto & m = (dir == INBOUND ? m_auth_pairs_rx : m_auth_pairs_tx);
	auto it = m.find(std::make_pair(local,remote));
	if (it != m.end()) {
		return (*it).second;
	}
	return NONE;
}

XMLStream::AUTH_STATE XMLStream::s2s_auth_pair(std::string const & local, std::string const & remote, SESSION_DIRECTION dir, XMLStream::AUTH_STATE state) {
	auto & m = (dir == INBOUND ? m_auth_pairs_rx : m_auth_pairs_tx);
	auto key = std::make_pair(local, remote);
	AUTH_STATE current = m[key];
	if (current < state) {
		m[key] = state;
		onAuthenticated.emit(*this);
	}
	return m[key];
}

bool XMLStream::filter(Stanza & s) {
	rapidxml::xml_node<> const * node = s.node();
	if (!node) {
		// Synthetic Stanza. Probably a bounce, or similar.
		return false;
	}
	std::set<std::string> xmlnses;
	// For each child element::
	for (auto child = node->first_node(); child; child = child->next_sibling()) {
		// If the namespace is the content namespace, use the empty string in lieu of the namespace.
		std::string xmlns;
		auto xmlns_v = child->xmlns();
		if (xmlns_v) {
			xmlns.assign(xmlns_v, child->xmlns_size());
			if (xmlns == content_namespace()) {
				xmlns = "";
			}
		}
		xmlnses.insert(std::move(xmlns));
	}
	for (auto const & xmlns : xmlnses) {
		// Then look to see if we have an active Filter for that element.
		auto i = m_filters.lower_bound(xmlns);
		// If we do not, check the Filter::Descriptions for one to create.
		if (i == m_filters.end() || (*i).first != xmlns) {
			Filter::instantiate(xmlns, *this);
			i = m_filters.lower_bound(xmlns);
		}
		auto i2 = m_filters.upper_bound(xmlns);
		// If we (now) do, for each matching Filter::
		for (; i != i2; ++i) {
			// pass the stanza to it. If it returns true, exit true. (It may also throw).
			if ((*i).second) {
				if ((*i).second->apply(true, s)) return true;
			}
		}
	}
	// If the stanza if a Message or Iq(non-result), and is now empty, we should bounce.
	return false;
}
