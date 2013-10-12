#include <zmq.hpp>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include "rapidxml.hpp"
#include <optional> // Uses the supplied optional by default.
#include "jid.hpp"
#include "xmppexcept.hpp"
#include "rapidxml_print.hpp"

using namespace elq;

typedef enum {
	C2S,
	S2S,
	COMP
} SESSION_TYPE;

typedef enum {
	INBOUND,
	OUTBOUND
} SESSION_DIRECTION;

class Stanza {
	std::optional<Jid> m_from;
	std::optional<Jid> m_to;
	std::string m_type_str;
	std::string m_lang;
	char * m_payload;
	size_t m_payload_l;
public:
	Stanza(rapidxml::xml_node<> const & node) {
	}
};


class Message : public Stanza {
public:
	Message(rapidxml::xml_node<> const & node) : Stanza(node) {
	}
};


class Iq : public Stanza {
public:
	Iq(rapidxml::xml_node<> const & node) : Stanza(node) {
	}
};


class Presence : public Stanza {
public:
	Presence(rapidxml::xml_node<> const & node) : Stanza(node) {
	}
};


class Endpoint {
	Jid m_jid;
public:
	Endpoint(Jid const & jid) : m_jid(jid) {}
	virtual void push(Message &);
	virtual void push(Iq &);
	virtual void push(Presence &);
};


class Account {
	Jid m_jid;
public:
	Account(Jid const & jid) : m_jid(jid) {}
	bool test_password(std::string const & password) {
		return password == "yes"; // TODO : Maybe make this more secure? //
	}
};


class Domain {
	std::string m_domain;
	std::map<std::string, Account *> m_accounts;
public:
	Domain(std::string const & domain) : m_domain(domain) {}
	Account & account(Jid const & jid) {
		auto acciter = m_accounts.find(jid.bare());
		if (acciter != m_accounts.end()) {
			return *acciter->second;
		}
		if (jid.bare() != "dave@jekyll.dave.cridland.net") {
			throw std::runtime_error("No such account");
		}
		auto acc = m_accounts[jid.bare()] = new Account(jid);
		return *acc;
	}
	std::string domain() const {
		return m_domain;
	}
};


class Server {
	std::map<std::string, Domain *> m_domains;
public:
	Server() {}
	Domain & domain(std::string const & domain) {
		auto domiter = m_domains.find(domain);
		if (domiter != m_domains.end()) {
			return *domiter->second;
		}
		if (domain != "jekyll.dave.cridland.net") {
			throw std::runtime_error("No such domain");
		}
		auto dom = m_domains[domain] = new Domain(domain);
		return *dom;
	}
};


class NetSession {
	std::string m_buf;
	int m_fd;
	static const size_t buflen = 4096;
	std::string m_outbuf;
	bool m_closed;
	SESSION_TYPE m_default_type;
public:
	NetSession(int fd, SESSION_TYPE type, Server * server) : m_fd(fd), m_type(type), m_server(server), m_opened(false), m_closed(false) {}
	bool drain() {
		// This is a phenomenally cool way of reading data from a socket to
		// a std::string. Extend string, read direct to buffer, resize string to
		// read-length.
		// Downside is that when std::string extends, we might cause an alloc,
		// but this should - I think - be rare.
		while (true) {
			auto oldsz = m_buf.length();
			m_buf.resize(oldsz + buflen);
			auto count = ::read(m_fd, &m_buf[oldsz], buflen);
			std::cout << "::read() returned " << count << std::endl;
			if (count < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					m_buf.resize(oldsz);
					break;
				} else {
					std::cout << "::read() returned " << strerror(errno) << std::endl;
					// Some more serious error.
					::close(m_fd);
					m_fd = -1;
					m_buf.resize(oldsz);
					break;
				}
			} else if (count == 0) {
				::close(m_fd);
				m_fd = -1;
				m_buf.resize(oldsz);
				break;
			} else {
				m_buf.resize(oldsz + count);
			}
		}
		std::cout << "Drained buffer, now: <<" << m_buf << ">> " << m_fd << std::endl;
		if (!m_closed) {
			process();
		}
		return m_fd >= 0;
	}
	bool need_push() {
		return !m_outbuf.empty();
	}
	bool push() {
		auto remain = m_outbuf.length();
		std::size_t ptr = 0;
		while (true) {
			auto count = ::write(m_fd, &m_outbuf[ptr], remain);
			if (count < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					break;
				} else {
					// Some more serious error.
					::close(m_fd);
					m_fd = -1;
					break;
				}
			} else if (count == 0) {
				::close(m_fd);
				m_fd = -1;
				break;
			} else {
				ptr += count;
				remain -= count;
			}			
		}
		if (remain == 0) {
			m_outbuf.erase();
			if (m_closed) {
				::shutdown(m_fd, SHUT_WR);
			}
		} else {
			m_outbuf.erase(0, ptr);
		}
		return m_fd >= 0 && remain;
	}
	
	void send(rapidxml::xml_document<> & d) {
		rapidxml::print(std::back_inserter(m_outbuf), d, rapidxml::print_no_indenting);
	}
	void send(std::string const & s) {
		m_outbuf += s;
	}
	void send(const char * p) {
		m_outbuf += p;
	}
};

class XMLStream {
	rapidxml::xml_document<> m_stream;
	rapidxml::xml_document<> m_stanza; // Not, in fact, always a stanza per-se. //
	SESSION_TYPE m_type;
	Server * m_server;
	bool m_opened;
	std::string m_stream_buf; // Sort-of-temporary buffer //
public:
	void process(std::string & buf) {
		using namespace rapidxml;
		try {
			try {
				if (buf.empty()) return;
				if (m_stream.first_node() == NULL) {
					/**
					 * We need to grab the stream open. Do so by parsing the main buffer to find where the open
					 * finishes, and copy that segment over to another buffer. Then reparse, this time properly.
					 */
					char * end = m_stream.parse<parse_open_only|parse_fastest>(const_cast<char *>(m_buf.c_str()));
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
					buf.erase(0, end - buf.data());
				}
			} catch(elq::base::xmpp_exception) {
				throw;
			} catch(std::exception & e) {
				throw elq::undefined_condition(e.what());
			} catch(...) {
				throw elq::undefined_condition();
			}
		} catch(elq::base::xmpp_exception & e) {
			xml_document<> d;
			auto error = d.allocate_node(node_element, "stream:error");
			auto specific = d.allocate_node(node_element, e.element_name());
			specific->append_attribute(d.allocate_attribute("xmlns", "urn:ietf:params:xml:ns:xmpp-streams"));
			auto text = d.allocate_node(node_element, "text", e.what());
			specific->append_node(text);
			if (dynamic_cast<elq::undefined_condition *>(&e)) {
				auto other = d.allocate_node(node_element, "unhandled-exception");
				other->append_attribute(d.allocate_attribute("xmlns", "http://cridland.im/xmlns/eloquence"));
				specific->append_node(other);
			}
			error->append_node(specific);
			if (m_opened) {
				d.append_node(error);
				putxml(d);
				m_outbuf.append("</stream:stream>");
			} else {
				auto node = d.allocate_node(node_element, "stream:stream");
				node->append_attribute(d.allocate_attribute("xmlns:stream", "http://etherx.jabber.org/streams"));
				node->append_attribute(d.allocate_attribute("version", "1.0"));
				node->append_attribute(d.allocate_attribute("xmlns", content_namespace()));
				node->append_node(error);
				d.append_node(node);
				m_outbuf = "<?xml version='1.0'?>";
				putxml(d);
			}
			m_closed = true;
		}
	}
	
	
	const char * content_namespace() const {
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

	void stream_open() {
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
		auto domain = m_server->domain(domainname);
		if (!stream->xmlns()) {
			throw elq::bad_format("Missing namespace for stream");
		}
		if (stream->name() != std::string("stream") ||
			stream->xmlns() != std::string("http://etherx.jabber.org/streams")) {
			throw elq::bad_namespace_prefix("Need a stream open");
		}
		// Assume we're good here.
		/*
		 *   We write this out as a string, to avoid trying to make rapidxml 
		 * write out only the open tag.
		 */
		m_outbuf = "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='";
		if (m_type == C2S) {
			m_outbuf += "jabber:client' from='";
		} else {
			m_outbuf += "jabber:server' xmlns:db='jabber:server:dialback' to='";
			m_outbuf += "'from='";
		}
		m_outbuf += domain.domain() + "'";
		auto version = stream->first_attribute("version");
		std::string ver = "1.0";
		if (version->value() &&
			version->value_size() == 3 &&
			ver.compare(0, 3, version->value(), version->value_size()) == 0) {
			m_outbuf += " version='1.0'>";
			rapidxml::xml_document<> doc;
			auto features = doc.allocate_node(rapidxml::node_element, "stream:features");
			doc.append_node(features);
			auto node = doc.allocate_node(rapidxml::node_element, "dialback");
			node->append_attribute(doc.allocate_attribute("xmlns", "urn:xmpp:features:dialback"));
			features->append_node(node);
			putxml(doc);
		}
	}
};


int main(int argc, char *argv[]) {
	zmq::context_t context(1);
	auto lsock = socket(AF_INET6, SOCK_STREAM, 0);
	sockaddr_in6 sin = { AF_INET6, htons(5222), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
	if (0 > bind(lsock, (sockaddr *)&sin, sizeof(sin))) {
		std::cout << "Cannot bind!" << std::endl;
		return 1;
	}
	int opt = 1;
	setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (0 > listen(lsock, 5)) {
		std::cout << "Cannot listen!" << std::endl;
		return 2;
	}
	std::cout << "Listening." << std::endl;
	std::vector<zmq::pollitem_t> pollitems;
	zmq::pollitem_t pollitem;
	pollitem.socket = NULL;
	pollitem.fd = lsock;
	pollitem.events = ZMQ_POLLIN;
	pollitems.push_back(pollitem);
	std::map<int, NetSession *> sockets;
	Server server;
	while (true) {
		zmq::poll(&pollitems[0], pollitems.size());
		if (pollitems[0].revents & ZMQ_POLLIN) {
			auto sock = accept(pollitems[0].fd, NULL, NULL);
			int fl = O_NONBLOCK;
			fcntl(sock, F_SETFL, fl); 
			zmq::pollitem_t pollitem;
			pollitem.socket = NULL;
			pollitem.fd = sock;
			pollitem.events = ZMQ_POLLIN;
			pollitems.push_back(pollitem);
			sockets[sock] = new NetSession(sock, C2S, &server);
		}
		for (auto & pollitem : pollitems) {
			if (pollitem.fd == lsock) continue;
			std::cout << "Activity on " << pollitem.fd << std::endl;
			if (!sockets[pollitem.fd]->drain()) {
				delete sockets[pollitem.fd];
				sockets[pollitem.fd] = 0;
				pollitem.fd = -1;
				continue;
			}
			if (sockets[pollitem.fd]->need_push()) {
				sockets[pollitem.fd]->push();
			}
			if (sockets[pollitem.fd]->need_push()) {
				pollitem.events = ZMQ_POLLIN|ZMQ_POLLOUT;
			} else {
				pollitem.events = ZMQ_POLLIN;
			}
		}
		pollitems.erase(std::remove_if(pollitems.begin(), pollitems.end(), [] (zmq::pollitem_t pollitem) {
			std::cout << "Considering " << pollitem.fd << std::endl;
			return pollitem.fd < 0;
		}), pollitems.end());
	}
	return 0;
}
