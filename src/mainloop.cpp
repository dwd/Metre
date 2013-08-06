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

typedef enum {
	C2S,
	S2S,
	COMP
} SESSION_TYPE;

namespace std {
	template<typename T>
	class optional {
		char m_void[sizeof(T)];
		bool m_engaged;
	private:
		void doset(T const & t) {
			new(m_void) T(t);
			m_engaged = true;
		}
		T * real() {
			if (!m_engaged) throw std::runtime_error("Deref when unengaged");
			return reinterpret_cast<T *>(&m_void);
		}
		T const * real() const {
			if (!m_engaged) throw std::runtime_error("Deref when unengaged");
			return reinterpret_cast<T const *>(&m_void);
		}
	public:
		optional(T const & t) : m_engaged(false) {
			doset(t);
		}
		optional() : m_engaged(false) {
		}
		void emplace() {
			if (m_engaged) throw std::runtime_error("Emplace when engaged");
			new(m_void) T;
		}
		T & operator * () {
			return *real();
		}
		T * operator -> () {
			return real();
		}
		T & value() {
			return *real();
		}
		T const & operator * () const {
			return *real();
		}
		T const * operator -> () const {
			return real();
		}
		T const & value() const {
			return *real();
		}
		operator bool () const {
			return m_engaged;
		}
	};
}


class Jid {
	std::optional<std::string> m_local;
	std::string m_domain;
	std::optional<std::string> m_resource;
	
	mutable std::optional<std::string> m_full;
	mutable std::optional<std::string> m_bare;
public:
	Jid(std::string const & jid) {
		// TODO : Parse out //
	}
	Jid(std::string const & local, std::string const & domain)
		: m_local(local), m_domain(domain) {
	}
	std::string const & full() const {
		if (!m_full) {
			m_full.emplace();
			if (m_local) {
				*m_full += *m_local;
				*m_full += "@";
			}
			*m_full += m_domain;
			if (m_resource) {
				*m_full += "/";
				*m_full += *m_resource;
			}
		}
		return *m_full;
	}
	std::string const & bare() const {
		if (!m_bare) {
			m_bare.emplace();
			if (m_local) {
				*m_bare += *m_local;
				*m_bare += "@";
			}
			m_bare.value() += m_domain;
		}
		return *m_bare;
	}
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
	std::string m_stream_buf;
	rapidxml::xml_document<> m_stream;
	rapidxml::xml_document<> m_stanza; // Not, in fact, always a stanza per-se. //
	SESSION_TYPE m_type;
	Server * m_server;
public:
	NetSession(int fd, SESSION_TYPE type, Server * server) : m_fd(fd), m_type(type), m_server(server) {}
	void drain() {
		// This is a phenomenally cool way of reading data from a socket to
		// a std::string. Extend string, read direct to buffer, resize string to
		// read-length.
		// Downside is that when std::string extends, we might cause an alloc,
		// but this should - I think - be rare.
		while (true) {
			auto oldsz = m_buf.length();
			m_buf.resize(oldsz + buflen);
			auto count = ::read(m_fd, &m_buf[oldsz], buflen);
			if (count < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					m_buf.resize(oldsz);
					break;
				} else {
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
		std::cout << "Drained buffer, now: \n" << m_buf << "\n!!!" << std::endl;
		process();
	}
	void process() {
		using namespace rapidxml;
		if (m_buf.empty()) return;
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
			m_stream_buf.assign(m_buf.data(), end - m_buf.data());
			m_buf.erase(0, end - m_buf.data());
			m_stream.parse<parse_open_only>(const_cast<char *>(m_stream_buf.c_str()));
			stream_open();
			auto stream_open = m_stream.first_node();
			std::cout << "Stream open with {" << stream_open->xmlns() << "}" << stream_open->name() << std::endl;
		}
		while(!m_buf.empty()) {
			char * end = m_stanza.parse<parse_fastest|parse_parse_one>(const_cast<char *>(m_buf.c_str()), m_stream);
			auto element = m_stanza.first_node();
			if (!element || !element->name()) return;
			std::cout << "TLE {" << element->xmlns() << "}" << element->name() << std::endl;
			m_buf.erase(0, end - m_buf.data());
		}
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
			std::cout << "Ooops! No xmlns for stream?" << std::endl;
		}
		if (stream->name() != std::string("stream") ||
			stream->xmlns() != std::string("http://etherx.jabber.org/streams")) {
			std::cout << "Ooops! Wrong name or invalid namespace." << std::endl;
		}
	}
};

int  main(int argc, char *argv[]) {
	zmq::context_t context(1);
	auto lsock = socket(AF_INET6, SOCK_STREAM, 0);
	sockaddr_in6 sin = { AF_INET6, htons(5222), 0, { {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} }, 0 };
	if (0 < bind(lsock, (sockaddr *)&sin, sizeof(sin))) {
		std::cout << "Cannot bind!" << std::endl;
		return 1;
	}
	int opt = 1;
	setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	listen(lsock, 5);
	
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
		for (auto pollitem : pollitems) {
			if (pollitem.fd == lsock) continue;
			std::cout << "Activity on " << pollitem.fd << std::endl;
			sockets[pollitem.fd]->drain();
		}
	}
	return 0;
}
