#include "netsession.hpp"
#include "xmlstream.hpp"

#include "rapidxml_print.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

using namespace Metre;

NetSession::NetSession(int fd, SESSION_TYPE type, Server * server)
	: m_fd(fd), m_xml_stream(new XMLStream(this, server, INBOUND, type)), m_server(server) {}

NetSession::NetSession(std::string const & domain, Server * server)
	: m_fd(-1), m_xml_stream(new XMLStream(this, server, OUTBOUND, S2S)), m_server(server) {}

bool NetSession::drain() {
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
	if (!m_xml_stream->closed()) {
		m_xml_stream->process(m_buf);
	}
	return m_fd >= 0;
}
bool NetSession::need_push() {
	return !m_outbuf.empty();
}
bool NetSession::push() {
	auto remain = m_outbuf.length();
	std::size_t ptr = 0;
	while (remain > 0) {
		auto count = ::write(m_fd, &m_outbuf[ptr], remain);
		std::cout << "Writing buffer: <<" << m_outbuf << ">> " << m_fd << std::endl;
		if (count < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				break;
			} else {
				std::cout << "::write() returned " << strerror(errno) << std::endl;
				// Some more serious error.
				::close(m_fd);
				m_fd = -1;
				break;
			}
		} else if (count == 0) {
			std::cout << "::write() Zreturned " << strerror(errno) << std::endl;
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
		if (m_xml_stream->closed()) {
			::shutdown(m_fd, SHUT_WR);
		}
	} else {
		m_outbuf.erase(0, ptr);
	}
	return m_fd >= 0 && remain;
}

void NetSession::send(rapidxml::xml_document<> & d) {
	rapidxml::print(std::back_inserter(m_outbuf), d, rapidxml::print_no_indenting);
}
void NetSession::send(std::string const & s) {
	m_outbuf += s;
}
void NetSession::send(const char * p) {
	m_outbuf += p;
}

/**
 * Connection/lookup
 */

void NetSession::new_srv(std::string const & domain, short prio, short weight, short port, std::string const & hostname, bool secure) {
	assert(m_domain == domain);
	if (m_fd >= 0) {
		return;
	}
	// Crappy: Just consider the last one.
	m_port = port;
	m_hostname = hostname;
	m_secure = true;
}

void NetSession::srv_done() {
	// Connect to the last one.
	/// Router::lookup_address(m_hostname, this);
}

void NetSession::new_addr(std::string const & hostname, void * addr) {
	if (m_hostname != hostname) {
		return;
	}
	/// m_fd = Router::connect(this, addr, m_port);
}
