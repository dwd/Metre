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

NetSession::NetSession(int fd, SESSION_DIRECTION dir, SESSION_TYPE type, Server * server)
	: m_fd(fd), m_xml_stream(new XMLStream(this, server, dir, type)), m_server(server) {}

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
