#include "netsession.hpp"
#include "xmlstream.hpp"
#include "router.hpp"

#include "rapidxml_print.hpp"

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

using namespace Metre;

NetSession::NetSession(long long unsigned serial, struct bufferevent * bev, SESSION_TYPE type, Server * server)
	: m_serial(serial), m_bev(bev), m_xml_stream(new XMLStream(this, server, INBOUND, type)), m_server(server) {
		bufferevent_setcb(bev, NetSession::read_cb, NULL, NetSession::error_cb, this);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
}

NetSession::NetSession(long long unsigned serial, std::string const & domain, Server * server)
	: m_serial(serial), m_bev(nullptr), m_xml_stream(new XMLStream(this, server, OUTBOUND, S2S)), m_server(server) {}

NetSession::~NetSession() {
	bufferevent_free(m_bev);
}

bool NetSession::drain() {
	// While there is data, see how much we can consume with the XMLStream.
	struct evbuffer * buf = bufferevent_get_input(m_bev); // TODO
	size_t len;
	while ((len = evbuffer_get_contiguous_space(buf)) > 0) {
		if (!m_xml_stream->closed()) {
			size_t used = m_xml_stream->process(evbuffer_pullup(buf, len), len);
			if (used == 0) {
				break;
			}
			evbuffer_drain(buf, used);
		}
	}
	// If we can't consume it all, try pullup(), then return.
	if ((len = evbuffer_get_length(buf)) > 0) {
		if (!m_xml_stream->closed()) {
			size_t used = m_xml_stream->process(evbuffer_pullup(buf, -1), len);
			if (used != 0) {
				evbuffer_drain(buf, used);
			}
		}
	}
	return m_xml_stream->closed() && (evbuffer_get_length(buf) == 0);
}

void NetSession::send(rapidxml::xml_document<> & d) {
	std::string tmp;
	rapidxml::print(std::back_inserter(tmp), d, rapidxml::print_no_indenting);
	struct evbuffer * buf = bufferevent_get_output(m_bev);
	evbuffer_add(buf, tmp.data(), tmp.length()); // Crappy and inefficient; we want to generate a char *, write directly to it, and dump it into an iovec.
}
void NetSession::send(std::string const & s) {
	struct evbuffer * buf = bufferevent_get_output(m_bev);
	evbuffer_add(buf, s.data(), s.length());
}
void NetSession::send(const char * p) {
	struct evbuffer * buf = bufferevent_get_output(m_bev);
	evbuffer_add(buf, p, std::strlen(p));
}

void NetSession::read_cb(bufferevent *, void * arg) {
	NetSession & ns = *reinterpret_cast<NetSession *>(arg);
	if (ns.drain()) Router::session_closed(ns);
}

void NetSession::error_cb(bufferevent *, short, void * arg) {
	NetSession & ns = *reinterpret_cast<NetSession *>(arg);
	Router::session_closed(ns);
}
