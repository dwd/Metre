/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/

#include "netsession.h"
#include "xmlstream.h"
#include "router.h"
#include "log.h"
#include "tls.h"

#include "rapidxml_print.hpp"

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <cstring>

using namespace Metre;

NetSession::NetSession(long long unsigned serial, struct bufferevent *bev, Config::Listener const *listen)
        : m_serial(serial), m_bev(nullptr), m_xml_stream(new XMLStream(this, INBOUND, listen->session_type)) {
    bufferevent(bev);
    METRE_LOG(Log::INFO, "New INBOUND session NS" << serial);
    if (listen->session_type == X2X) {
        m_xml_stream->remote_domain(listen->remote_domain);
        m_xml_stream->local_domain(listen->local_domain);
    }
    if (listen->tls_mode == IMMEDIATE) {
        start_tls(*m_xml_stream, false);
    }
}

NetSession::NetSession(long long unsigned serial, struct bufferevent *bev, std::string const &stream_from,
                       std::string const &stream_to, TLS_MODE tls_mode)
        : m_serial(serial), m_bev(nullptr), m_xml_stream(new XMLStream(this, OUTBOUND, S2S, stream_from, stream_to)) {
    bufferevent(bev);
    METRE_LOG(Log::INFO, "New OUTBOUND session NS" << serial);
    if (tls_mode == IMMEDIATE) {
        start_tls(*m_xml_stream, false);
    }
}

void NetSession::bufferevent(struct bufferevent *bev) {
    if (!bev) throw std::runtime_error("NULL BEV");
    bufferevent_setcb(bev, NetSession::read_cb, NULL, NetSession::event_cb, this);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    m_bev = bev;
}

NetSession::~NetSession() {
    if (m_bev) bufferevent_free(m_bev);
}

bool NetSession::drain() {
    // While there is data, see how much we can consume with the XMLStream.
    struct evbuffer *buf = nullptr; // This gets refreshed each time through the loops.
    size_t len;
    while ((len = evbuffer_get_contiguous_space(buf = bufferevent_get_input(m_bev))) > 0) {
        if (!m_xml_stream->closed()) {
            size_t used = m_xml_stream->process(evbuffer_pullup(buf, len), len);
            if (used == 0) {
                break;
            }
            //evbuffer_drain(buf, used);
        } else {
            break;
        }
    }
    // If we can't consume it all, try pullup(), then return.
    if ((len = evbuffer_get_length(buf = bufferevent_get_input(m_bev))) > 0) {
        if (!m_xml_stream->closed()) {
            m_xml_stream->process(evbuffer_pullup(buf, -1), len);
        } else {
            if (len > 0)
            METRE_LOG(Metre::Log::WARNING, "NS" << m_serial << " - Stuff left after close: {" << len << "}");
            return true;
        }
    }
    return m_xml_stream->closed() && (evbuffer_get_length(buf) == 0);
}

void NetSession::used(size_t n) {
    struct evbuffer *buf = bufferevent_get_input(m_bev);
    evbuffer_drain(buf, n);
}

void NetSession::send(rapidxml::xml_document<> &d) {
    std::string tmp;
    rapidxml::print(std::back_inserter(tmp), d, rapidxml::print_no_indenting);
    struct evbuffer *buf = bufferevent_get_output(m_bev);
    if (!buf) {
        return;
    }
    METRE_LOG(Metre::Log::DEBUG, "NS" << m_serial << " - Send: " << tmp);
    evbuffer_add(buf, tmp.data(),
                 tmp.length()); // Crappy and inefficient; we want to generate a char *, write directly to it, and dump it into an iovec.
}

void NetSession::send(std::string const &s) {
    struct evbuffer *buf = bufferevent_get_output(m_bev);
    METRE_LOG(Metre::Log::DEBUG, "NS" << m_serial << " - Send: " << s);
    if (!buf) {
        return;
    }
    evbuffer_add(buf, s.data(), s.length());
}

void NetSession::send(const char *p) {
    send(std::string(p));
    //struct evbuffer * buf = bufferevent_get_output(m_bev);
    //evbuffer_add(buf, p, std::strlen(p));
}

void NetSession::read() {
    if (drain()) {
        METRE_LOG(Log::INFO, "NS" << m_serial << " - Closing during read.");
        onClosed.emit(*this);
    }
}

void NetSession::read_cb(struct bufferevent *, void *arg) {
    NetSession &ns = *reinterpret_cast<NetSession *>(arg);
    METRE_LOG(Metre::Log::DEBUG, "NS" << ns.serial() << " - Read.");
    ns.read();
}

void NetSession::bev_closed() {
    // TODO : I had this here, but I think it's useless. It causes a nasty wait-free loop, though.
    /*if (m_xml_stream->frozen()) {
        Router::defer([this]() {
            this->bev_closed();
        });
        return;
    }*/
    METRE_LOG(Metre::Log::DEBUG, "NS" << m_serial << " - Closed.");
    onClosed.emit(*this);
}

void NetSession::bev_connected() {
    METRE_LOG(Metre::Log::DEBUG, "NS" << m_serial << " - Connected.");
    onConnected.emit(*this);
    m_xml_stream->restart();
}

#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>

void NetSession::event_cb(struct bufferevent *b, short events, void *arg) {
    NetSession &ns = *reinterpret_cast<NetSession *>(arg);
    METRE_LOG(Metre::Log::DEBUG, "NS" << ns.serial() << " - Events have happened.");
    if (b != ns.m_bev) {
        METRE_LOG(Log::DEBUG, "Not my BEV");
        return;
    }
    if (events & BEV_EVENT_EOF) {
        METRE_LOG(Metre::Log::DEBUG, "NS" << ns.serial() << " - BEV EOF.");
        ns.bev_closed();
    } else if (events & BEV_EVENT_TIMEOUT) {
        METRE_LOG(Log::INFO, "NS" << ns.serial() << " timed out, closing");
        ns.bev_closed();
    } else if (events & BEV_EVENT_ERROR) {
        METRE_LOG(Metre::Log::DEBUG,
                  "NS" << ns.serial() << " - BEV Error " << events << " : " << strerror(EVUTIL_SOCKET_ERROR()));
        while (unsigned long ssl_err = bufferevent_get_openssl_error(b)) {
            char buf[1024];
            METRE_LOG(Metre::Log::DEBUG, " :: " << ERR_error_string(ssl_err, buf));
        }
        ns.bev_closed();
    } else if (events & BEV_EVENT_CONNECTED) {
        ns.bev_connected();
    }
}

void NetSession::close() {
    if (m_xml_stream->frozen()) {
        Router::defer([this]() {
            this->close();
        });
        return;
    }
    METRE_LOG(Metre::Log::DEBUG, "NS" << m_serial << " - Closing.");
    bufferevent_flush(m_bev, EV_WRITE, BEV_FINISHED);
    onClosed.emit(*this);
}
