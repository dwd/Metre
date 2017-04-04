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

#ifndef NETSESSION__HPP
#define NETSESSION__HPP

#include <string>
#include "defs.h"
#include "rapidxml.hpp"
#include "sigslot/sigslot.h"
#include "config.h"

// fwd:
struct bufferevent;

namespace Metre {
    class XMLStream;

    class Server;

    class NetSession {
        unsigned long long m_serial;
        struct bufferevent *m_bev;
        std::unique_ptr<XMLStream> m_xml_stream;
        bool m_in_progress = false;
    public:
        NetSession(unsigned long long serial, struct bufferevent *bev, Config::Listener const *listen); /* Inbound */
        NetSession(unsigned long long serial, struct bufferevent *bev, std::string const &stream_from,
                   std::string const &stream_to, SESSION_TYPE, TLS_MODE tls_mode); /* Outbound S2S */

        // Scary stuff only used for buffer juggling.
        struct bufferevent *bufferevent() {
            return m_bev;
        }

        void bufferevent(struct bufferevent *bev);

        // Stuff for XMLStream to indicate it's used octets.
        void used(size_t n);

        // Signals:
        mutable sigslot::signal<sigslot::thread::st, NetSession &> onClosed;
        mutable sigslot::signal<sigslot::thread::st, NetSession &> onConnected;

        bool drain();

        void send(rapidxml::xml_document<> &d);

        void send(std::string const &s);

        void send(const char *p);

        void close();

        void read();

        unsigned long long serial() const {
            return m_serial;
        }

        static void read_cb(struct bufferevent *bev, void *arg);

        static void event_cb(struct bufferevent *bev, short flags, void *arg);

        XMLStream &xml_stream() {
            return *m_xml_stream;
        }

        ~NetSession();

    private:
        void bev_closed();

        void bev_connected();
    };
}

#endif
