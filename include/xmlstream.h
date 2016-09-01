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

#ifndef XMLSTREAM__H
#define XMLSTREAM__H

#include "defs.h"
#include <map>
#include <optional>
#include <memory>
#include <vector>
#include "sigslot/sigslot.h"
#include "rapidxml.hpp"
#include "feature.h"

struct X509_crl_st;

namespace Metre {
    class NetSession;

    class Server;

    class Feature;

    class Verify;

    class Stanza;

    class XMLStream : public sigslot::has_slots<sigslot::thread::st> {
    public:
        typedef enum {
            NONE, REQUESTED, AUTHORIZED
        } AUTH_STATE;

    private:
        rapidxml::xml_document<> m_stream;
        rapidxml::xml_document<> m_stanza; // Not, in fact, always a stanza per-se. //
        NetSession *m_session;
        SESSION_DIRECTION m_dir;
        SESSION_TYPE m_type;
        std::string m_stream_buf; // Sort-of-temporary buffer //
        std::map<std::string, Feature *> m_features;
        std::optional<std::string> m_user;
        std::string m_stream_id;
        std::string m_stream_local;
        std::string m_stream_remote;
        bool m_opened = false;
        bool m_closed = false;
        bool m_seen_open = false;
        bool m_secured = false; // Crypto in place via TLS. //
        bool m_authready = false; // Channel is ready for dialback/SASL //
        bool m_compressed = false; // Channel has compression enabled, by TLS or XEP-0138 //
        bool m_frozen = false;
        std::map<std::pair<std::string, std::string>, AUTH_STATE> m_auth_pairs_rx;
        std::map<std::pair<std::string, std::string>, AUTH_STATE> m_auth_pairs_tx;
        std::map<std::string, Filter *> m_filters;
        std::size_t m_num_crls = 0;
        std::map<std::string, struct X509_crl_st *> m_crls;
        bool m_crl_complete = false;

    public:
        XMLStream(NetSession *owner, SESSION_DIRECTION dir, SESSION_TYPE type);

        XMLStream(NetSession *owner, SESSION_DIRECTION dir, SESSION_TYPE type, std::string const &stream_from,
                  std::string const &stream_to);

        size_t process(unsigned char *, size_t);

        void freeze() {
            m_frozen = true;
        }

        void thaw();

        const char *content_namespace() const;

        SESSION_TYPE type() const {
            return m_type;
        }

        SESSION_DIRECTION direction() const {
            return m_dir;
        }

        bool closed() const {
            return m_closed;
        }

        std::optional<std::string> const &user() const {
            return m_user;
        }

        void user(std::string const &u) {
            m_user = u;
        }

        void send(rapidxml::xml_document<> &d);

        void send(std::unique_ptr<Stanza> v);

        void restart();

        void set_auth_ready() {
            m_authready = true;
            onAuthReady.emit(*this);
        }

        void set_compressed() { m_compressed = true; }

        bool secured() const { return m_secured; }

        void set_secured() { m_secured = true; }

        bool auth_ready() { return m_authready; }

        std::string const &local_domain() { return m_stream_local; }

        std::string const &remote_domain() { return m_stream_remote; }

        bool tls_auth_ok(Route &domain);

        AUTH_STATE s2s_auth_pair(std::string const &local, std::string const &remote, SESSION_DIRECTION) const;

        AUTH_STATE
        s2s_auth_pair(std::string const &local, std::string const &remote, SESSION_DIRECTION, AUTH_STATE auth);

        void check_domain_pair(std::string const &from, std::string const &to) const;

        bool process(Stanza &);

        bool filter(Stanza &); // Filter a stanza. Returns true if it's been swallowed.

        std::string const &stream_local() const {
            return m_stream_local;
        }

        NetSession &session() {
            return *m_session;
        }

        std::string const &stream_id() {
            return m_stream_id;
        }

        ~XMLStream();

        void generate_stream_id();

        void connected(NetSession &);

        void fetch_crl(std::string const & uri);

        void add_crl(std::string const &uri, int code, struct X509_crl_st *data);

        void crl(std::function<void(struct X509_crl_st *)> const &);

        Feature &feature(std::string const &);

        // Signals:
        sigslot::signal<sigslot::thread::st, XMLStream &> onAuthReady;
        sigslot::signal<sigslot::thread::st, XMLStream &> onAuthenticated;

    private:
        void handle(rapidxml::xml_node<> *);
        void do_restart();

        void stream_open();

        void send_stream_open(bool, bool);
    };
}

#endif
