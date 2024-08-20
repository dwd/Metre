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
#include "sigslot.h"
#include "rapidxml.hpp"
#include "feature.h"
#include "xmppexcept.h"
#include "filter.h"
#include "sigslot/tasklet.h"

struct X509_crl_st;

namespace Metre {
    class NetSession;

    class Server;

    class Feature;

    class Stanza;

    class XMLStream : public sigslot::has_slots {
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
        std::map<std::string, std::unique_ptr<Feature>> m_features;
        std::optional<std::string> m_user;
        std::string m_stream_id;
        std::string m_stream_local;
        std::string m_stream_remote;
        bool m_opened = false;
        bool m_closed = false;
        bool m_secured = false; // Crypto in place via TLS. //
        bool m_authready = false; // Channel is ready for dialback/SASL //
        bool m_compressed = false; // Channel has compression enabled, by TLS or XEP-0138 //
        std::map<std::pair<std::string, std::string>, AUTH_STATE> m_auth_pairs_rx;
        std::map<std::pair<std::string, std::string>, AUTH_STATE> m_auth_pairs_tx;
        std::list<std::unique_ptr<Filter>> m_filters;
        std::map<std::string, struct X509_crl_st *> m_crls;
        bool m_x2x_mode = false;
        bool m_bidi = false;
        bool m_dialback_errors = false;
        bool m_dialback = false;
        std::map<std::string, sigslot::signal<Stanza const &>> m_response_callbacks;
        std::list<std::shared_ptr<sigslot::tasklet<bool>>> m_tasks;
        int m_in_flight = 0; // Tasks in flight.
        std::shared_ptr<spdlog::logger> m_logger;

    public:
        XMLStream(NetSession *owner, SESSION_DIRECTION dir, SESSION_TYPE type);

        XMLStream(NetSession *owner, SESSION_DIRECTION dir, SESSION_TYPE type, std::string const &stream_from,
                  std::string const &stream_to);

        spdlog::logger &logger() const {
            return *m_logger;
        }

        size_t process(unsigned char *, size_t);

        void handle_exception(Metre::base::xmpp_exception &e);

        void in_context(std::function<void()> &&, Stanza &s);

        void in_context(std::function<void()> &&);

        void task_completed();

        std::shared_ptr<sigslot::tasklet<bool>> start_task(std::string const & s, sigslot::tasklet<bool> &&);

        void freeze() {
            ++m_in_flight;
        }

        bool frozen() const {
            return m_in_flight > 0;
        }

        void thaw();

        const char *content_namespace() const;

        SESSION_TYPE type() const {
            return m_type;
        }

        SESSION_DIRECTION direction() const {
            return m_dir;
        }

        bool bidi() const {
            return m_bidi;
        }

        bool bidi(bool b);

        bool closed() const {
            return m_closed;
        }
        bool multiplex(bool target) const;
        bool dialback() const {
            return m_dialback;
        }
        bool dialback(bool dialback, bool errors) {
            m_dialback = dialback;
            m_dialback_errors = dialback && errors;
            return m_dialback;
        }

        void close(rapidxml::optional_ptr<rapidxml::xml_node<>> error = {});

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
            auth_state_changed.emit(*this);
        }

        void set_compressed() { m_compressed = true; }

        bool secured() const { return m_secured; }

        void set_secured() { m_secured = true; }

        bool auth_ready() { return !m_closed && m_authready; }

        std::string const &local_domain() const { return m_stream_local; }

        void local_domain(std::string const &dom) { m_stream_local = dom; }

        std::string const &remote_domain() const { return m_stream_remote; }

        void remote_domain(std::string const &dom) { m_stream_remote = dom; }

        bool x2x_mode() const { return m_x2x_mode; }

        sigslot::tasklet<bool> tls_auth_ok(std::shared_ptr<sentry::span>, Route &domain);

        AUTH_STATE s2s_auth_pair(std::string const &local, std::string const &remote, SESSION_DIRECTION) const;

        AUTH_STATE
        s2s_auth_pair(std::string const &local, std::string const &remote, SESSION_DIRECTION, AUTH_STATE auth);

        void check_domain_pair(std::string const &from, std::string const &to) const;

        std::string const &stream_local() const {
            return m_stream_local;
        }

        NetSession &session() {
            return *m_session;
        }

        std::string const &stream_id() {
            return m_stream_id;
        }

        ~XMLStream() final;

        void generate_stream_id();

        void fetch_crl(std::string const & uri);

        void add_crl(std::string const &uri, int code, struct X509_crl_st *data);

        void crl(std::function<void(struct X509_crl_st *)> const &);

        Feature &feature(std::string const &);

        // Signals:
        sigslot::signal<XMLStream &> auth_state_changed;

    private:
        void handle(rapidxml::optional_ptr<rapidxml::xml_node<>>);

        void do_restart();

        void stream_open();

        sigslot::tasklet<bool> send_stream_open(std::shared_ptr<sentry::transaction>, bool);
    };
}

#endif
