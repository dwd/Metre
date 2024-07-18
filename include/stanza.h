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

#ifndef STANZA__H
#define STANZA__H

#include "jid.h"
#include "xmppexcept.h"
#include "rapidxml.hpp"
#include "sigslot.h"

#include <memory>

namespace Metre {
    class XMLStream;

    class Stanza {
    public:
        typedef enum {
            bad_request,
            conflict,
            feature_not_implemented,
            forbidden,
            gone,
            internal_server_error,
            item_not_found,
            jid_malformed,
            not_acceptable,
            not_allowed,
            not_authorized,
            policy_violation,
            recipient_unavailable,
            redirect,
            registration_required,
            remote_server_not_found,
            remote_server_timeout,
            resource_constraint,
            service_unavailable,
            subscription_required,
            undefined_condition,
            unexpected_request
        } Error;

        static const char *error_name(Error err);
    protected:
        const char *m_name;
        std::optional<Jid> m_from;
        std::optional<Jid> m_to;
        std::optional<std::string> m_type_str;
        std::optional<std::string> m_id;
        std::string m_lang;
        rapidxml::optional_ptr<rapidxml::xml_node<>> m_node = nullptr;
        std::unique_ptr<rapidxml::xml_document<>> m_doc;
    public:
        // Signals:
        sigslot::signal<Stanza &, bool> sent;

        Stanza(const char *name, rapidxml::optional_ptr<rapidxml::xml_node<>> node);

        explicit Stanza(const char *name);

        Stanza(const char *name, std::optional<Jid> const &from, std::optional<Jid> const &to, std::optional<std::string> const &type,
               std::optional<std::string> const &id);

        virtual ~Stanza() = default;
        Stanza(Stanza const &) = delete;

        const char *name() const {
            return m_name;
        }

        Jid const &to() const {
            return *m_to;
        }

        void to(Jid const &jid) {
            m_to.emplace(jid);
        }

        Jid const &from() const {
            return *m_from;
        }

        void from(Jid const &jid) {
            m_from.emplace(jid);
        }

        std::optional<std::string> const &type_str() const {
            return m_type_str;
        }

        void type_str(std::optional<std::string> const & n) {
            m_type_str = n;
        }

        std::optional<std::string> const &id() const {
            return m_id;
        }

        void id(std::string_view s) {
            m_id = s;
        }

        std::string const &lang() const {
            return m_lang;
        }

        //! If you change anything, in particular if you set names or values
        //! using locally-scoped strings, you must call freeze() before the scope ends.
        //! This is because rapidxml uses string_views rather than copying the data
        //!  by default.
        //! You can avoid this by calling node()->document())->allocate_string(), which
        //! is more efficient but clumsier.
        rapidxml::optional_ptr<rapidxml::xml_node<>> node() {
            return node_internal();
        }
        rapidxml::optional_ptr<rapidxml::xml_node<>> const node() const {
            return const_cast<Stanza *>(this)->node_internal();
        }

        void render(rapidxml::xml_document<> &d) const;
        void render(rapidxml::xml_document<> &d, std::optional<std::string> const &xmlns) const;

        std::unique_ptr<Stanza> create_bounce(Metre::base::stanza_exception const &e) const;

        std::unique_ptr<Stanza> create_bounce(Stanza::Error e) const;

        std::unique_ptr<Stanza> create_forward() const;

        void freeze(); // Make sure nothing is in volatile storage anymore.

    protected:
        rapidxml::optional_ptr<rapidxml::xml_node<>> node_internal(); // If changed, call update();
        void render_error(Stanza::Error e);

        void render_error(Metre::base::stanza_exception const &ex);
   };


    class Message : public Stanza {
    public:
        typedef enum {
            NORMAL, CHAT, HEADLINE, GROUPCHAT, STANZA_ERROR
        } Type;
        static const char *name;
    private:
        Type m_type;
    public:
        explicit Message(rapidxml::optional_ptr<rapidxml::xml_node<>> node);
        explicit Message();

        Type type() const {
            return m_type;
        }
        void type(Type t);

        std::unique_ptr<Message> create_response() const;

    protected:
        Type set_type() const;
    };


    class Iq : public Stanza {
    public:
        typedef enum {
            GET, SET, RESULT, STANZA_ERROR
        } Type;
        static const char *name;
    private:
        Type m_type;
    public:
        explicit Iq(rapidxml::optional_ptr<rapidxml::xml_node<>> node);

        Iq(Jid const &from, Jid const &to, Type t, std::optional<std::string> const &id);

        Type type() const {
            return m_type;
        }

        rapidxml::xml_node<> const &query() const;

    protected:
        static const char *type_toString(Type t);

        Type set_type() const;
    };


    class Presence : public Stanza {
    public:
        static const char *name;

        explicit Presence(rapidxml::optional_ptr<rapidxml::xml_node<>> node) : Stanza(name, node) {
        }
    };

    /*
        * Slightly hacky; used for handling the two dialback elements.
        * These are not stanzas, but behave so much like them syntactically it's silly not to use the code.
        */
    class DB : public Stanza {
    public:
        typedef enum {
            VALID, INVALID, STANZA_ERROR
        } Type;

        DB(const char *name, Jid const &to, Jid const &from, std::string const &stream_id,
           std::optional<std::string> const &key);

        DB(const char *name, rapidxml::optional_ptr<rapidxml::xml_node<>> node) : Stanza(name, node) {
        }

        DB(const char *name, Jid const &to, Jid const &from, std::string const &stream_id, Type t);

        DB(const char *name, Jid const &to, Jid const &from, std::string const &stream_id, Stanza::Error e);

        std::string_view const &key() const {
            if (!m_type_str) {
                const_cast<DB *>(this)->freeze();
                return m_node->value();
            } else {
                throw std::runtime_error("Keys not present in typed dialback element.");
            }
        }

        class Verify;

        class Result;
    };

    class DB::Verify : public DB {
    public:
        static const char *name;

        Verify(Jid const &to, Jid const &from, std::string const &stream_id, std::basic_string<char> key)
                : DB(name, to, from, stream_id, key) {
        }

        Verify(Jid const &to, Jid const &from, std::string const &stream_id, Type t) : DB(name, to, from, stream_id,
                                                                                          t) {}

        Verify(Jid const &to, Jid const &from, std::string const &stream_id, Stanza::Error t) : DB(name, to, from,
                                                                                                   stream_id,
                                                                                                   t) {}

        explicit Verify(rapidxml::optional_ptr<rapidxml::xml_node<>> node) : DB(name, node) {
        }
    };

    class DB::Result : public DB {
    public:
        static const char *name;

        Result(Jid const &to, Jid const &from, std::string const &key)
                : DB(name, to, from, "", key) {
        }

        Result(Jid const &to, Jid const &from, Type t) : DB(name, to, from, "",
                                                            t) {}

        Result(Jid const &to, Jid const &from, Stanza::Error t) : DB(name, to, from, "",
                                                                     t) {}

        explicit Result(rapidxml::optional_ptr<rapidxml::xml_node<>> node) : DB(name, node) {
        }
    };
}

#endif
