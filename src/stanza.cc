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

#include "stanza.h"
#include "xmlstream.h"
#include "rapidxml_print.hpp"
#include "rapidxml_iterators.hpp"
#include "log.h"

using namespace Metre;

Stanza::Stanza(const char *name, rapidxml::optional_ptr<rapidxml::xml_node<>> node) : m_name(name), m_node(node) {
    auto to = node->first_attribute("to");
    if (to) m_to = Jid(to->value());
    auto from = node->first_attribute("from");
    if (from) m_from = Jid(from->value());
    auto typestr = node->first_attribute("type");
    if (typestr) m_type_str = typestr->value();
    auto id = node->first_attribute("id");
    if (id) m_id = id->value();
}

Stanza::Stanza(const char *name) : m_name(name) {
}

Stanza::Stanza(const char *name, std::optional<Jid> const &from, std::optional<Jid> const &to, std::optional<std::string> const &type_str,
               std::optional<std::string> const &id)
        : m_name(name), m_from(from), m_to(to), m_type_str(type_str),
          m_id(id) {
    m_doc = std::make_unique<rapidxml::xml_document<>>();
    m_node = m_doc->append_element(m_name);
    if (m_from) m_node->append_attribute(m_doc->allocate_attribute("from", m_from->full()));
    if (m_to) m_node->append_attribute(m_doc->allocate_attribute("to", m_to->full()));
    if (m_type_str) m_node->append_attribute(m_doc->allocate_attribute("type", m_type_str.value()));
    if (m_id) m_node->append_attribute(m_doc->allocate_attribute("id", m_id.value()));
}

void Stanza::freeze() {
    auto doc = std::make_unique<rapidxml::xml_document<>>();
    auto node = doc->append_element(m_name);
    if (m_from) node->append_attribute(doc->allocate_attribute("from", m_from->full()));
    if (m_to) node->append_attribute(doc->allocate_attribute("to", m_to->full()));
    if (m_type_str) node->append_attribute(doc->allocate_attribute("type", m_type_str.value()));
    if (m_id) node->append_attribute(doc->allocate_attribute("id", m_id.value()));
    if (m_node) {
        for (auto & child : rapidxml::children(m_node)) {
            node->append_node(doc->clone_node(&child, true));
        }
    }
    m_doc = std::move(doc);
    m_node = node;
}

void Stanza::render(rapidxml::xml_document<> &d, std::optional<std::string> const & xmlns) const {
    rapidxml::optional_ptr<rapidxml::xml_node<>> root;
    if (xmlns.has_value()) {
        root = d.append_element({xmlns.value(), m_name});
    } else {
        root = d.append_element(m_name);
    }
    if (m_to) root->append_attribute(d.allocate_attribute("to", m_to->full()));
    if (m_from) root->append_attribute(d.allocate_attribute("from", m_from->full()));
    if (m_type_str) root->append_attribute(d.allocate_attribute("type", m_type_str.value()));
    if (m_id) root->append_attribute(d.allocate_attribute("id", m_id.value()));
    for (auto & child : rapidxml::children(m_node)) {
        root->append_node(d.clone_node(&child));
    }
}

void Stanza::render(rapidxml::xml_document<> &d) const {
    render(d, std::optional<std::string>{});
}

rapidxml::optional_ptr<rapidxml::xml_node<>> Stanza::node_internal() {
    if (m_node) return m_node;
    freeze();
    return m_node;
}

std::unique_ptr<Stanza> Stanza::create_bounce(base::stanza_exception const &ex) const {
    auto stanza = std::make_unique<Stanza>(m_name, m_to, m_from, "error", m_id);
    stanza->render_error(ex);
    for (auto & child : rapidxml::children(m_node)) {
        stanza->m_node->append_node(stanza->m_doc->clone_node(&child));
    }
    return stanza;
}

void Stanza::render_error(Metre::base::stanza_exception const &ex) {
    auto error = m_node->append_element("error");
    error->append_attribute(m_doc->allocate_attribute("type", ex.error_type()));
    error->append_element({"urn:ietf:params:xml:ns:xmpp-stanzas", ex.element_name()});
    error->append_element({"urn:ietf:params:xml:ns:xmpp-stanzas", "text"}, ex.what());
}

void Stanza::render_error(Stanza::Error e) {
    switch (e) {
        case remote_server_timeout:
            render_error(stanza_remote_server_timeout());
            return;
        case remote_server_not_found:
            render_error(stanza_remote_server_not_found());
            return;
        case service_unavailable:
            render_error(stanza_service_unavailable());
            return;
        case undefined_condition:
            render_error(stanza_undefined_condition());
            return;
        case policy_violation:
            render_error(stanza_policy_violation());
            return;
        default:
        METRE_LOG(Log::CRIT, "Unhandled stanza error type");
            render_error(stanza_undefined_condition());
    }
}

std::unique_ptr<Stanza> Stanza::create_bounce(Stanza::Error e) const {
    switch (e) {
        case remote_server_timeout:
            return create_bounce(stanza_remote_server_timeout());
        case remote_server_not_found:
            return create_bounce(stanza_remote_server_not_found());
        case service_unavailable:
            return create_bounce(stanza_service_unavailable());
        case undefined_condition:
            return create_bounce(stanza_undefined_condition());
        default:
        METRE_LOG(Log::CRIT, "Unhandled stanza error type");
            return create_bounce(stanza_undefined_condition());
    }
}

std::unique_ptr<Stanza> Stanza::create_forward() const {
    std::unique_ptr<Stanza> stanza{new Stanza(m_name)};
    stanza->m_from = m_from;
    stanza->m_to = m_to;
    stanza->m_id = m_id;
    stanza->m_type_str = m_type_str;
    for (auto & child : rapidxml::children(m_node)) {
        stanza->m_node->append_node(stanza->m_doc->clone_node(&child));
    }
    return stanza;
}

const char *Stanza::error_name(Stanza::Error err) {
    std::vector<const char *> names{
            "bad-request",
            "conflict",
            "feature-not-implemented",
            "forbidden",
            "gone",
            "internal-server-error",
            "item-not-found",
            "jid-malformed",
            "not-acceptable",
            "not-allowed",
            "not-authorized",
            "policy-violation",
            "recipient-unavailable",
            "redirect",
            "registration-required",
            "remote-server-not-found",
            "remote-server-timeout",
            "resource-constraint",
            "service-unavailable",
            "subscription-required",
            "undefined-condition",
            "unexpected-request"
    };
    return names.at(static_cast<std::vector<const char *>::size_type>(err));
}

Message::Message() : Stanza(Message::name) {
    m_type = set_type();
}

Message::Message(rapidxml::optional_ptr<rapidxml::xml_node<>> node) : Stanza(Message::name, node) {
    m_type = set_type();
}

std::unique_ptr<Message> Message::create_response() const {
    auto stanza = std::make_unique<Message>();
    stanza->m_from = m_to;
    stanza->m_to = m_from;
    stanza->m_id = m_id;
    stanza->m_type_str = m_type_str;
    stanza->m_type = m_type;
    return stanza;
}



void Message::type(Message::Type t) {
    m_type = t;
    switch(m_type) {
        case NORMAL:
            type_str(std::optional<std::string>());
            break;
        case CHAT:
            type_str("chat");
            break;
        case HEADLINE:
            type_str("headline");
            break;
        case GROUPCHAT:
            type_str("groupchat");
            break;
        case STANZA_ERROR:
            type_str("error");
            break;
    }
}

Message::Type Message::set_type() const {
    if (!type_str()) return NORMAL;
    std::string const &t = *type_str();
    switch (t[0]) {
        case 'n':
            if (t == "normal") return NORMAL;
            break;
        case 'c':
            if (t == "chat") return CHAT;
            break;
        case 'h':
            if (t == "headline") return HEADLINE;
            break;
        case 'g':
            if (t == "groupchat") return GROUPCHAT;
            break;
        case 'e':
            if (t == "error") return STANZA_ERROR;
            break;
    }
    throw std::runtime_error("Unknown Message type");
}

Iq::Iq(Jid const &from, Jid const &to, Type t, std::optional<std::string> const &id) : Stanza(Iq::name, from, to,
                                                                                              Iq::type_toString(t), id), m_type(t) {}

Iq::Iq(rapidxml::optional_ptr<rapidxml::xml_node<>> node) : Stanza(name, node) {
    m_type = set_type();
}

const char *Iq::type_toString(Type t) {
    switch (t) {
        case GET:
            return "get";
        case SET:
            return "set";
        case RESULT:
            return "result";
        case STANZA_ERROR:
            return "error";
    }
    return "error";
}

Iq::Type Iq::set_type() const {
    if (!type_str()) throw std::runtime_error("Missing type for Iq");
    std::string const &t = *type_str();
    switch (t[0]) {
        case 'g':
            if (t == "get") return GET;
            break;
        case 's':
            if (t == "set") return SET;
            break;
        case 'r':
            if (t == "result") return RESULT;
            break;
        case 'e':
            if (t == "error") return STANZA_ERROR;
            break;
    }
    throw std::runtime_error("Unknown IQ type");
}

rapidxml::xml_node<> const &Iq::query() const {
    return *node()->first_node();
}

const char *Iq::name = "iq";
const char *Message::name = "message";
const char *Presence::name = "presence";
const char *DB::Verify::name = "db:verify";
const char *DB::Result::name = "db:result";

/*
 * Dialback
 */

DB::DB(const char *name, Jid const &to, Jid const &from, std::string const &stream_id,
       std::optional<std::string> const &key)
        : Stanza(name, to, from, std::optional<std::string>{}, stream_id) {
    if (key) m_node->value(key.value());
}

DB::DB(const char *name, Jid const &to, Jid const &from, std::string const &stream_id, Type t) : Stanza(name) {
    m_to = to;
    m_from = from;
    m_id = stream_id;
    switch (t) {
        case VALID:
            m_type_str = "valid";
            break;
        case INVALID:
            m_type_str = "invalid";
            break;
        case STANZA_ERROR:
            m_type_str = "error";
            break;
    }
}

DB::DB(const char *name, Jid const &to, Jid const &from, std::string const &stream_id, Stanza::Error e) : Stanza(name) {
    m_to = to;
    m_from = from;
    m_id = stream_id;
    m_type_str = "error";
    render_error(e);
}