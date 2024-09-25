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

#include <http.h>
#include <xmlstream.h>

#include "rapidxml.hpp"
#include "xmlstream.h"
#include "xmppexcept.h"
#include "netsession.h"
#include "feature.h"
#include "filter.h"
#include "router.h"
#include "config.h"
#include "log.h"
#include "pkix.h"
#include "fmt-enum.h"

#ifdef VALGRIND
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(ptr, len) 0
#endif

using namespace Metre;

XMLStream::XMLStream(NetSession *n, SESSION_DIRECTION dir, SESSION_TYPE t)
        : has_slots(), m_session(n), m_dir(dir), m_type(t), m_logger(Config::config().logger("XmlStream serial=[{}] {} type=[{}]", m_session->serial(), dir, t)) {
    using enum SESSION_TYPE;
    if (t == X2X) {
        m_type = S2S;
        m_x2x_mode = true;
        m_bidi = true;
    }
}

XMLStream::XMLStream(NetSession *n, SESSION_DIRECTION dir, SESSION_TYPE t, std::string const &stream_local,
                     std::string const &stream_remote)
        : has_slots(), m_session(n), m_dir(dir), m_type(t), m_stream_local(stream_local),
          m_stream_remote(stream_remote), m_logger(Config::config().logger("XmlStream serial=[{}] {} type=[{}]", m_session->serial(), dir, t)) {
    using enum SESSION_TYPE;
    if (t == X2X) {
        m_type = S2S;
        m_x2x_mode = true;
        m_bidi = true;
    }
}

void XMLStream::thaw() {
    if (m_in_flight <= 0) return;
    --m_in_flight;
    if (m_in_flight > 0) return;
    logger().debug("thaw");
    m_session->read();
    logger().debug("thaw done");
}

size_t XMLStream::process(unsigned char *p, size_t len) {
    using namespace rapidxml;
    if (len == 0) return 0;
    if (frozen()) {
        logger().debug("Data arrived when frozen");
        return 0;
    }
    (void) VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(p, len);
    size_t spaces = 0;
    for (const unsigned char *sp{p}; len != 0; ++sp, --len, ++spaces) {
        switch (*sp) {
            default:
                break;
            case ' ':
            case '\r':
            case '\n':
                continue;
        }
        break;
    }
    if (spaces) m_session->used(spaces);
    if (len == 0) return spaces;
    std::string_view buf{reinterpret_cast<char *>(p + spaces), len};
    logger().debug("Got [{}]: {}", len, buf);
    try {
        try {
            if (m_stream_buf.empty()) {
                /**
                 * We need to grab the stream open. Do so by parsing the main buffer to find where the open
                 * finishes, and copy that segment over to another buffer. Then reparse, this time properly.
                 */
                logger().debug("Parsing stream open");
                try {
                    auto end = m_stream.parse<parse_open_only | parse_fastest>(buf);
                    m_first_read = false;
                    auto test = m_stream.first_node();
                    if (test && !test->name().empty()) {
                        m_stream_buf.assign(buf.data(), end.ptr());
                        m_session->used(end.ptr() - buf.data());
                        buf.remove_prefix(end.ptr() - buf.data());
                        m_stream.parse<parse_open_only>(m_stream_buf);
                        stream_open();
                    } else {
                        m_stream_buf.clear();
                    }
                } catch (rapidxml::eof_error &) {
                    throw;
                } catch (rapidxml::parse_error &) {
                    m_logger.info("Parse error; could be TLS handshake");
                    if (m_first_read && !m_secured) {
                        if (!start_tls(*this, false)) {
                            m_logger.error("Tried starttls, but that didn't work either");
                            throw;
                        } else {
                            m_logger.info("TLS negotiation underway");
                            m_first_read = false;
                            return 0;
                        }
                    } else {
                        m_logger.error("Not first read or already TLS; giving up");
                        throw;
                    }
                }
            }
            while (!buf.empty()) {
                auto end = m_stanza.parse<parse_fastest | parse_parse_one>(buf, &m_stream);
                m_first_read = false;
                auto element = m_stanza.first_node();
                if (!element || element->name().empty()) return len - buf.length();
                bool tls_nego = element->xmlns() == "urn:ietf:params:xml:ns:xmpp-tls";
                // For TLS negotiation elements, we need to special-case to avoid
                // the data still being in the buffer when the TLS handshake occurs.
                if (tls_nego) {
                    // Clone it then discard the buffer.
                    element = m_stanza.clone_node(element, true);
                    m_session->used(end.ptr() - buf.data());
                    buf.remove_prefix(end.ptr() - buf.data());
                }
                handle(element);
                if (!tls_nego) {
                    m_session->used(end.ptr() - buf.data());
                    buf.remove_prefix(end.ptr() - buf.data());
                }
                m_stanza.clear();
                if (frozen()) return spaces + len - buf.length();
            }
        } catch (Metre::base::xmpp_exception &) {
            throw;
        } catch (rapidxml::eof_error &) {
            return spaces + len - buf.length();
        } catch (rapidxml::parse_error &e) {
            if (buf == "</stream:stream>") {
                m_session->send("</stream:stream>");
                m_closed = true;
                m_session->used(buf.size());
                buf.remove_prefix(buf.size());
            } else {
                throw Metre::not_well_formed(e.what());
            }
        } catch (std::runtime_error &e) {
            throw Metre::undefined_condition(e.what());
        }
    } catch (Metre::base::xmpp_exception &e) {
        handle_exception(e);
    }
    return spaces + len - buf.length();
}

void XMLStream::handle_exception(Metre::base::xmpp_exception const & e) {
    using namespace rapidxml;
    logger().error("Raising error: [{}]", e.what());
    xml_document<> d;
    auto error = d.append_element("stream:error");
    auto specific = error->append_element({"urn:ietf:params:xml:ns:xmpp-streams", e.element_name()});
    error->append_element({"urn:ietf:params:xml:ns:xmpp-streams", e.element_name()}, e.what());
    if (dynamic_cast<Metre::undefined_condition const *>(&e)) {
        specific->append_element({"http://cridland.im/xmlns/metre", "unhandled-exception"});
    }
    close(error);
}

void XMLStream::close(rapidxml::optional_ptr<rapidxml::xml_node<>> error) {
    if (m_closed) return;
    if (m_opened) {
        if (error) m_session->send(error.value());
        m_session->send("</stream:stream>");
    } else {
        rapidxml::xml_document<> d;
        auto node = d.allocate_node(rapidxml::node_element, "stream:stream");
        node->append_attribute(d.allocate_attribute("xmlns:stream", "http://etherx.jabber.org/streams"));
        node->append_attribute(d.allocate_attribute("version", "1.0"));
        node->append_attribute(d.allocate_attribute("xmlns", content_namespace()));
        if (error) {
            node->append_node(d.clone_node(error));
        }
        d.append_node(node);
        m_session->send("<?xml version='1.0'?>");
        m_session->send(d);
    }
    m_closed = true;
    auth_state_changed(*this);
}

void XMLStream::in_context(std::function<void()> const &fn, Stanza const &s) {
    try {
        fn();
    } catch (Metre::base::xmpp_exception &e) {
        handle_exception(e);
    } catch (Metre::base::stanza_exception &stanza_error) {
        std::unique_ptr<Stanza> st = s.create_bounce(stanza_error);
        std::shared_ptr<Route> route = RouteTable::routeTable(st->from()).route(st->to());
        route->transmit(std::move(st));
    } catch (std::runtime_error &e) {
        Metre::stanza_undefined_condition stanza_error(e.what());
        std::unique_ptr<Stanza> st = s.create_bounce(stanza_error);
        std::shared_ptr<Route> route = RouteTable::routeTable(st->from()).route(st->to());
        route->transmit(std::move(st));
    }
}

void XMLStream::in_context(std::function<void()> const &fn) {
    try {
        fn();
    } catch (Metre::base::xmpp_exception &e) {
        handle_exception(e);
    } catch (Metre::base::stanza_exception &e) {
        handle_exception(Metre::undefined_condition(std::string("Uncaught stanza error: ") + e.what()));
    } catch (std::runtime_error &e) {
        handle_exception(Metre::undefined_condition(e.what()));
    }
}

const char *XMLStream::content_namespace() const {
    const char *p;
    switch (m_type) {
        using enum SESSION_TYPE;
        case C2S:
            p = "jabber:client";
            break;
        case COMP:
            p = "jabber:component:accept";
            break;
        default:
            p = "jabber:server";
            break;
    }
    return p;
}

void XMLStream::check_domain_pair(std::string const &from_domain, std::string const &to_domain) const {
    using enum SESSION_TYPE;
    Config::Domain const &to = Config::config().domain(to_domain);
    if (to.block()) {
        throw Metre::host_unknown("Requested domain is blocked: to=[" + to_domain + "]");
    }
    if (m_type == COMP && to.transport_type() != COMP) {
        throw Metre::host_unknown("Component connection protocol mismatch: from=[" + from_domain + "] to=[" + to_domain + "]");
    }
    Config::Domain const &from = Config::config().domain(from_domain);
    if (!from_domain.empty()) {
        if (from.block()) {
            throw Metre::host_unknown("Requesting domain is blocked: from=[" + from_domain + "]");
        }
        if ((to.transport_type() != COMP) &&
            ((from.forward() == to.forward()) && to.transport_type() != INTERNAL &&
             from.transport_type() != INTERNAL)) {
            throw Metre::host_unknown("Will not forward between same domains with non-internal protocol: from=[" + from_domain + "] to=[" + to_domain + "]");
        }
        if (m_type != COMP && from.transport_type() == COMP) {
            throw Metre::host_unknown("Attempting to connect to non-component with component protocol:from=[" + from_domain + "] to=[" + to_domain + "]");
        }
    }
}

void XMLStream::stream_open() {
    /**
     * We may be able to change our minds on what stream type this is, here,
     * by looking at the default namespace.
     */
    auto stream = m_stream.first_node();
    if (auto xmlns = stream->first_attribute("xmlns"); xmlns && !xmlns->value().empty()) {
        using enum SESSION_TYPE;
        if (xmlns->value() == "jabber:client") {
            logger().debug("C2S stream detected.");
            m_type = C2S;
        } else if (xmlns->value() == "jabber:server") {
            logger().debug("S2S stream detected.");
            m_type = S2S;
        } else if (xmlns->value() == "jabber:component:accept") {
            logger().debug("114 (component) stream detected.");
            m_type = COMP;
        } else {
            logger().warn("Unidentified connection.");
        }
    }

    std::string domainname;
    if (auto domainat = stream->first_attribute("to"); domainat && !domainat->value().empty()) {
        domainname.assign(domainat->value());
        logger().debug("Requested contact domain [{}]", domainname);
    } else if (m_dir == SESSION_DIRECTION::OUTBOUND) {
        domainname = Jid(m_stream_local).domain();
    } else {
        domainname = Config::config().default_domain();
    }
    std::string from;
    if (auto fromat = stream->first_attribute("from")) {
        from = Jid(fromat->value()).domain();
        if (m_dir == SESSION_DIRECTION::OUTBOUND && from != m_stream_remote) {
            logger().warn("Remote server responded with {}, not {}", from, m_stream_remote);
            from = m_stream_remote;
        }
        logger().debug("Requesting domain is {}", from);
        check_domain_pair(from, domainname);
    }
    if (stream->xmlns().empty()) {
        throw Metre::bad_format("Missing namespace for stream");
    }
    if (stream->name() != "stream" ||
        stream->xmlns() != "http://etherx.jabber.org/streams") {
        throw Metre::bad_namespace_prefix("Need a stream open");
    }
    // Assume we're good here.
    auto version = stream->first_attribute("version");
    bool with_ver = false;
    if (version && version->value() == "1.0") {
        with_ver = true;
    }
    if (with_ver) {
        auto const & ver_domain = (m_type == SESSION_TYPE::COMP) ? domainname : from;
        with_ver = Config::config().domain(ver_domain).xmpp_ver();
        if (!with_ver) logger().debug("Suppressing the version for {} due to config", ver_domain);
    }
    if (m_dir == SESSION_DIRECTION::INBOUND) {
        m_stream_local = domainname;
        if (from.empty()) {
            // TODO: A bit cut'n'pastey here.
            start_task("Empty from inbound send_stream_open", send_stream_open(std::make_shared<sentry::transaction>("element", "{http://etherx.jabber.org/streams}stream"), with_ver));
        } else {
            m_stream_remote = from;
            if (m_stream_remote == m_stream_local) {
                throw std::runtime_error("That's me, you fool");
            }
            start_task("With from, inbound send_stream_open", send_stream_open(std::make_shared<sentry::transaction>("element", "{http://etherx.jabber.org/streams}stream"), with_ver));
        }
    } else if (m_dir == SESSION_DIRECTION::OUTBOUND) {
        if (m_type == SESSION_TYPE::S2S) {
            auto id_att = stream->first_attribute("id");
            if (id_att) {
                if (!m_stream_id.empty()) {
                    Router::unregister_stream_id(m_stream_id);
                }
                m_stream_id = id_att->value();
                Router::register_stream_id(m_stream_id, *m_session);
            }
        }
        return;
    }
}

sigslot::tasklet<bool> XMLStream::send_stream_open(std::shared_ptr<sentry::transaction> trans, bool with_version) {
    if (m_x2x_mode) {
        if (m_secured) {
            auto route = RouteTable::routeTable(m_stream_local).route(m_stream_remote);
            if (!co_await tls_auth_ok(trans->start_child("tls", m_stream_remote), *route)) {
                throw host_unknown("Cannot authenticate host");
            }
        }
        std::string stream_buf = fmt::format("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='{}' to='{}' from='{}'>", content_namespace(), m_stream_local, m_stream_remote);
        process(reinterpret_cast<unsigned char *>(stream_buf.data()), stream_buf.size());
        set_auth_ready();
    } else {
        /*
        *   We write this out as a string, to avoid trying to make rapidxml
        * write out only the open tag.
        */
        std::string open = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='";
        open += content_namespace();
        if (m_type == SESSION_TYPE::S2S) {
            open += "' xmlns:db='jabber:server:dialback";
            if (!m_stream_remote.empty()) {
                open += "' to='";
                open += m_stream_remote;
            }
        }
        open += "' from='";
        open += m_stream_local;
        if (m_dir == SESSION_DIRECTION::INBOUND) {
            open += "' id='";
            generate_stream_id();
            open += m_stream_id;
        }
        if (with_version) {
            open += "' version='1.0'>";
        } else {
            open += "'>";
        }
        m_session->send(open);
        if (with_version && m_dir == SESSION_DIRECTION::INBOUND) {
            rapidxml::xml_document<> doc;
            auto features = doc.allocate_node(rapidxml::node_element, "stream:features");
            doc.append_node(features);
            for (auto const & f : Feature::features(m_type)) {
                co_await *start_task("Feature offer", f->offer(trans->start_child("feature.offer", f->xmlns()), features, *this));
            }
            m_session->send(doc);
        }
    }
    m_opened = true;
    co_return true;
}

void XMLStream::send(rapidxml::xml_document<> &d) {
    m_session->send(d);
}

void XMLStream::send(std::unique_ptr<Stanza> s) {
    m_session->send(*s->node());
    s->sent(*s, true);
}

void XMLStream::handle(rapidxml::optional_ptr<rapidxml::xml_node<>> element) {
    m_logger.trace("handle element={} xmlns={}", element->name(), element->xmlns());
    if (element->xmlns() == "http://etherx.jabber.org/streams") {
        if (element->name() == "features") {
            for (;;) {
                rapidxml::optional_ptr<rapidxml::xml_node<>> feature_offer = nullptr;
                Feature::Type feature_type = Feature::Type::FEAT_NONE;
                std::string feature_xmlns;
                for (auto feat_ad = element->first_node(); feat_ad; feat_ad = feat_ad->next_sibling()) {
                    auto const & offer_ns = feat_ad->xmlns();
                    logger().debug("Got feature offer: [{}:{}]", feat_ad->xmlns(), feat_ad->name());
                    if (m_features.contains(offer_ns)) continue; // Already negotiated.
                    Feature::Type offer_type = Feature::type(offer_ns, *this);
                    logger().debug("Offer type seems to be [{}]", std::to_underlying(offer_type));
                    switch (offer_type) {
                        using enum Feature::Type;
                        case FEAT_NONE:
                            continue;
                        case FEAT_SECURE:
                            if (m_secured) continue;
                            break;
                        case FEAT_COMP:
                            if (m_compressed) continue;
                            break;
                        default:
                            /* pass */;
                    }
                    if (feature_type < offer_type) {
                        logger().debug("Feature [{}:{}] supersedes [{}]", feat_ad->xmlns(), feat_ad->name(), feature_xmlns);
                        feature_offer = feat_ad;
                        feature_xmlns = offer_ns;
                        feature_type = offer_type;
                    }
                }
                m_logger.debug("Processing feature [{}]", feature_xmlns);
                if (feature_type == Feature::Type::FEAT_NONE) {
                    if (!m_features.contains("urn:xmpp:features:dialback")) {
                        auto so = m_stream.first_node();
                        auto dbatt = so->first_attribute("xmlns:db");
                        if (dbatt && dbatt->value() == std::string("jabber:server:dialback")) {
                            feature_xmlns = "urn:xmpp:features:dialback";
                            goto try_feature;
                        }
                    } else if (s2s_auth_pair(local_domain(), remote_domain(), SESSION_DIRECTION::OUTBOUND) == AUTH_STATE::AUTHORIZED) {
                        set_auth_ready();
                    }
                    return;
                }
                try_feature:
                auto f = Feature::feature(feature_xmlns, *this);
                assert(f.get());
                bool escape = f->negotiate(feature_offer);
                m_features.try_emplace(feature_xmlns, std::move(f));
                m_logger.debug("Feature negotiated, stream restart is [{}]", escape);
                if (escape) return; // We've done a stream restart or something.
            }
        } else if (element->name() == "error") {
            const std::string err_ns = "urn:ietf:params:xml:ns:xmpp-streams";
            auto err_type = element->first_node({}, err_ns);
            auto err_text = element->first_node("text", err_ns);
            auto level = err_type->name() == "connection-timeout" ? spdlog::level::debug : spdlog::level::err;
            if (err_text) {
                m_logger.log(level, "Received {} over stream: {}", err_type->name(), err_text->value());
            } else {
                m_logger.log(level,"Received {} over stream", err_type->name());
            }
            m_session->close();
            return;
        } else {
            throw Metre::unsupported_stanza_type("Unknown stream element");
        }
    } else {
        auto const & xmlns = element->xmlns();
        auto fit = m_features.find(xmlns);
        m_logger.debug("Hunting handling feature for [{}]", xmlns);
        if (fit == m_features.end()) {
            auto feat = Feature::feature(xmlns, *this);
            auto [new_it, success] = m_features.try_emplace(std::string{xmlns}, std::move(feat));
            fit = new_it;
            m_logger.debug("Created new feature [{}]", xmlns);
        }

        bool handled = false;

        if (auto const & feat = fit->second; feat) {
            std::string clark_name = "{";
            clark_name += element->xmlns();
            clark_name += "}";
            clark_name += element->name();
            auto task = start_task("XMLStream handle element", feat->handle(std::make_shared<sentry::transaction>("element", clark_name), element));
            if (task->running()) {
                return;
            } else {
                handled = task->get();
            }
        }
        m_logger.debug("Handled: [{}]", handled);
        if (!handled) {
            throw Metre::unsupported_stanza_type();
        }
    }
}

void XMLStream::restart() {
    do_restart();
}

void XMLStream::do_restart() {
    if (!m_stream_id.empty()) {
        Router::unregister_stream_id(m_stream_id);
        m_stream_id.clear();
    }
    m_features.clear();
    m_stream.clear();
    m_stanza.clear();
    m_stream_buf.clear();
    if (m_dir == SESSION_DIRECTION::OUTBOUND) {
        start_task("Restart outbound send_stream_open", send_stream_open(std::make_shared<sentry::transaction>("element", "{http://etherx.jabber.org/streams}stream"), true));
        thaw();
    }
}

void XMLStream::generate_stream_id() {
    if (!m_stream_id.empty()) {
        Router::unregister_stream_id(m_stream_id);
    }
    m_stream_id = Config::config().random_identifier();
    Router::register_stream_id(m_stream_id, *m_session);
}

XMLStream::AUTH_STATE
XMLStream::s2s_auth_pair(std::string const &local, std::string const &remote, SESSION_DIRECTION dir) const {
    using enum AUTH_STATE;
    using enum SESSION_DIRECTION;
    if (m_type == SESSION_TYPE::COMP && m_user) {
        if (dir == OUTBOUND && *m_user == remote) {
            return AUTHORIZED;
        } else if (dir == INBOUND && *m_user == remote) {
            return AUTHORIZED;
        }
    }
    if (m_bidi) dir = m_dir; // For XEP-0288, only consider the primary direction.
    auto &m = (dir == INBOUND ? m_auth_pairs_rx : m_auth_pairs_tx);
    AUTH_STATE auth_state = NONE;
    if (auto it = m.find(std::make_pair(local, remote)); it != m.end()) {
        auth_state = (*it).second;
    }
    if (auth_state != AUTHORIZED && x2x_mode()) {
        if (dir == INBOUND) {
            if (!secured()
                // TODO : Needs to be checking the host is correct.
                && Config::config().domain(remote).auth_host()) {
                return AUTHORIZED;
            }
        } else if (dir == OUTBOUND) {
            return AUTHORIZED;
        }
    }
    return auth_state;
}

XMLStream::AUTH_STATE XMLStream::s2s_auth_pair(std::string const &local, std::string const &remote, SESSION_DIRECTION dir, XMLStream::AUTH_STATE state) {
    using enum SESSION_DIRECTION;
    if (state == AUTH_STATE::AUTHORIZED && !m_secured && Config::config().domain(remote).require_tls()) {
        throw Metre::not_authorized("Authorization attempt without TLS");
    }
    if (m_bidi) dir = m_dir; // For XEP-0288, only consider the primary direction.
    auto &m = (dir == INBOUND ? m_auth_pairs_rx : m_auth_pairs_tx);
    auto key = std::make_pair(local, remote);
    if (auto current = m[key]; current < state) {
        m[key] = state;
        if (state == XMLStream::AUTH_STATE::AUTHORIZED) {
            logger().info("Authorized {} session local: {} remote: {}", (dir == INBOUND ? "INBOUND" : "OUTBOUND"),
                          local, remote);
            if (m_bidi && dir == INBOUND) RouteTable::routeTable(local).route(remote)->outbound(m_session);
            auth_state_changed.emit(*this);
        }
    }
    return m[key];
}

bool XMLStream::bidi(bool b) {
    m_bidi = b;
    if (m_bidi && m_dir == SESSION_DIRECTION::INBOUND) {
        for (auto const & [domains, state] : m_auth_pairs_rx) {
            if (state == XMLStream::AUTH_STATE::AUTHORIZED) {
                auto const & [local, remote] = domains;
                RouteTable::routeTable(local).route(remote)->outbound(m_session);
            }
        }
    }
    return m_bidi;
}

sigslot::tasklet<bool> XMLStream::tls_auth_ok(std::shared_ptr<sentry::span> span, Route &route) {
    if (!m_secured) co_return false;
    auto task = start_task("tls_auth_ok call verify_tls", verify_tls(span->start_child("tls", "verify"), *this, route));
    auto ret = co_await *task;
    co_return ret;
}

void XMLStream::task_completed() {
    Router::defer([this]() {
        m_tasks.remove_if([this](auto & task) {
            if(!task->running()) {
                in_context([task]() {
                    task->get();
                });
                return true;
            }
            return false;
        });
    });
    thaw();
}

std::shared_ptr<sigslot::tasklet<bool>> XMLStream::start_task(std::string const & s, sigslot::tasklet<bool> &&otask) {
    auto task = std::make_shared<sigslot::tasklet<bool>>(std::move(otask));
    task->set_name(s);
    task->start();
    if (task->running()) {
        freeze();
        task->complete().connect(this, &XMLStream::task_completed);
        m_tasks.emplace_back(task);
        logger().debug("Task [{}] paused, currently [{}] running.", s, m_tasks.size());
    }
    return task;
}

bool XMLStream::multiplex(bool target) const {
    if (Config::config().domain(m_stream_remote).multiplex()) {
        if (target) return m_dialback_errors; // Try target multiplexing if the remote end supports dialback errors.
        return m_dialback; // Try sender multiplexing if any dialback is supported.
    }
    return false;
}
