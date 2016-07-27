#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include "router.h"
#include "netsession.h"
#include "config.h"
#include <memory>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace Metre;
using namespace rapidxml;

namespace {
  const std::string tls_ns = "urn:ietf:params:xml:ns:xmpp-tls";

  class StartTls : public Feature {
  private:
      SSL * m_ssl;
  public:
    StartTls(XMLStream & s) : Feature(s) {}
    class Description : public Feature::Description<StartTls> {
    public:
      Description() : Feature::Description<StartTls>(tls_ns, FEAT_SECURE) {};
      virtual void offer(xml_node<> * node, XMLStream &) override {
        xml_document<> * d = node->document();
        auto feature = d->allocate_node(node_element, "starttls");
        feature->append_attribute(d->allocate_attribute("xmlns", tls_ns.c_str()));
        if (false) {
          auto required = d->allocate_node(node_element, "required");
          feature->append_node(required);
        }
        node->append_node(feature);
      }
    };

    SSL_CTX * context() {
      SSL_CTX * ctx = Config::config().domain(m_stream.local_domain()).ssl_ctx();
      if (!ctx) {
        ctx = Config::config().domain("").ssl_ctx();
      }
      return ctx;
    }

    bool handle(rapidxml::xml_node<> * node) override {
      xml_document<> * d = node->document();
      d->fixup<parse_default>(node, true);
      std::string name = node->name();
      if ((name == "starttls" && m_stream.direction() == INBOUND) ||
          (name == "proceed" && m_stream.direction() == OUTBOUND)) {
        SSL_CTX * ctx = context();
        if (!ctx) throw new std::runtime_error("Failed to load certificates");
        SSL * ssl = SSL_new(ctx);
        if (!ssl) throw std::runtime_error("Failure to initiate TLS, sorry!");
        m_ssl = ssl;
        X509_VERIFY_PARAM * vpm = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set1_host(vpm, m_stream.remote_domain().c_str(), m_stream.remote_domain().size());
        // X509_VERIFY_PARAM_set_auth_level(vpm, 1); // OpenSSL 1.1.0 only, maybe?
        SSL_set1_param(ssl, vpm);
        bufferevent_ssl_state st = BUFFEREVENT_SSL_ACCEPTING;
        if (m_stream.direction() == INBOUND) {
          SSL_set_accept_state(ssl);
          xml_document<> d;
          auto n = d.allocate_node(node_element, "proceed");
          n->append_attribute(d.allocate_attribute("xmlns", tls_ns.c_str()));
          d.append_node(n);
          m_stream.send(d);
        } else { //m_stream.direction() == OUTBOUND
          SSL_set_connect_state(ssl);
          st = BUFFEREVENT_SSL_CONNECTING;
        }
        struct bufferevent * bev = m_stream.session().bufferevent();
        struct bufferevent * bev_ssl = bufferevent_openssl_filter_new(bufferevent_get_base(bev), bev, ssl, st, BEV_OPT_CLOSE_ON_FREE);
        if (!bev_ssl) throw std::runtime_error("Cannot create OpenSSL filter");
        m_stream.session().bufferevent(bev_ssl);
        m_stream.set_secured();
        // m_stream.restart(); // Will delete *this.
        return true;
      } else {
        throw std::runtime_error("Unimplemented");
      }
      return false;
    }

    bool negotiate(rapidxml::xml_node<> *) override {
      xml_document<> d;
      auto n = d.allocate_node(node_element, "starttls");
      n->append_attribute(d.allocate_attribute("xmlns", tls_ns.c_str()));
      d.append_node(n);
      m_stream.send(d);
      return true;
    }

      SSL * ssl() {
          return m_ssl;
      }
  };

  bool s2s_declared = Feature::declare<StartTls>(S2S);
  bool c2s_declared = Feature::declare<StartTls>(C2S);
}

namespace Metre {
    bool verify_tls(Feature & feature) {
        StartTls & tls = dynamic_cast<StartTls &>(feature);
        SSL * ssl = tls.ssl();
        return 0 == SSL_get_verify_result(ssl);
    }
}