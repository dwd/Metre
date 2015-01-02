#include "feature.hpp"
#include "stanza.hpp"
#include "xmppexcept.hpp"
#include "router.hpp"
#include "netsession.hpp"
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

    static SSL_CTX * context() {
      static SSL_CTX * ctx = 0;
      if (!ctx) {
        SSL_library_init();
    		ERR_load_crypto_strings();
    		SSL_load_error_strings();
    		OpenSSL_add_all_algorithms();
    		if (RAND_poll() == 0) {
          return nullptr;
    		}
        ctx = SSL_CTX_new(SSLv23_method());
        SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
        if (SSL_CTX_use_certificate_chain_file(ctx, "cridland.im.stuffs") != 1) {
          return nullptr;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, "cridland.im.key", SSL_FILETYPE_PEM) != 1) {
          return nullptr;
        }
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
  };

  bool s2s_declared = Feature::declare<StartTls>(S2S);
  bool c2s_declared = Feature::declare<StartTls>(C2S);
}
