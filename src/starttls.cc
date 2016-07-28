#include "feature.h"
#include "stanza.h"
#include "xmppexcept.h"
#include "router.h"
#include "netsession.h"
#include "config.h"
#include "log.h"
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
      virtual void offer(xml_node<> * node, XMLStream & s) override {
        if (s.secured()) return;
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
    bool verify_tls(XMLStream & stream, std::string const & hostname) {
        SSL * ssl = bufferevent_openssl_get_ssl(stream.session().bufferevent());
        if (!ssl) return false; // No TLS.
        if (X509_V_OK != SSL_get_verify_result(ssl)) {
            METRE_LOG("Cert failed verification but rechecking anyway.");
        } // TLS failed basic verification.
        X509 * cert = SSL_get_peer_certificate(ssl);
        if (!cert) {
            METRE_LOG("No cert, so no auth");
            return false;
        }
        METRE_LOG("[Re]verifying TLS for " + hostname);
        STACK_OF(X509) * chain = SSL_get_peer_cert_chain(ssl);
        SSL_CTX * ctx = SSL_get_SSL_CTX(ssl);
        X509_STORE * store = SSL_CTX_get_cert_store(ctx);
        // TODO : Can I free ctx now?
        X509_VERIFY_PARAM * vpm = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set1_host(vpm, hostname.c_str(), hostname.size());
        // X509_VERIFY_PARAM_set_auth_level(vpm, 1); // OpenSSL 1.1.0 only, maybe?
        // TODO add additional names and DANE here.
        X509_STORE_CTX * st = X509_STORE_CTX_new();
        X509_STORE_CTX_init(st, store, cert, chain);
        // TODO : can I free some of this stuff now?
        //X509_STORE_free(store);
        //X509_free(cert);
        //sk_X509_free(chain); // Not pop free, apparently.
        X509_STORE_CTX_set0_param(st, vpm); // Hands ownership to st.
        ///X509_VERIFY_PARAM_free(vpm);
        int result = X509_verify_cert(st);
        X509_STORE_CTX_free(st);
        METRE_LOG(std::string("[Re]verify was ") + (result == X509_V_OK ? "SUCCESS" : "FAILURE"));
        return result == X509_V_OK;
    }
}