#include "router.hpp"
#include "dns.hpp"
#include "xmlstream.hpp"
#include "netsession.hpp"

#include <iostream>

using namespace Metre;

Route::Route(Jid const & to) : m_domain(to) {
}

void Route::transmit(std::unique_ptr<Verify> v) {
  auto vrfy = m_vrfy.lock();
  if(vrfy) {
    if (vrfy->xml_stream().auth_ready()) {
      vrfy->xml_stream().send(std::move(v));
    } else {
      vrfy->xml_stream().onAuthReady.connect(this, &Route::SessionDialback);
    }
  } else {
    // TODO Look for an existing session and use that.
    // Otherwise, start SRV lookups.
    m_dialback.push_back(std::move(v));
    DNS::Resolver::resolver().SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  }
}

void Route::transmit(std::unique_ptr<Stanza> s) {
  auto to = m_to.lock();
  if (to) {
    switch (to->xml_stream().s2s_auth_pair("cridland.im", m_domain.domain(), OUTBOUND)) {
    case XMLStream::AUTHORIZED:
      to->xml_stream().send(std::move(s));
      break;
    default:
      if (!to->xml_stream().auth_ready()) {
        to->xml_stream().onAuthReady.connect(this, &Route::SessionDialback);
        return;
      } else {
        /// Send a dialback request or something.
        std::string key = "validate-me";
        rapidxml::xml_document<> d;
        auto dbr = d.allocate_node(rapidxml::node_element, "db:result");
        dbr->append_attribute(d.allocate_attribute("to", m_domain.domain().c_str()));
        dbr->append_attribute(d.allocate_attribute("from", "cridland.im"));
        dbr->value(key.c_str(), key.length());
        d.append_node(dbr);
        to->xml_stream().send(d);
        to->xml_stream().s2s_auth_pair("cridland.im", m_domain.domain(), OUTBOUND, XMLStream::REQUESTED);
      }
    case XMLStream::REQUESTED:
      m_stanzas.push_back(std::move(s));
      to->xml_stream().onAuthenticated.connect(this, &Route::SessionAuthenticated);
    }
  } else {
    if(!m_vrfy.expired()) {
      std::shared_ptr<NetSession> vrfy(m_vrfy);
      m_to = vrfy;
      transmit(std::move(s)); // Retry
      return;
    }
    // TODO Look for an existing session, etc.
    m_stanzas.push_back(std::move(s));
    DNS::Resolver::resolver().SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  }
}

void Route::SrvResult(DNS::Srv const * srv) {
  auto vrfy = m_vrfy.lock();
  std::cout << "Got SRV" << std::endl;
  if (vrfy) {
    return;
  }
  m_srv = *srv;
  if (!m_srv.error.empty()) {
    std::cout << "Got an error during DNS: " << m_srv.error << std::endl;
    return;
  }
  m_rr = m_srv.rrs.begin();
  // TODO Look for an existing host/port session and use that.
  std::cout << "Should look for " << (*m_rr).hostname << ":" << (*m_rr).port << std::endl;
  // TODO Otherwise, start address lookups.
  DNS::Resolver::resolver().AddressLookup((*m_rr).hostname).connect(this, &Route::AddressResult);
}

void Route::AddressResult(DNS::Address const * addr) {
  auto vrfy = m_vrfy.lock();
  std::cout << "Now what?" << std::endl;
  if (vrfy) {
    return;
  }
  if (!addr->error.empty()) {
    std::cout << "Got an error during DNS: " << addr->error << std::endl;
    return;
  }
  m_addr = *addr;
  m_arr = m_addr.addr4.begin();
  vrfy = Router::connect("cridland.im", m_domain.domain(), (*m_rr).hostname, *m_arr, (*m_rr).port);
  std::cout << "Connected, " << &*vrfy << std::endl;
  vrfy->xml_stream().onAuthReady.connect(this, &Route::SessionDialback);
  m_vrfy = vrfy;
  if (m_to.expired()) {
    m_to = vrfy;
    vrfy->xml_stream().onAuthenticated.connect(this, &Route::SessionAuthenticated);
  }
  // m_vrfy->connected.connect(...);
}

void Route::SessionDialback(XMLStream & stream) {
  auto vrfy = m_vrfy.lock();
  std::cout << "Stream is ready for dialback." << std::endl;
  if (vrfy && &stream.session() == &*vrfy) {
    std::cout << "This is the droid I am looking for." << std::endl;
    for (auto & v : m_dialback) {
      vrfy->xml_stream().send(std::move(v));
    }
    m_dialback.clear();
  }
  auto to = m_to.lock();
  if (to && &stream.session() == &*to && stream.s2s_auth_pair("cridland.im", m_domain.domain(), OUTBOUND) == XMLStream::NONE) {
    std::cout << "Stream is to; needs dialback." << std::endl;
  }
}

void Route::SessionAuthenticated(XMLStream & stream) {
  auto to = m_to.lock();
  std::cout << "Stream is ready for stanzas." << std::endl;
  if (&stream.session() == &*to && stream.s2s_auth_pair("cridland.im", m_domain.domain(), OUTBOUND) == XMLStream::AUTHORIZED) {
    std::cout << "This is the droid I am looking for." << std::endl;
    for (auto & s : m_stanzas) {
      to->xml_stream().send(std::move(s));
    }
    m_stanzas.clear();
  }
}

RouteTable & RouteTable::routeTable() {
  static RouteTable rt;
  return rt;
}

std::shared_ptr<Route> & RouteTable::route(Jid const & to) {
  // TODO This needs to be more complex once we have clients.
  if (!m_routes[to.domain()]) {
    m_routes[to.domain()] = std::shared_ptr<Route>(new Route(to));
  }
  return m_routes[to.domain()];
}
