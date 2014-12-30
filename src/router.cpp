#include "router.hpp"
#include "dns.hpp"
#include "xmlstream.hpp"
#include "netsession.hpp"

#include <iostream>

using namespace Metre;

Route::Route(Jid const & to) : m_domain(to) {
}

void Route::transmit(std::unique_ptr<Verify> v) {
  if(m_vrfy) {
    m_vrfy->xml_stream().send(std::move(v));
  } else {
    // TODO Look for an existing session and use that.
    // Otherwise, start SRV lookups.
    m_dialback.push_back(std::move(v));
    DNS::Resolver::resolver().SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  }
}

void Route::SrvResult(DNS::Srv const * srv) {
  std::cout << "Got SRV" << std::endl;
  if (m_vrfy) {
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
  std::cout << "Now what?" << std::endl;
  if (m_vrfy) {
    return;
  }
  if (!addr->error.empty()) {
    std::cout << "Got an error during DNS: " << addr->error << std::endl;
    return;
  }
  m_addr = *addr;
  m_arr = m_addr.addr4.begin();
  m_vrfy = Router::connect("cridland.im", m_domain.domain(), (*m_rr).hostname, *m_arr, (*m_rr).port);
  std::cout << "Connected, " << &*m_vrfy << std::endl;
  // _vrfy->xml_stream().onSecured.connect(this, &Route::SessionSecured);
  // m_vrfy->connected.connect(...);
}

void Route::SessionDialback(XMLStream & stream) {
  std::cout << "Stream is secured." << std::endl;
  if (&stream.session() == &*m_vrfy) {
    std::cout << "This is the droid I am looking for." << std::endl;
    for (auto & v : m_dialback) {
      m_vrfy->xml_stream().send(std::move(v));
    }
    m_dialback.clear();
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
