#include "router.hpp"
#include "dns.hpp"

#include <iostream>

using namespace Metre;

Route::Route(Jid const & to) : m_domain(to) {
}

void Route::transmit(Verify const & v) {
  if(m_vrfy) {
    // TODO Just send it.
  } else {
    // TODO Look for an existing session and use that.
    // TODO Otherwise, start SRV lookups.
    DNS::Resolver::resolver().SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  }
}

void Route::SrvResult(DNS::Srv srv) {
  std::cout << "Got SRV" << std::endl;
  if (m_vrfy) {
    // Hey, we connected already!
    return;
  }
  m_srv = srv;
  // TODO For each record,
  if (!m_srv.error.empty()) {
    std::cout << "Got an error during DNS: " << m_srv.error << std::endl;
    return;
  }
  m_rr = srv.rrs.begin();
  // TODO Look for an existing host/port session and use that.
  std::cout << "Should look for " << (*m_rr).hostname << ":" << (*m_rr).port << std::endl;
  // TODO Otherwise, start address lookups.
  DNS::Resolver::resolver().AddressLookup((*m_rr).hostname).connect(this, &Route::AddressResult);
}

void Route::AddressResult(DNS::Address addr) {
  std::cout << "Now what?" << std::endl;
  if (m_vrfy) {
    // Hey, we connected already!
    return;
  }
  if (!addr.error.empty()) {
    std::cout << "Got an error during DNS: " << addr.error << std::endl;
    return;
  }
  m_addr = addr;
  m_arr = addr.addr4.begin();
  m_vrfy = Router::connect("cridland.im", m_domain.domain(), (*m_rr).hostname, *m_arr, (*m_rr).port);
  // m_vrfy->closed.connect(...);
  // m_vrfy->connected.connect(...);
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
