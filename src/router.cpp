#include "router.hpp"
#include "dns.hpp"
#include "xmlstream.hpp"
#include "netsession.hpp"

#include <iostream>
#include <unordered_map>

using namespace Metre;

Route::Route(Jid const & from, Jid const & to) : m_local(from), m_domain(to) {
  std::cout << "Route created, local is " << m_local.domain() << " remote is " << m_domain.domain() << std::endl;
}

namespace {
  bool check_verify(Route & r, std::shared_ptr<NetSession> const & vrfy) {
    if(vrfy) {
      if (vrfy->xml_stream().auth_ready()) {
        r.SessionDialback(vrfy->xml_stream());
        return true;
      } else {
        vrfy->xml_stream().onAuthReady.connect(&r, &Route::SessionDialback);
      }
    }
    return false;
  }


  bool check_to(Route & r, std::shared_ptr<NetSession> const & to) {
    if (to) {
      switch (to->xml_stream().s2s_auth_pair(r.local(), r.domain(), OUTBOUND)) {
      case XMLStream::AUTHORIZED:
        r.SessionAuthenticated(to->xml_stream());
        return true;
      default:
        if (!to->xml_stream().auth_ready()) {
          to->xml_stream().onAuthReady.connect(&r, &Route::SessionDialback);
        } else {
          /// Send a dialback request or something.
          std::string key = "validate-me";
          rapidxml::xml_document<> d;
          auto dbr = d.allocate_node(rapidxml::node_element, "db:result");
          dbr->append_attribute(d.allocate_attribute("to", r.domain().c_str()));
          dbr->append_attribute(d.allocate_attribute("from", r.local().c_str()));
          dbr->value(key.c_str(), key.length());
          d.append_node(dbr);
          to->xml_stream().send(d);
          to->xml_stream().s2s_auth_pair(r.local(), r.domain(), OUTBOUND, XMLStream::REQUESTED);
        }
      case XMLStream::REQUESTED:
        to->xml_stream().onAuthenticated.connect(&r, &Route::SessionAuthenticated);
      }
    }
    return false;
  }
}

void Route::transmit(std::unique_ptr<Verify> v) {
  if (!m_dialback.empty()) {
    m_dialback.push_back(std::move(v));
    return;
  }
  auto vrfy = m_vrfy.lock();
  if(check_verify(*this, vrfy)) {
    vrfy->xml_stream().send(std::move(v));
  } else {
    // TODO Look for an existing session and use that.
    // Otherwise, start SRV lookups.
    m_dialback.push_back(std::move(v));
    DNS::Resolver::resolver().SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  }

}
void Route::transmit(std::unique_ptr<Stanza> s) {
  if (!m_stanzas.empty()) {
    m_stanzas.push_back(std::move(s));
    return;
  }
  auto to = m_to.lock();
  if (check_to(*this, to)) {
    to->xml_stream().send(std::move(s));
  } else if (!to) {
    if(!m_vrfy.expired()) {
      std::shared_ptr<NetSession> vrfy(m_vrfy);
      m_to = vrfy;
      transmit(std::move(s)); // Retry
      return;
    }
    // TODO Look for an existing session, etc.
    std::shared_ptr<NetSession> dom = Router::session_by_domain(m_domain.domain());
    if (dom) {
      m_to = dom;
      transmit(std::move(s)); // Retry;
      return;
    }
    m_stanzas.push_back(std::move(s));
    std::cout << "Queued stanza (fallback) for " << m_local.domain() << "=>" << m_domain.domain() << std::endl;
    DNS::Resolver::resolver().SrvLookup(m_domain.domain()).connect(this, &Route::SrvResult);
  } else { // Got a to but it's not ready yet.
    std::cout << "Queued stanza (to) for " << m_local.domain() << "=>" << m_domain.domain() << std::endl;
    m_stanzas.push_back(std::move(s));
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
  std::shared_ptr<NetSession> sesh = Router::session_by_address((*m_rr).hostname, (*m_rr).port);
  if (sesh) {
    m_vrfy = sesh;
    check_verify(*this, sesh);
    if (m_to.expired()) m_to = sesh;
    check_to(*this, sesh);
    return;
  }
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
  vrfy = Router::connect(m_local.domain(), m_domain.domain(), (*m_rr).hostname, *m_arr, (*m_rr).port);
  std::cout << "Connected, " << &*vrfy << std::endl;
  vrfy->xml_stream().onAuthReady.connect(this, &Route::SessionDialback);
  m_vrfy = vrfy;
  if (m_to.expired()) {
    m_to = vrfy;
    check_to(*this, vrfy);
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
    if (m_to.expired()) {
      m_to = vrfy;
      check_to(*this, vrfy);
    }
  }
  auto to = m_to.lock();
  if (to) {
    if (&stream.session() == &*to && stream.s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::NONE) {
      std::cout << "Stream is to; needs dialback." << std::endl;
    }
  }
}

void Route::SessionAuthenticated(XMLStream & stream) {
  auto to = m_to.lock();
  std::cout << "Stream is ready for stanzas." << std::endl;
  if (&stream.session() == &*to && stream.s2s_auth_pair(m_local.domain(), m_domain.domain(), OUTBOUND) == XMLStream::AUTHORIZED) {
    std::cout << "This is the droid I am looking for." << std::endl;
    for (auto & s : m_stanzas) {
      to->xml_stream().send(std::move(s));
    }
    m_stanzas.clear();
  }
}

RouteTable & RouteTable::routeTable(std::string const & d) {
  static std::unordered_map<std::string,RouteTable> rt;
  auto it = rt.find(d);
  if (it != rt.end()) return (*it).second;
  auto itp = rt.emplace(d, d);
  return (*(itp.first)).second;
}

RouteTable & RouteTable::routeTable(Jid const & j) {
  return RouteTable::routeTable(j.domain());
}

std::shared_ptr<Route> & RouteTable::route(Jid const & to) {
  // TODO This needs to be more complex once we have clients.
  if (!m_routes[to.domain()]) {
    m_routes[to.domain()] = std::shared_ptr<Route>(new Route(m_local_domain, to));
  }
  return m_routes[to.domain()];
}

RouteTable::RouteTable(std::string const & d) : m_routes(), m_local_domain(d) {
}
