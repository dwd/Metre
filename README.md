Metre :: An XMPP Server (Sort Of)
=================================

Metre (check that spelling) is an XMPP Server, of sorts. Unlike traditional XMPP servers
which host services internally, Metre is specifically designed to connect between servers,
mediating connections and traffic.

It's written in C++11 (ie, modern C++), and aims to provide a semantically-aware filter
between domains, to avoid exposing your internal XMPP fully to the world.

You'll probably want to read the [FAQ](FAQ.md), and you may wish to find some
[BUILD](BUILD.md) instructions.

In particular, this is not (yet) finished.

Currently working:
* Component hosting (XEP-0114)
* TLS
* X.509 auth (PKIX)
* Dialback and S2S
* Basic forwarding/routing
* DNSSEC (Including RFC 6125 additional reference identifiers)

Currently poorly tested:
* S2S <-> S2S proxying
* Basic Filtering

Currently unimplemented but planned:
* DNS overrides (although A records are done)
* Semantic filtering
* DANE
* IPv6
* Daemonizing
