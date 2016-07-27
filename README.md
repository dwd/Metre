Metre :: An XMPP Server (Sort Of)
=================================

Metre (check that spelling) is an XMPP Server, of sorts. Unlike traditional XMPP servers
which host services internally, Metre is specifically designed to connect between servers,
mediating connections and traffic.

It's written in C++11 (ie, modern C++), and aims to provide a semantically-aware filter
between domains, to avoid exposing your internal XMPP fully to the world.

It's also barely started. So don't use it unless you're a bleeding-edge trunk monkey.

Currently working:
* Component hosting (XEP-0114)
* TLS
* Dialback and S2S
* Basic forwarding/routing

Currently poorly tested:
* X.509 auth
* S2S <-> S2S proxying
* Basic Filtering

Currently unimplemented but planned:
* DNS overrides
* Semantic filtering
