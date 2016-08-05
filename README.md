Metre :: An XMPP Server (Sort Of)
=================================

Metre (check that spelling) is an XMPP Server, of sorts. Unlike traditional XMPP servers
which host services internally, Metre is specifically designed to connect between servers,
mediating connections and traffic.

It's written in C++11 (ie, modern C++), and aims to provide a semantically-aware filter
between domains, to avoid exposing your internal XMPP fully to the world.

You'll probably want to read the [FAQ](FAQ.md), and you may wish to find some
[BUILD](BUILD.md) instructions. The [LICENCE](LICENSE) is MIT, and the copyright
rests (mostly - see the [Base 64 code](src/base64.cc)) jointly with Surevine Ltd and
Dave Cridland.

In particular, this is not (yet) finished.

Currently working:
* Component hosting (XEP-0114)
* TLS
* X.509 auth (PKIX)
* Dialback and S2S
* Basic forwarding/routing
* DNSSEC (Including RFC 6125 additional reference identifiers)
* S2S <-> S2S proxying
* DNS overrides (SRV, A, and TLSA per-domain)
* DANE (including via TLSA overrides as above)

Currently poorly tested:
* Basic Filtering
* Daemonizing

Currently unimplemented but planned:
* Semantic filtering
* IPv6
