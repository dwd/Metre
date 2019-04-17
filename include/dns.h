/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/

#ifndef METRE_DNS_H
#define METRE_DNS_H

#include "defs.h"
#include "sigslot.h"
#include <string>
#include <vector>
// For struct sockaddr_storage :
#ifdef METRE_UNIX
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

namespace Metre {

    namespace DNS {
        class SrvRR {
        public:
            std::string hostname;
            unsigned short port = 0;
            unsigned short weight = 0;
            unsigned short priority = 0;
            bool tls = false;
        };

        class Srv {
        public:
            bool xmpp;
            bool xmpps;
            std::vector<SrvRR> rrs;
            std::string domain;
            bool dnssec = false;
            std::string error;
            bool nxdomain = false;
        };

        class Address {
        public:
            bool ipv4 = false;
            bool ipv6 = false;
            std::vector<struct sockaddr_storage> addr;
            bool dnssec = false;
            std::string error;
            std::string hostname;
        };

        class TlsaRR {
        public:
            typedef enum {
                CAConstraint = 0,
                CertConstraint = 1,
                TrustAnchorAssertion = 2,
                DomainCert = 3
            } CertUsage;
            typedef enum {
                FullCert = 0,
                SubjectPublicKeyInfo = 1
            } Selector;
            typedef enum {
                Full = 0,
                Sha256 = 1,
                Sha512 = 2
            } MatchType;
            CertUsage certUsage;
            Selector selector;
            MatchType matchType;
            std::string matchData;
        };

        class Tlsa {
        public:
            std::string domain;
            std::string error;
            bool dnssec = false;

            std::vector<TlsaRR> rrs;
        };

    }
}

#endif
