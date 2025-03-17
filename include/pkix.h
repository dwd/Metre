/***

Copyright 2016-2024 Dave Cridland
Copyright 2016 Surevine Ltd

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


#ifndef METRE_PKIX_H
#define METRE_PKIX_H

#include <openssl/ossl_typ.h>
#include <yaml-cpp/yaml.h>
#include "defs.h"
#include <covent/dns.h>


namespace Metre {
    covent::task<bool> verify_tls(XMLStream &stream, Route const &route);

    bool start_tls(XMLStream &stream, bool send_proceed);

}

#include "fmt-enum.h"

METRE_ENUM_FORMATTER(covent::dns::rr::TLSA::CertUsage,
                     METRE_ENUM_ENTRY_TXT(CertConstraint, "CertConstraint (PKIX-EE)")
                     METRE_ENUM_ENTRY_TXT(CAConstraint, "CAConstraint (PKIX-CA)")
                     METRE_ENUM_ENTRY_TXT(DomainCert, "DomainCert (DANE-EE)")
                     METRE_ENUM_ENTRY_TXT(TrustAnchorAssertion, "TrustAnchorAssertion (DANE-TA)")
 );

METRE_ENUM_FORMATTER(covent::dns::rr::TLSA::Selector,
                     METRE_ENUM_ENTRY(SubjectPublicKeyInfo)
                     METRE_ENUM_ENTRY(FullCert)
);

METRE_ENUM_FORMATTER(covent::dns::rr::TLSA::MatchType,
                     METRE_ENUM_ENTRY_TXT(Sha256, "SHA-256")
                     METRE_ENUM_ENTRY_TXT(Sha512, "SHA-512")
                     METRE_ENUM_ENTRY(Full)
);

#endif //METRE_PKIX_H
