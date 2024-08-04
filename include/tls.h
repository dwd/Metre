/***

Copyright 2016 Dave Cridland
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


#ifndef METRE_TLS_H
#define METRE_TLS_H

#include <openssl/ossl_typ.h>
#include "defs.h"
#include "dns.h"


namespace Metre {
    bool tlsa_matches(DNS::TlsaRR const &rr, X509 *cert);

    sigslot::tasklet<bool> verify_tls(std::shared_ptr<sentry::span>, XMLStream &stream, Route &route);

    bool start_tls(XMLStream &stream, bool send_proceed);
}

#endif //METRE_TLS_H
