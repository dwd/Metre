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

#include "feature.h"
#include "router.h"
#include "config.h"
#include "log.h"

using namespace Metre;
using namespace rapidxml;

namespace {
    const std::string bidi_feat_ns = "urn:xmpp:features:bidi";
    const std::string bidi_ns = "urn:xmpp:bidi";

    /**
     * Here, we advertise the feature, and if seen, we just (blindly) send a bidi request.
     * We don't need to do anything special aside from marking the stream bidirectional.
     */
    class Bidi : public Feature, public sigslot::has_slots {
    public:
        explicit Bidi(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<Bidi> {
        public:
            Description() : Feature::Description<Bidi>(bidi_feat_ns, Type::FEAT_PREAUTH) {};

            sigslot::tasklet<bool> offer(std::shared_ptr<sentry::span>, optional_ptr<xml_node<>>node, XMLStream &s) override {
                if (s.bidi()) co_return false;
                node->append_element({bidi_feat_ns, "bidi"});
                co_return
                true;
            }
        };

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction>, optional_ptr<rapidxml::xml_node<>> node) override {
            METRE_LOG(Metre::Log::DEBUG, "Handle BIDI");
            // We don't really handle it here, since we picked a different Namespace.
            // That was silly of us.
            co_return false;
        }

        bool negotiate(optional_ptr<rapidxml::xml_node<>>) override {
            xml_document<> d;
            d.append_element({bidi_ns, "bidi"});
            m_stream.send(d);
            m_stream.bidi(true);
            return false;
        }
    };

    /**
     * In this namespace, we handle inbound bidi requests.
     * Again, we don't actually need to do anything yet because we're not - yet - authenticated.
     */
    class BidiInbound : public Feature, public sigslot::has_slots {
    public:
        explicit BidiInbound(XMLStream &s) : Feature(s) {}

        class Description : public Feature::Description<BidiInbound> {
        public:
            Description() : Feature::Description<BidiInbound>(bidi_ns, Type::FEAT_PREAUTH) {};
        };

        sigslot::tasklet<bool> handle(std::shared_ptr<sentry::transaction>, optional_ptr<rapidxml::xml_node<>> node) override {
            METRE_LOG(Metre::Log::DEBUG, "Handle BIDI Inbound");
            m_stream.bidi(true);
            co_return true;
        }

        bool negotiate(optional_ptr<rapidxml::xml_node<>>) override {
            return false;
        }
    };

    DECLARE_FEATURE(Bidi, S2S);

    DECLARE_FEATURE(BidiInbound, S2S);
}
