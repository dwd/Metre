#include "filter.h"

using namespace Metre;

namespace {
    class Spiffing : public Filter {
        class Description : public Filter::Description<Spiffing> {
            Description(std::string && name) : Filter::Description<Spiffing>(std::move(name)) {};
        };
        Spiffing(XMLStream & s) : Filter(s) {
        }
    };
}