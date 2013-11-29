#include "jid.hpp"
#include "tests.hpp"

using namespace Metre;

class JidTest : public Test {
public:
	JidTest() : Test("Jid") {}
	bool run() {
		Jid one("dwd", "dave.cridland.net");
		assert::equal(one.full(), "dwd@dave.cridland.net", "bare/full");
		assert::equal(one.bare(), "dwd@dave.cridland.net", "bare/bare");
		Jid two("dwd", "dave.cridland.net", "Resource");
		assert::equal(two.bare(), "dwd@dave.cridland.net", "full/bare");
		assert::equal(two.full(), "dwd@dave.cridland.net/Resource", "full/full");
		return true;
	}
};

namespace {
	JidTest jidtest;
}
