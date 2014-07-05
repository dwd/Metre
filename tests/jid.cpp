#include "jid.hpp"
#include "tests.hpp"
#include <iostream>

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
		Jid three("dwd@dave.cridland.net/Resource");
		assert::equal(three.domain(), "dave.cridland.net", "parsed/domain");
		assert::equal(three.bare(), "dwd@dave.cridland.net", "parsed/bare");
		assert::equal(three.full().length(), std::string("dwd@dave.cridland.net/Resource").length(), "parsed/full");
		assert::equal(three.full(), "dwd@dave.cridland.net/Resource", "parsed/full");
		return true;
	}
};

namespace {
	JidTest jidtest;
}
