#include "jid.h"
#include "gtest/gtest.h"
#include <iostream>

using namespace Metre;

TEST(JidTest, Tests) {
		Jid one("dwd", "dave.cridland.net");
    ASSERT_EQ(one.full(), "dwd@dave.cridland.net");
    ASSERT_EQ(one.bare(), "dwd@dave.cridland.net");
		Jid two("dwd", "dave.cridland.net", "Resource");
    ASSERT_EQ(two.bare(), "dwd@dave.cridland.net");
    ASSERT_EQ(two.full(), "dwd@dave.cridland.net/Resource");
		Jid three("dwd@DAVE.CRIDLAND.NET/Resource");
    ASSERT_EQ(three.domain(), "dave.cridland.net");
    ASSERT_EQ(three.bare(), "dwd@dave.cridland.net");
    ASSERT_EQ(three.full().length(), std::string("dwd@dave.cridland.net/Resource").length());
    ASSERT_EQ(three.full(), "dwd@dave.cridland.net/Resource");
}
