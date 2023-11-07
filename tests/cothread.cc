#include "gtest/gtest.h"
#include <iostream>
#include <regex>
#include <coroutine>
#include <list>
#include "core.h"
#include "cothread.h"
#include <sigslot/sigslot.h>
#include <sigslot/tasklet.h>
#include "testfns.h"

sigslot::tasklet<bool> inner(std::string const & s) {
    std::cout << "Here!" << std::endl;
    Metre::CoThread<bool, std::string const &> thread1([](std::string const &s) {
        std::cout << "There 1! " << s << std::endl;
        return true;
    });
    Metre::CoThread<bool> thread2([]() {
        std::cout << "+ Launch" << std::endl;
        sleep(1);
        std::cout << "+ There 2!" << std::endl;
        sleep(1);
        std::cout << "+ End" << std::endl;
        return true;
    });
    std::cout << "Still here!" << std::endl;
    thread2.run();
    auto result1 = co_await thread1.run(s);
    std::cout << "Got result1:" << result1 << std::endl;
    auto result2 = co_await thread2;
    std::cout << "Got result2:" << result2 << std::endl;
    co_return true;
}

sigslot::tasklet<void> start() {
    std::string s = "Hello world!";
    auto result = co_await inner(s);
    std::cout << "Completed test with result " << result << std::endl;
}

TEST(CoThreadTest, Tests) {
    std::cout << "Start" << std::endl;
    auto coro = start();
    sigslot::resume(coro.coro);
    while(coro.running()) {
        Metre::Router::run_pending();
    }
    std::cout << "*** END ***" << std::endl;
}