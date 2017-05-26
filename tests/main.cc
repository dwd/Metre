#include "tests.h"
#include <iostream>
#include <memory>
#include <router.h>

Metre::Test::Test(std::string const & name) : m_name(name) {
	Metre::Test::add(this);
}
Metre::Test::~Test() {}
std::string const & Metre::Test::name() const { return m_name; }
std::list<Metre::Test*> & Metre::Test::tests() {
	static std::list<Test*> s_list;
	return s_list;
}
void Metre::Test::add(Metre::Test * t) {
	Metre::Test::tests().push_back(t);
}

int main(int argc, char *argv[]) {
	try {
		int r = 0;
		for (auto t : Metre::Test::tests()) {
			try {
				std::cout << "[" << t->name() << "] ";
				if (!t->run()) {
					r = 1;
					std::cout << " Failed (clean)\n";
				} else {
					std::cout << " OK\n";
				}
			} catch (std::runtime_error & e) {
				std::cout << "Failed (" << e.what() << ")" << std::endl;
				r = 1;
			} catch (...) {
				std::cout << "Unknown exception for " << t->name() << std::endl;
				r = 1;
			}
		}
		if (r) {
			std::cout << "Sum toasts fulled." << std::endl;
		} else {
			std::cout << "All toasts pissed." << std::endl;
		}
		return r;
	} catch(...) {
		std::cout << "Unknown exception\r\n";
	}
	return 1;
}
