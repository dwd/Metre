#ifndef ELOQUENCE_TESTS__H
#define ELOQUENCE_TESTS__H

#include <list>
#include <string>
#include <stdexcept>

namespace Metre {
	namespace assert {
		template <typename T1, typename T2>
		void equal(T1 const & t1, T2 const & t2, const char * c) {
			if (t1 != t2) throw std::runtime_error(c);
			if (t2 != t1) throw std::runtime_error(c);
		}
	}

	class Test {
		std::string m_name;
	public:
		Test(std::string const & name);
		virtual ~Test();
		std::string const & name() const;

		static std::list<Test *> & tests();
		virtual bool run() = 0;
	private:
		static void add(Test *);
	};
}

#endif
