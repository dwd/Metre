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

#ifndef ELOQUENCE_TESTS__H
#define ELOQUENCE_TESTS__H

#include <list>
#include <string>
#include <stdexcept>
#include <iostream>

namespace Metre {
    namespace assert {
        template<typename T1, typename T2>
        void equal(T1 const &t1, T2 const &t2, const char *c) {
            if (t1 != t2) throw std::runtime_error(c);
            if (t2 != t1) throw std::runtime_error(c);
        }
    }

    class Test {
        std::string m_name;
    public:
        Test(std::string const &name);

        virtual ~Test();

        std::string const &name() const;

        static std::list<Test *> &tests();

        virtual bool run() = 0;

    private:
        static void add(Test *);
    };
}

#endif
