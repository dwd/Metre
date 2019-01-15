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

#include <string>
#include <config.h>
#include <iostream>
#include <string.h>
#include <log.h>
#include <signal.h>
#include <fstream>
#include <router.h>

namespace {
    class BootConfig {
    public:
        std::string config_file;
        std::string boot_method;

        BootConfig(int argc, char *argv[])
                : config_file("./metre.conf.xml"), boot_method() {
            for (int i = 1; argv[i]; ++i) {
                char opt;
                switch (argv[i][0]) {
                    case '-':
                    case '/':
                        opt = argv[i][1];
                        break;
                    default:
                        std::cerr << "Don't understand commandline arg " << argv[i] << std::endl;
                        exit(2);
                }
                ++i;
                if (!argv[i]) {
                    std::cerr << "Missing argument for option '" << opt << "'" << std::endl;
                    exit(2);
                }
                switch (opt) {
                    case 'c':
                        config_file = argv[i];
                        break;
                    case 'd':
                        boot_method = argv[i];
                        break;
                }
            }
        }
    };

    std::unique_ptr<BootConfig> bc;
    std::unique_ptr<Metre::Config> config;

    void hup_handler(int s) {
        //config.reset(new Metre::Config(bc->config_file));
        //Metre::Router::reload();
        METRE_LOG(Metre::Log::INFO, "NOT Reloading config.");
    }

    void term_handler(int s) {
        METRE_LOG(Metre::Log::INFO, "Shutdown received.");
        Metre::Router::quit();
    }
}

int main(int argc, char *argv[]) {
    try {
        // Firstly, load up the configuration.
        bc = std::make_unique<BootConfig>(argc, argv);
        config = std::make_unique<Metre::Config>(bc->config_file);
        if (bc->boot_method.empty()) {
            bc->boot_method = config->boot_method();
        }
    } catch (std::runtime_error &e) {
        std::cout << "Error while loading config: " << e.what() << std::endl;
        return 1;
    }
    try {
        if (bc->boot_method == "none") {
            config->log_init();
            Metre::Router::main();
        } else {
            std::cerr << "I don't know what " << bc->boot_method << " means." << std::endl;
            return 1;
        }
    } catch (std::runtime_error &e) {
        std::cout << "Error while loading config: " << e.what() << std::endl;
        return 2;
    }
    config.reset(nullptr);
    bc.reset(nullptr);
    return 0;
}

