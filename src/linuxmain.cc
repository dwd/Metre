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
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <log.h>
#include <signal.h>
#include <fstream>
#include <router.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>

namespace {
    class BootConfig {
    public:
        std::string config_file = "./metre.conf.yml";
        std::string boot_method = "";

        BootConfig(int argc, char *argv[]) {
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
                    default:
                        std::cerr << "Unknown switch " << opt << std::endl;
                        exit(2);
                }
            }
        }
    };

    std::unique_ptr<BootConfig> bc;
    std::unique_ptr<Metre::Config> config;

    void hup_handler(int) {
        //config.reset(new Metre::Config(bc->config_file));
        //Metre::Router::reload();
        METRE_LOG(Metre::Log::INFO, "NOT Reloading config.");
    }

    void term_handler(int) {
        METRE_LOG(Metre::Log::INFO, "Shutdown received.");
        Metre::Router::quit();
    }

    void terminate_handler() {
        unw_cursor_t cursor;
        unw_context_t uc;

        unw_getcontext(&uc);
        unw_init_local(&cursor, &uc);
        auto eptr = std::current_exception();
        if (eptr) {
            try {
                std::rethrow_exception(eptr);
            } catch(const std::runtime_error & e) {
                std::cerr << "Uncaught runtime_error: " << e.what() << std::endl;
            } catch(const std::exception & e) {
                std::cerr << "Uncaught exception: " << e.what() << std::endl;
            } catch(...) {
                std::cerr << "Unknown exception caught" << std::endl;
            }
        } else {
            std::cerr << "std::terminate called with no exception" << std::endl;
        }
        while (unw_step(&cursor) > 0) {
            unw_word_t ip;
            unw_word_t sp;
            unw_get_reg(&cursor, UNW_REG_IP, &ip);
            unw_get_reg(&cursor, UNW_REG_SP, &sp);
            std::array<char, 1024> buffer;
            unw_word_t offset;
            unw_get_proc_name(&cursor, buffer.data(), buffer.size(), &offset);
            std::string proc_name(buffer.data());
            std::cerr << "ip = " << std::ios::hex << ip << ", sp = " << sp << ", " << proc_name << "+" << offset << std::ios::dec << std::endl;
        }
        std::abort();
    }

    void segv_handler(int s) {
        METRE_LOG(Metre::Log::INFO, "Fatal signal " << s);
        terminate_handler();
    }
}

int main(int argc, char *argv[]) {
    try {
        // Firstly, load up the configuration.
        std::set_terminate(terminate_handler);
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
        if (bc->boot_method == "sysv") {
            pid_t child = fork();
            if (child == -1) {
                std::cerr << "Fork failed: " << strerror(errno) << std::endl;
                exit(1);
            }
            if (child != 0) {
                // This is the parent; we exit here.
                return 0;
            }
            // We are the new child. Close fds, session, etc.
            close(0);
            close(1);
            close(2);
            config->log_init();
            config->write_runtime_config();
            if (-1 == setsid()) {
                METRE_LOG(Metre::Log::CRIT, "setsid() failed with " << strerror(errno));
            }
            // Now fork again. Like we did last summer.
            child = fork();
            if (child == -1) {
                METRE_LOG(Metre::Log::CRIT, "fork(2) failed with " << strerror(errno));
                exit(1);
            }
            if (child != 0) {
                std::ofstream pidfile(config->pidfile(), std::ios_base::trunc);
                pidfile << child << std::endl;
                return 0;
            }
            chdir(config->runtime_dir().c_str());
            signal(SIGPIPE, SIG_IGN);
            signal(SIGHUP, hup_handler);
            signal(SIGTERM, term_handler);
            signal(SIGSEGV, segv_handler);
            signal(SIGBUS, segv_handler);
            Metre::Router::main([]() { return false; });
        } else if (bc->boot_method == "none") {
            config->log_init(true);
            config->write_runtime_config();
            signal(SIGPIPE, SIG_IGN);
            signal(SIGHUP, hup_handler);
            signal(SIGTERM, term_handler);
            signal(SIGINT, term_handler);
            signal(SIGSEGV, segv_handler);
            signal(SIGBUS, segv_handler);
            Metre::Router::main([]() { return false; });
        } else if (bc->boot_method == "docker") {
            config->docker_setup();
            config->write_runtime_config();
            signal(SIGPIPE, SIG_IGN);
            signal(SIGHUP, hup_handler);
            signal(SIGTERM, term_handler);
            signal(SIGINT, term_handler);
            signal(SIGSEGV, segv_handler);
            signal(SIGBUS, segv_handler);
            Metre::Router::main([]() { return false; });
        } else if (bc->boot_method == "systemd") {
            config->log_init(true);
            config->write_runtime_config();
            signal(SIGPIPE, SIG_IGN);
            signal(SIGHUP, hup_handler);
            signal(SIGTERM, term_handler);
            signal(SIGSEGV, segv_handler);
            signal(SIGBUS, segv_handler);
            Metre::Router::main([]() { return false; });
        } else {
            std::cerr << "I don't know what " << bc->boot_method << " means." << std::endl;
            return 1;
        }
    } catch (std::runtime_error const &e) {
        std::cerr << "Error while loading config: " << e.what() << std::endl;
        return 2;
    }
    config.reset(nullptr);
    bc.reset(nullptr);
    return 0;
}

