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
#include <cxxabi.h>

#include "event2/event.h"
#include "event2/http.h"
#include "event2/buffer.h"

#ifdef METRE_SENTRY
#include "sentry.h"
#endif

namespace {
    class BootConfig {
    public:
        std::string config_file = "./metre.conf.yml";
        std::string boot_method = "";

        BootConfig(int argc, char *argv[]) {
            const char * env_conf_file = getenv("METRE_CONF_YML");
            if (env_conf_file) config_file = env_conf_file;
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

    const char * demangle(const char * input) {
        static std::array<char, 2048> buffer;
        int status = -4;
        std::size_t length = 2048;
        abi::__cxa_demangle(input, buffer.data(), &length, &status);
        if (status == 0) {
            buffer[length] = 0;
            return buffer.data();
        }
        return input;
    }

#ifdef METRE_SENTRY
    void patch_stacktrace(sentry_value_t & stacktrace, unw_cursor & cursor)
    {
        void *walked_backtrace[256];
        void **ips = nullptr;
        size_t len = 0;
        std::array<char, 2048> buffer;
        unw_word_t offset;
        const std::string sigaction{"__sigaction"};
        const std::string cxa_throw{"__cxa_throw"};
        size_t strip = 0;

        // if nobody gave us a backtrace, walk now.
        if (!ips) {
            len = sentry_unwind_stack(NULL, walked_backtrace, 256);
            ips = walked_backtrace;
        }

        sentry_value_t frames = sentry_value_get_by_key(stacktrace, "frames");
        for (size_t i = 0; i < len; i++) {
            sentry_value_t frame = sentry_value_get_by_index(frames, i);
            unw_set_reg(&cursor, UNW_REG_IP, (uint64_t)(size_t)ips[len - i - 1]);
            if (unw_get_proc_name(&cursor, buffer.data(), buffer.size(), &offset) == 0) {
                auto name = demangle(buffer.data());
                sentry_value_set_by_key(frame, "function", sentry_value_new_string(name));
                if (name == sigaction || name == cxa_throw) {
                    strip = i;
                }
            }
        }

        if (strip) {
            while(sentry_value_get_length(frames) != strip) {
                sentry_value_remove_by_index(frames, sentry_value_get_length(frames) - 1);
            }
        }
    }

#endif

    void bug_reporter(const char * deftype, const char * detail) {
        unw_cursor_t cursor;
        unw_context_t uc;

        unw_getcontext(&uc);
        unw_init_local(&cursor, &uc);
#ifdef METRE_SENTRY
        auto ev = sentry_value_new_event();
        sentry_value_t exc;
        sentry_value_t stacktrace = sentry_value_new_stacktrace(nullptr, 0);
        patch_stacktrace(stacktrace, cursor);
#endif
        auto eptr = std::current_exception();
        if (eptr) {
            try {
                std::rethrow_exception(eptr);
            } catch(const std::runtime_error & e) {
                std::cerr << "Uncaught runtime_error: " << e.what() << std::endl;
#ifdef METRE_SENTRY
                exc = sentry_value_new_exception(demangle(typeid(e).name()), e.what());
#endif
            } catch(const std::exception & e) {
                std::cerr << "Uncaught exception: " << e.what() << std::endl;
#ifdef METRE_SENTRY
                exc = sentry_value_new_exception(demangle(typeid(e).name()), e.what());
#endif
            } catch(...) {
                std::cerr << "Unknown exception caught" << std::endl;
#ifdef METRE_SENTRY
                exc = sentry_value_new_exception(demangle(abi::__cxa_current_exception_type()->name()), "Unknown exception at std::terminate");
#endif
            }
        } else {
            std::cerr << "std::terminate called with no exception" << std::endl;
#ifdef METRE_SENTRY
            exc = sentry_value_new_exception(deftype, detail);
#endif
        }
#ifdef METRE_SENTRY
        // We'll use libunwind to patch up the stack trace locally, since we can:

        sentry_value_set_by_key(exc, "stacktrace", stacktrace);
        sentry_event_add_exception(ev, exc);
        sentry_capture_event(ev);
        sentry_close(); // A bit hopeful at this point.
#endif

        while (unw_step(&cursor) > 0) {
            unw_word_t ip;
            unw_word_t sp;
            unw_get_reg(&cursor, UNW_REG_IP, &ip);
            unw_get_reg(&cursor, UNW_REG_SP, &sp);
            std::array<char, 2048> buffer;
            unw_word_t offset;
            unw_get_proc_name(&cursor, buffer.data(), buffer.size(), &offset);
            std::cerr << "ip = " << std::ios::hex << ip << ", sp = " << sp << ", " << demangle(buffer.data()) << "+" << offset << std::ios::dec << std::endl;
        }
        std::abort();
    }

    void segv_handler(int s) {
        METRE_LOG(Metre::Log::INFO, "Fatal signal " << s);
        bug_reporter(sigabbrev_np(s), sigdescr_np(s));
    }

    void terminate_handler() {
        bug_reporter("std::terminate", "Termination function called");
    }

    bool healthcheck_response = false;

    void request_callback(struct evhttp_request* req, void* arg) {
        if (req) {
            int response_code = evhttp_request_get_response_code(req);
            if (response_code == HTTP_OK) {
                healthcheck_response = true;
                std::cerr << "Healthcheck is happy bunny" << std::endl;
            } else {
                std::cerr << "Healthcheck failure, status code " << response_code << std::endl;
            }
        } else {
            std::cerr << "Healthcheck received no response." << std::endl;
        }
        event_base_loopbreak((struct event_base*)arg);
    }


    bool healthcheck(unsigned short port) {
        struct event_base* base = event_base_new();
        struct evhttp_connection* conn = evhttp_connection_base_new(base, nullptr, "127.0.0.1", port);
        struct evhttp_request* req = evhttp_request_new(request_callback, base);

        // Set the request path (e.g., "/api/status")
        evhttp_make_request(conn, req, EVHTTP_REQ_GET, "/api/status");

        event_base_dispatch(base);

        evhttp_connection_free(conn);
        event_base_free(base);

        return healthcheck_response;
    }
}

int main(int argc, char *argv[]) {
#ifdef METRE_SENTRY
    auto sentry_options = sentry_options_new();
    sentry_options_set_traces_sample_rate(sentry_options, 1.0);
    sentry_init(sentry_options);
#endif
    std::set_terminate(terminate_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, hup_handler);
    signal(SIGTERM, term_handler);
    signal(SIGINT, term_handler);
    signal(SIGSEGV, segv_handler);
    signal(SIGBUS, segv_handler);
    // Firstly, load up the configuration.
    bc = std::make_unique<BootConfig>(argc, argv);
    std::cout << "Trying to load config from " << bc->config_file <<std::endl;
    auto config_lite = std::make_unique<Metre::Config>(bc->config_file, true);
    if (bc->boot_method.empty()) {
        bc->boot_method = config->boot_method();
    }
    if (bc->boot_method == "healthcheck") {
        if (healthcheck(config_lite->healthcheck_port())) {
            exit(0);
        } else {
            exit(1);
        }
    }
    config = std::make_unique<Metre::Config>(bc->config_file);
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
    config.reset(nullptr);
    bc.reset(nullptr);
#ifdef METRE_SENTRY
    sentry_close();
#endif
    return 0;
}

