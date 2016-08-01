#include <string>
#include <config.h>
#include <unistd.h>
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
        config.reset(new Metre::Config(bc->config_file));
        Metre::Router::reload();
        METRE_LOG(Metre::Log::INFO, "Reloading config.");
    }

    void term_handler(int s) {
        METRE_LOG(Metre::Log::INFO, "Shutdown received.");
        Metre::Router::quit();
    }
}

int main(int argc, char * argv[]) {
    // Firstly, load up the configuration.
    bc.reset(new BootConfig(argc, argv));
    config.reset(new Metre::Config(bc->config_file));
    if (bc->boot_method.empty()) {
        bc->boot_method = config->boot_method();
    }
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
        Metre::Router::main();
    } else if (bc->boot_method == "none") {
        config->log_init();
        signal(SIGPIPE, SIG_IGN);
        signal(SIGHUP, hup_handler);
        signal(SIGTERM, term_handler);
        signal(SIGINT, term_handler);
        Metre::Router::main();
    } else if (bc->boot_method == "systemd") {
        config->log_init(true);
        signal(SIGPIPE, SIG_IGN);
        signal(SIGHUP, hup_handler);
        signal(SIGTERM, term_handler);
        Metre::Router::main();
    } else {
        std::cerr << "I don't know what " << bc->boot_method << " means." << std::endl;
        return 1;
    }
    config.reset(nullptr);
    bc.reset(nullptr);
    return 0;
}

