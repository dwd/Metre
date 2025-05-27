//
// Created by dwd on 9/19/24.
//

#include "config.h"
#include <iostream>

bool Metre::Config::run_healthcheck(unsigned short port, bool tls) {
    covent::Loop loop;

    const auto uri = std::format("{}://localhost:{}/api/status", tls ? "https" : "http", port);
    Config::config().logger().info("Healthcheck against {}", uri);

    covent::Service healthcheck_service;
    auto & entry = healthcheck_service.add("");
    entry.make_tls_context(tls, false, "");
    covent::http::Client client(healthcheck_service, uri);
    auto request = client.request(covent::http::Method::GET, uri);

    auto response = loop.run_task(request());

    if ((response->status() / 100) == 2) {
        return true;
    }
    std::cerr << "Healthcheck unhappy with " << response->status() << std::endl;
    return false;
}
