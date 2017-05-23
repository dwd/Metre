//
// Created by dwd on 13/05/17.
//

#include "datastore.h"
#include <router.h>

using namespace Metre;

Datastore::Datastore() : m_empty() {
}

Datastore::~Datastore() {
}

void Datastore::get(std::string const &scope, std::string const &node, std::string const &item_id,
                    callback const &fn) const {
    Router::defer([fn, this]() {
        fn(m_empty);
    });
}

void Datastore::set(std::string const &scope, std::string const &node, std::string const &item_id,
                    std::string const &item, callback const &fn) {
    changed.emit(scope, node, item_id, item);
}

void Datastore::get(std::string const &scope, std::string const &node, callback const &fn) const {
    Router::defer([fn, this]() {
        fn(m_empty);
    });
}

void Datastore::del(std::string const &scope, std::string const &node, std::string const &item_id,
                    callback const &fn) {
    changed.emit(scope, node, item_id, "");
}

Datastore &Datastore::datastore() {
    static Datastore s_datastore;
    return s_datastore;
}
