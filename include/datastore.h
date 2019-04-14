//
// Created by dwd on 13/05/17.
//

#ifndef METRE_DATASTORE_H_H
#define METRE_DATASTORE_H_H

#include <string>
#include <event2/event.h>
#include <functional>
#include "sigslot.h"
#include <map>
#include <optional>

namespace Metre {
    class Datastore {
    public:
        ~Datastore();

        static Datastore &datastore();

        typedef std::function<void(std::optional<std::string> const &)> callback;

        void get(std::string const &scope, std::string const &node, callback const &fn) const;

        void
        get(std::string const &scope, std::string const &node, std::string const &item_id, callback const &fn) const;

        void set(std::string const &scope, std::string const &node, std::string const &item_id, std::string const &item,
                 callback const &fn);

        void del(std::string const &scope, std::string const &node, std::string const &item_id, callback const &fn);

        sigslot::signal<std::string, std::string, std::string, std::string> changed; // scope, node, item_id, item

    private:
        Datastore();

        Datastore(Datastore const &) = delete;

        Datastore(Datastore &&) = delete;

        std::optional<std::string> m_empty;

        // Fake, temporary, implementation:
        typedef std::map<std::string, std::string> itemmap;
        typedef std::map<std::string, itemmap> nodemap;
        typedef std::map<std::string, nodemap> scopemap;
        scopemap m_scopes;
    };
}

#endif //METRE_DATASTORE_H_H
