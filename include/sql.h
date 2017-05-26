//
// Created by dwd on 14/05/17.
//

#ifndef METRE_SQL_H
#define METRE_SQL_H

#include <functional>
#include <memory>

struct sqlite3;
struct sqlite3_stmt;

namespace Metre {
    class SqlDB {
        std::unique_ptr<sqlite3, std::function<void(sqlite3 *)>> m_db;

    };
}

#endif //METRE_SQL_H
