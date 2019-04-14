//
// Created by dwd on 14/05/17.
//

#ifndef METRE_SQL_H
#define METRE_SQL_H

#include <functional>
#include <memory>
#include "sigslot.h"
#include <postgresql/libpq-fe.h>

namespace Metre {
    class Database {
    protected:
        Database();

    public:
        Database &database();

        ~Database();

        class StatementBase {
            std::string m_statement;

        protected:
            StatementBase(std::string const &);

        public:
            virtual ~StatementBase();
        };

        class Row {

        };

        class Query {
        public:
            Query(StatementBase &statement);

            sigslot::signal<sigslot::thread::st, Row &> row;
            sigslot::signal<sigslot::thread::st, bool> complete;

            void completed(); // Throws a suitable exception.
        };

        template<typename ..._Types>
        class Statement : public StatementBase {
        public:
            Statement(std::string const &sql) : StatementBase(sql) {}

            std::unique_ptr<Query> execute(_Types...) {
                // Bind each parameter.
                return std::unique_ptr<Query>{new Query(*this)};
            }
        };

    };
}

#endif //METRE_SQL_H
