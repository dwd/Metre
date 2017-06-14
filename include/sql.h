//
// Created by dwd on 14/05/17.
//

#ifndef METRE_SQL_H
#define METRE_SQL_H

#include <functional>
#include <memory>

namespace Metre {
    class Database {
    protected:
        Database()

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

        template<typename ..._Types>
        class Statement : public StatementBase {
        public:
            Statement(std::string const &sql) : StatementBase(sql) {}

            std::unique_ptr<Query> execute(...

            _Types) {
                // Bind each parameter.
            }
        };

        template<>
        class Statement : public StatementBase {
        public:
            Statement(std::string const &sql);

            std::unique_ptr<Query> execute();
        };

        class Query {

        };

    };
}

#endif //METRE_SQL_H
