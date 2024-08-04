//
// Created by dwd on 8/2/24.
//

#include <string>
#include <memory>

#ifndef METRE_SENTRY_H
#define METRE_SENTRY_H

#ifdef METRE_SENTRY
#include "sentry.h"
#include "sigslot.h"
#include "sigslot/tasklet.h"

#endif

namespace sentry {
#ifndef METRE_SENTRY
    namespace detail {
        class dummy_raii {
        public:
            explicit dummy_raii(std::string const &, std::string const &) {};
            void name(std::string const &) {}
            std::shared_ptr<dummy_raii> start_child(std::string const &, std::string const&) { return {}; }
        };
    }
    using transaction = detail::dummy_raii;
    using span = detail::dummy_raii;
#else
    class scope;
    class span;
    class transaction;

    class scope : public sigslot::tracker {
    public:
        scope();
        void terminate() override;
        void exception(std::exception_ptr const &) override;
        ~scope();
    };

class span : public sigslot::tracker {
    sentry_span_t *  m_span = nullptr;
    transaction & m_trans;

    void end();
public:
    span(sentry_span_t * s, transaction & t);
    sentry::transaction  & containing_transaction() {
        return m_trans;
    }
    std::shared_ptr<span> start_child(std::string const & op_name, std::string const & desc);

    void terminate() override;
    void exception(std::exception_ptr const &) override;
    ~span();
};

class transaction : public sigslot::tracker {
    sentry_transaction_t * m_trans;
    sentry_transaction_context_t * m_trans_ctx;

    void end();
public:
    transaction(std::string const & op_name, std::string const & description);
    void name(std::string const &);
    std::shared_ptr<span> start_child(std::string const & op_name, std::string const & desc);

    void terminate() override;
    void exception(std::exception_ptr const &) override;
    ~transaction() override;
};
#endif
}

#endif //METRE_SENTRY_H
