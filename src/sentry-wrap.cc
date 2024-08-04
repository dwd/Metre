//
// Created by dwd on 8/2/24.
//

#include "sentry-wrap.h"
#include "log.h"

using namespace sentry;

transaction::transaction(const std::string &op_name, const std::string &description) {
    m_trans_ctx = sentry_transaction_context_new(description.c_str(), op_name.c_str());
    m_trans = sentry_transaction_start(m_trans_ctx, sentry_value_new_null());
}

void transaction::name(std::string const & n) {
    sentry_transaction_set_name(m_trans, n.c_str());
}

void transaction::end() {
    if (m_trans) {
        sentry_transaction_finish(m_trans);
        m_trans = nullptr;
    }
}

void transaction::terminate() {
    end();
}

void transaction::exception(std::exception_ptr const & eptr) {
    if (m_trans) {
        sentry_transaction_set_status(m_trans, sentry_span_status_t::SENTRY_SPAN_STATUS_INTERNAL_ERROR);
    }
}

transaction::~transaction() {
    if (m_trans) {
        auto eptr = std::current_exception();
        if (eptr) sentry_transaction_set_status(m_trans, sentry_span_status_t::SENTRY_SPAN_STATUS_INTERNAL_ERROR);
        end();
    }
}

std::shared_ptr<span> transaction::start_child(const std::string &op_name, const std::string &desc) {
    sentry_span_t * span_ptr = sentry_transaction_start_child(m_trans, op_name.c_str(), desc.c_str());
    return std::make_shared<span>(span_ptr, *this);
}

std::shared_ptr<span> span::start_child(const std::string &op_name, const std::string &desc) {
    sentry_span_t * span_ptr = sentry_span_start_child(m_span, op_name.c_str(), desc.c_str());
    return std::make_shared<span>(span_ptr, this->containing_transaction());
}

span::span(sentry_span_t *s, sentry::transaction & t) : m_span(s), m_trans(t) {}

void span::end() {
    if (m_span) {
        sentry_span_finish(m_span);
        m_span = nullptr;
    }
}

void span::terminate() {
    end();
}

void span::exception(std::exception_ptr const & eptr) {
    if (m_span) {
        sentry_span_set_status(m_span, sentry_span_status_t::SENTRY_SPAN_STATUS_INTERNAL_ERROR);
    }
}

span::~span() {
    if (m_span) {
        auto eptr = std::current_exception();
        if (eptr) sentry_span_set_status(m_span, sentry_span_status_t::SENTRY_SPAN_STATUS_INTERNAL_ERROR);
        end();
    }
}

