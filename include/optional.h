#ifndef OPTIONAL__H
#define OPTIONAL__H

#include <stdexcept>

namespace std {
	template<typename T>
	class optional {
		char m_void[sizeof(T)];
		bool m_engaged = false;
	private:
		void doset(T const & t) {
			new(m_void) T(t);
			m_engaged = true;
		}
		void dounset() {
			reinterpret_cast<T *>(&m_void)->~T();
			m_engaged = false;
		}
		T * real() {
			if (!m_engaged) throw std::runtime_error("Deref when unengaged");
			return reinterpret_cast<T *>(&m_void);
		}
		T const * real() const {
			if (!m_engaged) throw std::runtime_error("Deref when unengaged");
			return reinterpret_cast<T const *>(&m_void);
		}
	public:
		optional(T const & t) {
			doset(t);
		}
		optional() {
		}
		optional(optional<T> const & t) {
			if (t.m_engaged) doset(t.value());
		}
		template<class... Args>
		void emplace(Args&&... args) {
			if (m_engaged) {
				dounset();
			}
			new(m_void) T(args...);
			m_engaged = true;
		}
		T & operator * () {
			return *real();
		}
		T * operator -> () {
			return real();
		}
		T & value() {
			return *real();
		}
		T const & operator * () const {
			return *real();
		}
		T const * operator -> () const {
			return real();
		}
		T const & value() const {
			return *real();
		}
		operator bool () const {
			return m_engaged;
		}
		optional<T> & operator = (T const & t) {
			if (m_engaged) dounset();
			doset(t);
			return *this;
		}
		optional<T> & operator = (optional<T> const & t) {
			if (m_engaged) dounset();
			doset(t.value());
			return *this;
		}
	};
}

#endif
