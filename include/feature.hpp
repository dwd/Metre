#ifndef FEATURE__HPP
#define FEATURE__HPP

#include "defs.hpp"
#include "rapidxml.hpp"
#include "xmlstream.hpp"
#include <list>

namespace Metre {
	class Feature {
	public:
		class BaseDescription {
		private:
			std::string const & m_xmlns;
		public:
			BaseDescription(std::string const &);
			virtual void offer(rapidxml::xml_node<> * node, XMLStream & s) = 0;
			std::string const & xmlns() const;
			virtual Feature * instantiate(XMLStream &) = 0;
			virtual ~BaseDescription();
		};
	protected:
		XMLStream & m_stream;
		static std::list<Feature::BaseDescription *> & all_features(SESSION_TYPE);
	public:
		Feature(XMLStream &);
		template<typename T> class Description : public BaseDescription {
		public:
			Description(std::string const & ns) : BaseDescription(ns) {}
			/// offer!
			Feature * instantiate(XMLStream & s) {
				return new T(s);
			}
		};
			

		virtual bool handle(rapidxml::xml_node<> *) = 0;
		
		static Feature * feature(std::string const & xmlns, XMLStream &);
		static std::list<Feature::BaseDescription *> const & features(SESSION_TYPE);
		template<typename T> static bool declare(SESSION_TYPE t) {
			Feature::all_features(t).push_back(new typename T::Description());
			return true;
		}
		virtual ~Feature();
	};
}

#endif
