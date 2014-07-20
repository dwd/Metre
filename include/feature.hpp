#ifndef FEATURE__HPP
#define FEATURE__HPP

#include "defs.hpp"
#include "rapidxml.hpp"
#include "xmlstream.hpp"
#include <list>

namespace Metre {
	class Feature {
	public:
		enum Type {FEAT_NONE=0, FEAT_SECURE, FEAT_AUTH, FEAT_COMP, FEAT_POSTAUTH};
		class BaseDescription {
		private:
			std::string const & m_xmlns;
			Feature::Type const m_type;
		public:
			BaseDescription(std::string const &, Feature::Type);
			virtual void offer(rapidxml::xml_node<> * node, XMLStream & s) = 0;
			std::string const & xmlns() const;
			virtual Feature * instantiate(XMLStream &) = 0;
			virtual Feature::Type type(XMLStream &) {
				return m_type;
			}
			virtual ~BaseDescription();
		};
	protected:
		XMLStream & m_stream;
		static std::list<Feature::BaseDescription *> & all_features(SESSION_TYPE);
	public:
		Feature(XMLStream &);
		template<typename T> class Description : public BaseDescription {
		public:
			Description(std::string const & ns, Feature::Type t) : BaseDescription(ns, t) {}
			/// offer!
			Feature * instantiate(XMLStream & s) {
				return new T(s);
			}
		};


		virtual bool handle(rapidxml::xml_node<> *) = 0;
		virtual bool negotiate(rapidxml::xml_node<> *) {return false;}

		static Feature * feature(std::string const & xmlns, XMLStream &);
		static std::list<Feature::BaseDescription *> const & features(SESSION_TYPE);
		template<typename T> static bool declare(SESSION_TYPE t) {
			Feature::all_features(t).push_back(new typename T::Description());
			return true;
		}
		static Feature::Type type(std::string const & xmlns, XMLStream & t);
		virtual ~Feature();
	};
}

#endif
