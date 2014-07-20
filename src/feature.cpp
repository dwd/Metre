#include "feature.hpp"
#include <map>

using namespace Metre;

Feature::Feature(XMLStream & s) : m_stream(s) {}

Feature::~Feature() {}

Feature::BaseDescription::BaseDescription(std::string const & ns, Feature::Type type) : m_xmlns(ns), m_type(type) {}

std::string const & Feature::BaseDescription::xmlns() const {
	return m_xmlns;
}

Feature::BaseDescription::~BaseDescription() {}

std::list<Feature::BaseDescription *> & Feature::all_features(SESSION_TYPE t) {
	static std::map<SESSION_TYPE,std::list<Feature::BaseDescription *>> ls;
	return ls[t];
}

std::list<Feature::BaseDescription *> const & Feature::features(SESSION_TYPE t) {
	return Feature::all_features(t);
}

Feature * Feature::feature(std::string const & xmlns, XMLStream & stream) {
	for (auto f : Feature::features(stream.type())) {
		if (f->xmlns() == xmlns) {
			return f->instantiate(stream);
		}
	}
	return 0;
}

Feature::Type Feature::type(std::string const & xmlns, XMLStream & stream) {
	for (auto f : Feature::features(stream.type())) {
		if (f->xmlns() == xmlns) {
			return f->type(stream);
		}
	}
	return FEAT_NONE;
}
