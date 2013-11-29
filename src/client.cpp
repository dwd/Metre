#include "feature.hpp"

using namespace Metre;
using namespace rapidxml;

namespace {
	const std::string sasl_ns = "jabber:client";

	class Client : public Feature {
	public:
		Client(XMLStream & s) : Feature(s) {}
		class Description : public Feature::Description<Client> {
		public:
			Description() : Feature::Description<Client>(sasl_ns) {};
			virtual void offer(xml_node<> *, XMLStream &) {
				// No feature advertised.
			}
		};
		
		bool handle(rapidxml::xml_node<> * node) {
			return true;
		}
	};
	
	bool declared = Feature::declare<Client>(C2S);
}

