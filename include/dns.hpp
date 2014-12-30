#ifndef METRE_DNS_H
#define METRE_DNS_H

#include <sigslot/sigslot.h>
#include <string>
#include <vector>

namespace Metre {

	namespace DNS {
		enum RR {
			A,
			AAAA,
			SRV,
			CNAME,
			ANY
		};

		class SrvRR {
		public:
			std::string hostname;
			unsigned short port;
			unsigned short weight;
			unsigned short priority;
		};
		class Srv {
		public:
			std::vector<SrvRR> rrs;
			std::string domain;
			bool dnssec;
			std::string error;
			//Srv() : dnssec(false) {}
			//Srv(Srv const &) = default;
		};

		class Address {
		public:
			std::vector<uint32_t> addr4;
			std::vector<unsigned char[16]> addr6;
			bool dnssec;
			std::string error;
			std::string hostname;
			//Address() : dnssec(false) {};
			//Address(Address const &) = default;
		};


		class Resolver {
		public:
			typedef sigslot::signal<sigslot::thread::mt, Srv const*> srv_callback_t;
			typedef sigslot::signal<sigslot::thread::mt, Address const*> addr_callback_t;
			virtual srv_callback_t & SrvLookup(std::string const & domain) = 0;
			virtual addr_callback_t & AddressLookup(std::string const & hostname) = 0;
			static Resolver & resolver();
		};
	}
}

#endif
