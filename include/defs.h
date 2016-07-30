#ifndef DEFS__HPP
#define DEFS__HPP

namespace Metre {
	typedef enum {
		C2S,
		S2S,
		COMP,
		INT
	} SESSION_TYPE;


	typedef enum {
		INBOUND,
		OUTBOUND
	} SESSION_DIRECTION;

	class Feature;
	class Filter;
	class Stanza;
	class XMLStream;
	class Route;
}

#define SIGSLOT_PURE_ISO
#endif
