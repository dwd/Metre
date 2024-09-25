//
// Created by dwd on 9/18/24.
//

#ifndef METRE_FMT_ENUM_H
#define METRE_FMT_ENUM_H

#include <spdlog/logger.h>
#include "defs.h"


#define METRE_ENUM_ENTRY(x) case x: name = #x; break;
#define METRE_ENUM_ENTRY_TXT(x, y) case x: name = y; break;
#define METRE_ENUM_FORMATTER(e, c) \
template <> \
struct fmt::formatter< e > : fmt::formatter<std::string_view> { \
    auto format(const e val, fmt::format_context& ctx) const { \
        std::string_view name = "[Unknown " #e " value]"; \
        switch (val) { \
            using enum e ; \
            c \
        }                          \
        return fmt::formatter<std::string_view>::format(name, ctx);   \
        }                          \
}

METRE_ENUM_FORMATTER(Metre::SESSION_TYPE,
                     METRE_ENUM_ENTRY(C2S)
                     METRE_ENUM_ENTRY(S2S)
                     METRE_ENUM_ENTRY(X2X)
                     METRE_ENUM_ENTRY(COMP)
                     METRE_ENUM_ENTRY(INTERNAL)
);

METRE_ENUM_FORMATTER(Metre::SESSION_DIRECTION,
                     METRE_ENUM_ENTRY_TXT(INBOUND, "IN")
                     METRE_ENUM_ENTRY_TXT(OUTBOUND, "OUT")
);

METRE_ENUM_FORMATTER(Metre::TLS_MODE,
                     METRE_ENUM_ENTRY(IMMEDIATE)
                     METRE_ENUM_ENTRY(STARTTLS)
);

METRE_ENUM_FORMATTER(Metre::TLS_PREFERENCE,
                     METRE_ENUM_ENTRY(PREFER_IMMEDIATE)
                     METRE_ENUM_ENTRY(PREFER_STARTTLS)
                     METRE_ENUM_ENTRY(PREFER_ANY)
);

METRE_ENUM_FORMATTER(Metre::FILTER_RESULT,
                     METRE_ENUM_ENTRY(PASS)
                     METRE_ENUM_ENTRY(DROP)
);

METRE_ENUM_FORMATTER(Metre::FILTER_DIRECTION,
                     METRE_ENUM_ENTRY(FROM)
                     METRE_ENUM_ENTRY(TO)
);


#endif //METRE_FMT_ENUM_H
