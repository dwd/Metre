cmake_minimum_required(VERSION 2.8)
project(metre)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -pedantic -Werror -O0 -g")

set(SOURCE_FILES
    include/base64.h
    include/config.h
    include/defs.h
    include/dns.h
    include/feature.h
    include/filter.h
    include/jid.h
    include/log.h
    include/netsession.h
    include/optional
    include/optional.h
    include/router.h
        include/stanza.h
    include/tests.h
    include/xmlstream.h
    include/xmppexcept.h
        gen/dh1024.cc
        gen/dh2048.cc
        gen/dh4096.cc
        src/base64.cc
        src/components.cc
    src/config.cc
    src/dialback.cc
    src/feature.cc
    src/filter.cc
    src/jabberserver.cc
    src/jid.cc
    src/log.cc
    src/mainloop.cc
    src/netsession.cc
    src/router.cc
    src/stanza.cc
    src/starttls.cc
    src/xmlstream.cc src/saslexternal.cc src/spiffing.cc include/dhparams.h src/linuxmain.cc include/http.h src/http.cc)

add_executable(metre ${SOURCE_FILES})
target_link_libraries(metre event_core ssl crypto event_openssl event_extra unbound)
include_directories(include)
include_directories(./deps/rapidxml)
include_directories(./deps/sigslot)

