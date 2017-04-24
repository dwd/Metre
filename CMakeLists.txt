cmake_minimum_required(VERSION 2.8)
project(metre)

set(CPACK_PACKAGE_CONTACT "dave.cridland@surevine.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "XMPP-S2S filtering and security proxy")
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Dave Cridland <dave.cridland@surevine.com>")

# Pick package formats.

message(STATUS "Platform id is ${CMAKE_C_PLATFORM_ID}")
if (UNIX)
    set(CPACK_GENERATOR "TGZ")
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        find_program(LSB_RELEASE lsb_release)
        execute_process(COMMAND ${LSB_RELEASE} -is OUTPUT_VARIABLE LSB_RELEASE_ID OUTPUT_STRIP_TRAILING_WHITESPACE)
        message(STATUS "Linux distro is ${LSB_RELEASE_ID}")
        if (${LSB_RELEASE_ID} MATCHES "Ubuntu")
            set(CPACK_GENERATOR "${CPACK_GENERATOR};DEB")
        endif (${LSB_RELEASE_ID} MATCHES "Ubuntu")
        if (${LSB_RELEASE_ID} MATCHES "CentOS")
            set(CPACK_GENERATOR "${CPACK_GENERATOR};RPM")
        endif (${LSB_RELEASE_ID} MATCHES "CentOS")
    endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
endif (UNIX)

set(OPENSSL_USE_STATIC_LIBS true)
set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/deps/openssl)

find_package(OpenSSL REQUIRED)
find_path(ICU2_INCLUDE_DIR NAMES unicode/unorm2.h)
find_path(ICU_INCLUDE_DIR NAMES unicode/unorm.h)
message("ICU2 dir is ${ICU2_INCLUDE_DIR}")
message("ICU dir is ${ICU_INCLUDE_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -pedantic -O0 -g -DSIGSLOT_PURE_ISO")
set(ICU_LIBS)
if (ICU2_INCLUDE_DIR)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_ICU2")
    message("Found ICU2")
    set(ICU_LIBS icudata icuuc)
elseif (ICU_INCLUDE_DIR)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_ICU")
    message("Found ICU")
    set(ICU_LIBS icudata icuuc)
else ()
    message("No ICU Found")
endif ()

set(FILTER_SOURCES
        src/filters/disco-filter.cc
        src/filters/spiffing.cc
        src/filters/disco-cache.cc
        src/filters/domain-translation.cc)
if (${ICU2_INCLUDE_DIR})
    set(FILTER_SOURCES ${FILTER_SOURCES} src/filters/unicode.cc)
endif ()

set(SOURCE_FILES
        ${FILTER_SOURCES}
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
        src/xmlstream.cc src/saslexternal.cc include/dhparams.h src/linuxmain.cc include/http.h src/http.cc include/tls.h)

#set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#set(BUILD_SHARED_LIBS  OFF)
#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
#find_library(LIBUNBOUND_STATIC libunbound.a)
#find_library(LIBLDNS_STATIC libldns.a)
add_executable(metre ${SOURCE_FILES})
add_subdirectory(deps/spiffing)
add_subdirectory(deps/libevent EXCLUDE_FROM_ALL)
set(LIBUNBOUND ${CMAKE_SOURCE_DIR}/deps/unbound-1.6.1/.libs/libunbound.a)
message("Found libunbound as ${LIBUNBOUND}")
#set_target_properties(metre PROPERTIES LINK_SEARCH_START_STATIC 1)
#set_target_properties(metre PROPERTIES LINK_SEARCH_END_STATIC 1)
target_link_libraries(metre event_core_static OpenSSL::SSL OpenSSL::Crypto event_openssl_static event_extra_static ${LIBUNBOUND} ${ICU_LIBS} spiffing spiffing-asn dl pthread rt)
include_directories(include)
include_directories(./deps/rapidxml)
include_directories(./deps/sigslot)
include_directories(./deps/spiffing/include)
include_directories(./deps/openssl/include)
include_directories(./deps/libevent/include)
include_directories(./deps/unbound-1.6.1/libunbound)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/deps/libevent/include)

install(TARGETS metre DESTINATION bin)
# These install into stupid places:
#
# install(FILES metre.conf.xml DESTINATION ./etc/metre)
# install(FILES data/README.md DESTINATION ./var/cache/metre)

include(CPack)

