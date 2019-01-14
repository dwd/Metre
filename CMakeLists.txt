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
        if (${LSB_RELEASE_ID} MATCHES "RedHatEnterpriseServer")
            set(CPACK_GENERATOR "${CPACK_GENERATOR};RPM")
        endif (${LSB_RELEASE_ID} MATCHES "RedHatEnterpriseServer")
    endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
endif (UNIX)

set(OPENSSL_USE_STATIC_LIBS true)
set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/deps/openssl)

find_package(OpenSSL REQUIRED)
find_path(ICU2_INCLUDE_DIR PATHS /usr/local/opt/icu4c/include NAMES unicode/unorm2.h)
find_path(ICU_INCLUDE_DIR PATHS /usr/local/opt/icu4c/include NAMES unicode/unorm.h)
message("ICU2 dir is ${ICU2_INCLUDE_DIR}")
message("ICU dir is ${ICU_INCLUDE_DIR}")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -O0 -g -DSIGSLOT_PURE_ISO")
set(ICU_LIBS)
if (ICU2_INCLUDE_DIR)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_ICU2")
    include_directories(${ICU2_INCLUDE_DIR})
    link_directories(${ICU2_INCLUDE_DIR}/../lib)
    message("Found ICU2")
    set(ICU_LIBS icudata icuuc)
elseif (ICU_INCLUDE_DIR)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_ICU")
    include_directories(${ICU_INCLUDE_DIR})
    link_directories(${ICU_INCLUDE_DIR}/../lib)
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
if (ICU2_INCLUDE_DIR)
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
    src/starttls.cc src/bidi.cc
        src/xmlstream.cc src/saslexternal.cc include/dhparams.h src/linuxmain.cc include/http.h src/http.cc include/tls.h src/pubsub/pubsub.cc include/capability.h src/capability.cc src/capabilities/ping.cc include/endpoint.h src/endpoint.cc src/endpoints/simple.cc include/datastore.h src/datastore.cc include/sql.h src/capabilities/pubsub.cc src/capabilities/disco.cc include/node.h src/capabilities/node.cc)

add_executable(metre ${SOURCE_FILES})
add_subdirectory(deps/spiffing EXCLUDE_FROM_ALL)
add_subdirectory(deps/libevent EXCLUDE_FROM_ALL)
add_subdirectory(deps/unbound EXCLUDE_FROM_ALL)
add_subdirectory(deps/spdlog EXCLUDE_FROM_ALL)
add_subdirectory(deps/googletest EXCLUDE_FROM_ALL)
SET(METRE_EXTRA_LIBS )
if (${CMAKE_C_PLATFORM_ID} MATCHES "Linux")
    SET(METRE_EXTRA_LIBS ${METRE_EXTRA_LIBS} rt)
endif()
target_link_libraries(metre event_core_static OpenSSL::SSL OpenSSL::Crypto event_openssl_static event_extra_static unbound ${ICU_LIBS} spiffing spiffing-asn dl pthread)
include_directories(include)
include_directories(./deps/rapidxml)
include_directories(./deps/sigslot)
include_directories(./deps/spiffing/include)
include_directories(./deps/openssl/include)
include_directories(./deps/libevent/include)
include_directories(./deps/unbound/libunbound)
include_directories(./deps/spdlog/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/deps/libevent/include)

install(TARGETS metre DESTINATION bin)

add_executable(metre-test tests/log.cc src/stanza.cc src/jid.cc tests/stanza.cc tests/jid.cc src/endpoint.cc src/capability.cc src/capabilities/disco.cc src/capabilities/ping.cc src/capabilities/pubsub.cc src/capabilities/node.cc tests/endpoint.cc)
include_directories(./deps/googletest/googletest/include)
target_link_libraries(metre-test ${LIBUNBOUND} ${ICU_LIBS} gtest gtest_main)
target_compile_definitions(metre-test PUBLIC METRE_TESTING=1)
# These install into stupid places:
#
# install(FILES metre.conf.xml DESTINATION ./etc/metre)
# install(FILES data/README.md DESTINATION ./var/cache/metre)

include(CPack)

