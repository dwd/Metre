cmake_minimum_required(VERSION 3.8)
project(metre)

set(CPACK_PACKAGE_CONTACT "dave@cridland.net")
set(CPACK_PACKAGE_VENDOR "Dave Cridland")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Metre - XMPP-S2S filtering and security proxy")
set(CPACK_PACKAGE_NAME "Metre")
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Dave Cridland <dave@cridland.net>")

option(VENDORED_DEPS "Use vendored dependencies" OFF)
option(VCREDIST_PATH "Visual Studio Redistributable Installer path" "")
option(USE_SPIFFING "Use Spiffing for label-based filtering (incomplete)" OFF)
option(METRE_BUILD_TESTS "Build the tests for Metre" ON)
option(METRE_SENTRY "Add Sentry/GlitchTip support" ON)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")


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
else ()
    set(CPACK_COMPONENTS_ALL application)
    set(CPACK_COMPONENT_APPLICATION_DISPLAY_NAME "Metre")
    set(CPACK_COMPONENT_APPLICATION_DESCRIPTION "Metre itself")
    set(CPACK_ALL_INSTALL_TYPES Full)
    set(CPACK_COMPONENT_APPLICATION_INSTALL_TYPES Full)
    message(STATUS "VCREDIST_PATH set to ${VCREDIST_PATH}")
    if (VCREDIST_PATH)
        message(STATUS "Setting vcredist install path")
        install(PROGRAMS ${VCREDIST_PATH} DESTINATION tmp COMPONENT application)
        message(STATUS "Setting extra commands")
        list(APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS " ExecWait '$INSTDIR\\\\tmp\\\\vc_redist.x64.exe'")
        list(APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS " ExecWait 'sc create \\\"Metre\\\" binPath= $INSTDIR\\\\bin\\\\metre.exe'")
        list(APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS " ExecWait 'sc delete \\\"Metre\\\"'")
    endif ()
endif (UNIX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-DSIGSLOT_COROUTINES)

if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -O3 -g -fcoroutines")
    add_definitions(-DMETRE_UNIX)
else()
    add_definitions(-DMETRE_WINDOWS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /await")
endif ()

set(SIGSLOT_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/sigslot")
set(RAPIDXML_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/rapidxml")

set(BUILD_SHARED_LIBS OFF)
if(USE_SPIFFING)
    add_subdirectory(deps/spiffing EXCLUDE_FROM_ALL)
    set(SPIFFING_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/spiffing/include")
    set(SPIFFING_LDFLAGS spiffing spiffing-asn)
    add_definitions(-DUSE_SPIFFING)
endif(USE_SPIFFING)

if(VENDORED_DEPS)
    find_path(_ICU2_INCLUDE_DIR PATHS /usr/local/opt/icu4c/include NAMES unicode/unorm2.h)
    find_path(_ICU_INCLUDE_DIR PATHS /usr/local/opt/icu4c/include NAMES unicode/unorm.h)
    message("ICU2 dir is ${_ICU2_INCLUDE_DIR}")
    message("ICU dir is ${_ICU_INCLUDE_DIR}")
    if (_ICU2_INCLUDE_DIR)
        message("Found ICU2 at ${_ICU2_INCLUDE_DIR}")
        add_definitions(-DHAVE_ICU2)
        set(ICU_INCLUDE_DIRS ${_ICU2_INCLUDE_DIR})
        set(ICU_LDFLAGS icudata icuuc)
        link_directories(${ICU_INCLUDE_DIRS}/../lib)
    elseif (_ICU_INCLUDE_DIR)
        message("Found ICU at ${_ICU_INCLUDE_DIR}")
        add_definitions(-DHAVE_ICU)
        set(ICU_INCLUDE_DIRS ${_ICU_INCLUDE_DIR})
        set(ICU_LDFLAGS icudata icuuc)
        link_directories(${ICU_INCLUDE_DIRS}/../lib)
    else ()
        message("No ICU Found")
    endif ()

    set(OPENSSL_USE_STATIC_LIBS true)
    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl)

    set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "Build libevent statically" FORCE)
    add_subdirectory(deps/libevent EXCLUDE_FROM_ALL)
    add_subdirectory(deps/unbound EXCLUDE_FROM_ALL)
    add_subdirectory(deps/spdlog EXCLUDE_FROM_ALL)

    set(EVENT_INCLUDE_DIRS  "${CMAKE_CURRENT_SOURCE_DIR}/deps/libevent/include" ${CMAKE_CURRENT_BINARY_DIR}/deps/libevent/include)
    set(EVENT_LDFLAGS event_core_static event_openssl_static event_extra_static event_pthreads_static)
    
    set(UNBOUND_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/unbound/libunbound")
    set(UNBOUND_LDFLAGS unbound)

    set(SPDLOG_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/spdlog/include")
else()
    if(APPLE)
        set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/local/opt/openssl@1.1/lib/pkgconfig:/usr/local/opt/icu4c/lib/pkgconfig/")
    elseif(UNIX)
        # Nothing to do for Linux
    else()
        message(FATAL_ERROR "Non-vendored builds not supported on Windows yet")
    endif()

    # Find libs with pkg-config
    find_package(PkgConfig)
    #pkg_check_modules(SPDLOG spdlog>=1.0.0 REQUIRED)
    add_subdirectory(deps/spdlog EXCLUDE_FROM_ALL)
    set(SPDLOG_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/spdlog/include")
    pkg_check_modules(EVENT libevent libevent_openssl libevent_pthreads REQUIRED)
#    pkg_check_modules(UNBOUND libunbound REQUIRED)
    pkg_check_modules(ICU icu-uc REQUIRED)
    add_definitions(-DHAVE_ICU2)
    set(UNBOUND_LDFLAGS unbound)

#    if(APPLE)
#        set(SPDLOG_INCLUDE_DIRS "/usr/local/include/") # Busted pkg-config for SPDLOG
#    elseif(UNIX)
#        set(SPDLOG_INCLUDE_DIRS "/usr/include/") # Busted pkg-config for SPDLOG
#    endif()
endif()

find_package(OpenSSL 3.0.0 REQUIRED)

add_subdirectory(deps/yaml-cpp EXCLUDE_FROM_ALL)
if (METRE_SENTRY)
    set(SENTRY_BACKEND inproc)
    add_subdirectory(deps/sentry-native EXCLUDE_FROM_ALL)
    set(METRE_SENTRY_SOURCES src/sentry-wrap.cc)
else(METRE_SENTRY)
    set(METRE_SENTRY_SOURCES )
endif(METRE_SENTRY)

set(YAMLCPP_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/yaml-cpp/include")

set(FILTER_SOURCES
    src/filters/disco-cache.cc
    src/filters/disco-filter.cc
    src/filters/domain-translation.cc
        src/filters/minimix.cc
)

if (USE_SPIFFING)
    list(APPEND FILTER_SOURCES src/filters/spiffing.cc)
endif()

if (ICU2_INCLUDE_DIR)
    list(APPEND FILTER_SOURCES src/filters/unicode.cc)
endif()

# Capabilities
set(CAPABILITY_SOURCES
    include/capability.h
    include/datastore.h
    include/endpoint.h
    include/node.h
    include/sql.h
    src/capabilities/disco.cc
    src/capabilities/node.cc
    src/capabilities/ping.cc
    src/capabilities/pubsub.cc
    src/capabilities/version.cc
    src/capability.cc
    src/datastore.cc
    src/endpoint.cc
    src/endpoints/simple.cc
)
if(UNIX)
    list(APPEND CAPABILITY_SOURCES src/pubsub/pubsub.cc)
endif()

# Main sources
set(SOURCE_FILES
    ${FILTER_SOURCES}
    ${CAPABILITY_SOURCES}
    include/base64.h
    include/config.h
    include/core.h
    include/defs.h
        include/dns.h
    include/feature.h
    include/filter.h
    include/http.h
    include/jid.h
    include/log.h
    include/netsession.h
    include/router.h
    include/sigslot.h
    include/stanza.h
        include/pkix.h
    include/xmlstream.h
    include/xmppexcept.h
    src/base64.cc
    src/bidi.cc
    src/components.cc
    src/config.cc
    src/dialback.cc
    src/feature.cc
    src/filter.cc
    src/http.cc
    src/jabberserver.cc
    src/jid.cc
    src/log.cc
    src/mainloop.cc
    src/netsession.cc
    src/router.cc
    src/saslexternal.cc
    src/stanza.cc
    src/starttls.cc
    src/xmlstream.cc
        src/dns.cc
        include/sentry-wrap.h
        ${METRE_SENTRY_SOURCES}
        include/send.h
        src/send.cc
        src/send.cc
        include/sockaddr-cast.h
        src/pkix.cc
        include/fmt-enum.h
        src/healthcheck.cc
)

if(UNIX)
    list(APPEND SOURCE_FILES src/linuxmain.cc)
else()
    list(APPEND SOURCE_FILES src/winmain.cc)
endif()

add_executable(metre ${SOURCE_FILES})

target_include_directories(metre PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    ${EVENT_INCLUDE_DIRS}
    ${ICU_INCLUDE_DIRS}
    ${RAPIDXML_INCLUDE_DIRS}
    ${SIGSLOT_INCLUDE_DIRS}
    ${SPDLOG_INCLUDE_DIRS}
    ${UNBOUND_INCLUDE_DIRS}
        ${YAMLCPP_INCLUDE_DIRS}
)

target_link_libraries(metre PRIVATE
    ${EVENT_LDFLAGS}
    ${ICU_LDFLAGS}
    ${RAPIDXML_LDFLAGS}
    ${SIGSLOT_LDFLAGS}
    ${UNBOUND_LDFLAGS}
    OpenSSL::SSL
    OpenSSL::Crypto
        yaml-cpp
)
if(METRE_SENTRY)
    target_link_libraries(metre PRIVATE sentry)
    target_compile_definitions(metre PRIVATE METRE_SENTRY=1)
endif(METRE_SENTRY)

# target_compile_definitions(metre PRIVATE -DSIGSLOT_RESUME_OVERRIDE)

if (UNIX)
    target_include_directories(metre PRIVATE
        ${SPIFFING_INCLUDE_DIRS}
    )

    set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads)

    target_link_libraries(metre PRIVATE
        ${SPIFFING_LDFLAGS}
        ${CMAKE_DL_LIBS} 
        Threads::Threads
            -lunwind
    )
else()
    target_link_libraries(metre PRIVATE
        ws2_32
        crypt32
        Iphlpapi
    )
endif()

install(TARGETS metre RUNTIME DESTINATION bin COMPONENT application)

# Tests
if(METRE_BUILD_TESTS)
include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/main.zip
        DOWNLOAD_EXTRACT_TIMESTAMP ON
        EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(metre-test
    tests/log.cc
    src/stanza.cc
    src/jid.cc
    tests/stanza.cc
    tests/jid.cc 
    ${CAPABILITY_SOURCES}
    tests/endpoint.cc
        src/dns.cc
        tests/dns.cc
        tests/main.cc
)

target_compile_definitions(metre-test PUBLIC
    METRE_TESTING=1
)
target_compile_options(metre-test PRIVATE -g -O0 --coverage)
target_link_options(metre-test PRIVATE -g -O0 --coverage)

# These are all duplicated, because we're not actually linking against a 'libmetre', like we should

target_include_directories(metre-test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${EVENT_INCLUDE_DIRS}
    ${ICU_INCLUDE_DIRS}
    ${RAPIDXML_INCLUDE_DIRS}
    ${SIGSLOT_INCLUDE_DIRS}
    ${SPDLOG_INCLUDE_DIRS}
    ${UNBOUND_INCLUDE_DIRS}
        ${YAMLCPP_INCLUDE_DIRS}
)

target_link_libraries(metre-test PRIVATE
    ${EVENT_LDFLAGS}
    ${ICU_LDFLAGS}
    ${RAPIDXML_LDFLAGS}
    ${SIGSLOT_LDFLAGS}
    ${UNBOUND_LDFLAGS}
    OpenSSL::SSL
    OpenSSL::Crypto
        GTest::gtest
)
if(METRE_SENTRY)
    target_link_libraries(metre-test PRIVATE sentry)
    target_compile_definitions(metre-test PRIVATE DWD_GTEST_SENTRY=1)
endif(METRE_SENTRY)

if (UNIX)
    target_include_directories(metre-test PRIVATE
        ${SPIFFING_INCLUDE_DIRS}
    )

    target_link_libraries(metre-test PRIVATE
        ${SPIFFING_LDFLAGS}
        ${CMAKE_DL_LIBS} 
        Threads::Threads
    )
else()
    target_link_libraries(metre-test PRIVATE
        ws2_32
        crypt32
        Iphlpapi
    )

    target_link_options(metre-test PRIVATE
        /NODEFAULTLIB:LIBCPMTD
        /NODEFAULTLIB:LIBCMTD
    )
endif()

include(GoogleTest)
gtest_discover_tests(metre-test)
endif(METRE_BUILD_TESTS)

## These install into stupid places:
##
install(FILES metre.conf.yml DESTINATION etc/metre)
## install(FILES data/README.md DESTINATION ./var/cache/metre)

include(CPack)
