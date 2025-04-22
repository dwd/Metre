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

if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -O3 -g -fcoroutines")
    add_definitions(-DMETRE_UNIX)
else()
    add_definitions(-DMETRE_WINDOWS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /await")
endif ()

set(BUILD_SHARED_LIBS OFF)
if(USE_SPIFFING)
    find_package(Spiffing)
endif(USE_SPIFFING)

find_package(ICU)
find_package(covent)
find_package(OpenSSL)
find_package(yaml-cpp)
find_package(fmt)
find_package(st-sigslot)
find_package(spdlog)
find_package(libunwind)
find_package(flxml)

set(FILTER_SOURCES
    src/filters/disco-cache.cc
    src/filters/disco-filter.cc
    src/filters/domain-translation.cc
        src/filters/minimix.cc
#        src/filters/unicode.cc
)

if (USE_SPIFFING)
    list(APPEND FILTER_SOURCES src/filters/spiffing.cc)
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
    include/feature.h
    include/filter.h
    include/jid.h
    include/log.h
    include/router.h
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
    src/jabberserver.cc
    src/jid.cc
    src/log.cc
    src/router.cc
    src/saslexternal.cc
    src/stanza.cc
    src/starttls.cc
    src/xmlstream.cc
        include/send.h
        src/send.cc
        include/fmt-enum.h
        src/healthcheck.cc
        include/jwt.h
        src/jwt.cc
        src/registry.cc
)

if(UNIX)
    list(APPEND SOURCE_FILES src/linuxmain.cc)
else()
    list(APPEND SOURCE_FILES src/winmain.cc)
endif()

add_executable(metre ${SOURCE_FILES})

target_include_directories(metre PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(metre PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    yaml-cpp::yaml-cpp
    ICU::uc
    ICU::i18n
    fmt::fmt
    covent::covent
    st-sigslot::st-sigslot
    spdlog::spdlog
    libunwind::unwind
    flxml::flxml
)
if(METRE_SENTRY)
    target_link_libraries(metre PRIVATE sentry)
    target_compile_definitions(metre PRIVATE METRE_SENTRY=1)
endif(METRE_SENTRY)

if (UNIX)
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
    find_package(GTest)
enable_testing()

add_executable(metre-test
    tests/log.cc
    src/stanza.cc
    src/jid.cc
    tests/stanza.cc
    tests/jid.cc 
    ${CAPABILITY_SOURCES}
    tests/endpoint.cc
        src/base64.cc
        src/jwt.cc
        tests/main.cc
        tests/jwt.cc
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
)

target_link_libraries(metre-test PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        yaml-cpp::yaml-cpp
        ICU::uc
        ICU::i18n
        fmt::fmt
        covent::covent
        st-sigslot::st-sigslot
        GTest::gtest
        spdlog::spdlog
        flxml::flxml
)
if(METRE_SENTRY)
    target_link_libraries(metre-test PRIVATE sentry)
    target_compile_definitions(metre-test PRIVATE DWD_GTEST_SENTRY=1)
endif(METRE_SENTRY)

if (UNIX)
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
