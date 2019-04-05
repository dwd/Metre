# Copyright (C) 2014 Canonical Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Build with system gmock and embedded gtest
#
# Usage:
#
# find_package(GMock)
#
# ...
#
# target_link_libraries(
#   my-target
#   ${GTEST_BOTH_LIBRARIES}
# )
#
# NOTE: Due to the way this package finder is implemented, do not attempt
# to find the GMock package more than once.

if(DEFINED GOOGLETEST_ROOT_DIR)
    set(GMOCK_SOURCE_DIR "${GOOGLETEST_ROOT_DIR}/googlemock" CACHE PATH "gmock source directory")
    set(GMOCK_INCLUDE_DIRS "${GMOCK_SOURCE_DIR}/include" CACHE PATH "gmock source include directory")
    set(GTEST_SOURCE_DIR "${GOOGLETEST_ROOT_DIR}/googletest" CACHE PATH "gmock source directory")
    set(GTEST_INCLUDE_DIRS "${GTEST_SOURCE_DIR}/include" CACHE PATH "gtest source include directory")
elseif(EXISTS "/usr/src/googletest")
    # As of version 1.8.0
    set(GOOGLETEST_ROOT_DIR "/usr/src/googletest")
    set(GMOCK_SOURCE_DIR "${GOOGLETEST_ROOT_DIR}/googlemock" CACHE PATH "gmock source directory")
    set(GMOCK_INCLUDE_DIRS "${GMOCK_SOURCE_DIR}/include" CACHE PATH "gmock source include directory")
    set(GTEST_SOURCE_DIR "${GOOGLETEST_ROOT_DIR}/googletest" CACHE PATH "gmock source directory")
    set(GTEST_INCLUDE_DIRS "${GTEST_SOURCE_DIR}/include" CACHE PATH "gtest source include directory")
else()
    set(GOOGLETEST_ROOT_DIR "/usr/src/gmock" CACHE PATH "gmock source directory")
    set(GMOCK_INCLUDE_DIRS "/usr/include" CACHE PATH "gmock source include directory")
    set(GTEST_INCLUDE_DIRS "/usr/include" CACHE PATH "gtest source include directory")
endif()

# Prevent GoogleTest from overriding our compiler/linker options
# when building with Visual Studio
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

add_subdirectory("${GOOGLETEST_ROOT_DIR}" "${CMAKE_BINARY_DIR}/googletest" EXCLUDE_FROM_ALL)

set(GTEST_LIBRARIES gtest CACHE PATH "gtest libraries")
set(GTEST_MAIN_LIBRARIES gtest_main CACHE PATH "gtest libraries")
set(GMOCK_LIBRARIES gmock gmock_main CACHE PATH "gtest libraries")
set(GTEST_BOTH_LIBRARIES ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES} CACHE PATH "gtest libraries")