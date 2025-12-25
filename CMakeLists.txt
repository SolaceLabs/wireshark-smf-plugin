# Copyright 2025 Solace Corporation. All rights reserved.

cmake_minimum_required(VERSION 3.16)
project(smf DESCRIPTION "SMF Wireshark Plugin" LANGUAGES C)

include(cmake/SetupWiresharkSDK.cmake)

find_package(Wireshark CONFIG REQUIRED)
find_package(ZLIB REQUIRED)

if(Wireshark_VERSION)
    message(STATUS "Wireshark version detected: ${Wireshark_VERSION}")
    string(REPLACE "." ";" _ws_ver_list ${Wireshark_VERSION})
    list(GET _ws_ver_list 0 WS_VERSION_MAJOR)
    list(GET _ws_ver_list 1 WS_VERSION_MINOR)
    list(GET _ws_ver_list 2 WS_VERSION_PATCH)
else()
    message(WARNING "Could not detect Wireshark version, defaulting to 0.0.0")
    set(WS_VERSION_MAJOR 0)
    set(WS_VERSION_MINOR 0)
    set(WS_VERSION_PATCH 0)
endif()
set(PROJECT_VERSION "${WS_VERSION_MAJOR}.${WS_VERSION_MINOR}.${WS_VERSION_PATCH}")

set(PLUGIN_VERSION_MAJOR "${WS_VERSION_MAJOR}" CACHE STRING "Major Version")
set(PLUGIN_VERSION_MINOR "${WS_VERSION_MINOR}" CACHE STRING "Minor Version")
set(PLUGIN_VERSION_PATCH "-1"                  CACHE STRING "Patch Version")
set(PLUGIN_VERSION "${PLUGIN_VERSION_MAJOR}.${PLUGIN_VERSION_MINOR}.${PLUGIN_VERSION_PATCH}")
message(STATUS "SMF plugin version set to:  ${PLUGIN_VERSION}")

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}" CACHE PATH "Installation prefix" FORCE)
endif()

include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)
configure_file(config.h.in ${CMAKE_BINARY_DIR}/config.h @ONLY)

if(WIN32)
    set(MODULE_NAME "smf")
    set(MODULE_VERSION "${PLUGIN_VERSION}")
    string(REPLACE "." "," RC_VERSION "${PROJECT_VERSION},0")
    string(REPLACE "." "," RC_MODULE_VERSION "${MODULE_VERSION},0")
    set(MSVC_VARIANT "${CMAKE_GENERATOR}")

    configure_file(plugin.rc.in ${CMAKE_BINARY_DIR}/plugin.rc @ONLY)
    set(PLUGIN_RC_FILE ${CMAKE_CURRENT_BINARY_DIR}/plugin.rc)
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

set(DISSECTOR_SRC
    packet-assuredctrl.c
    packet-clientctrl.c
    packet-pubctrl.c
    packet-smf.c
    packet-smf-binarymeta.c
    packet-smf-compress.c
    packet-matelink.c
    packet-smf-openmama-payload.c
    packet-smp.c
    packet-smrp.c
    packet-subctrl.c
    packet-xmllink.c
    sdt-decoder.c
    smf-analysis.c
    perftool-decoder.c
)
set(PLUGIN_FILES
    plugin.c
    ${PLUGIN_RC_FILE}
    ${DISSECTOR_SRC}
)

add_library(smf MODULE ${PLUGIN_FILES})
set_target_properties(smf PROPERTIES PREFIX "" DEFINE_SYMBOL "")

target_include_directories(smf PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}
    ${ZLIB_INCLUDE_DIRS}
)

target_link_libraries(smf epan ${ZLIB_LIBRARIES})
