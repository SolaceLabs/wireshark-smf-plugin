# Copyright 2026 Solace Corporation. All rights reserved.

include(${CMAKE_CURRENT_LIST_DIR}/WiresharkVersion.cmake)

if(NOT WIRESHARK_TARGET_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR "WIRESHARK_TARGET_VERSION in cmake/WiresharkVersion.cmake must be major.minor.patch, got '${WIRESHARK_TARGET_VERSION}'")
endif()
set(WS_SDK_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(WS_SDK_VERSION_MINOR "${CMAKE_MATCH_2}")
set(WS_SDK_VERSION_MICRO "${CMAKE_MATCH_3}")
set(WS_FULL_VERSION "${WIRESHARK_TARGET_VERSION}")

if(USE_SYSTEM_WIRESHARK AND NOT WIN32)
    find_package(Wireshark CONFIG QUIET)
    if(Wireshark_FOUND)
        message(STATUS "Using system Wireshark ${Wireshark_VERSION} (WIRESHARK_TARGET_VERSION is ${WIRESHARK_TARGET_VERSION})")
        return()
    endif()
endif()

set(WS_SDK_ROOT "${CMAKE_BINARY_DIR}/_deps/wireshark-${WS_FULL_VERSION}")
set(WS_SRC_DIR "${WS_SDK_ROOT}/src")

if(WIN32)
    set(WS_SDK_READY "${WS_SDK_ROOT}/libs/wsutil.lib")
    find_program(WS_POWERSHELL NAMES pwsh powershell)
    set(WS_SDK_COMMAND "${WS_POWERSHELL}" -ExecutionPolicy Bypass -File "${CMAKE_SOURCE_DIR}/cmake/scripts/prepare_sdk_win.ps1"
                       -Version "${WS_FULL_VERSION}" -SdkRoot "${WS_SDK_ROOT}")
else()
    set(WS_SDK_READY "${WS_SRC_DIR}/epan/packet.h")
    set(WS_SDK_COMMAND bash "${CMAKE_SOURCE_DIR}/cmake/scripts/prepare_sdk_unix.sh" "${WS_FULL_VERSION}" "${WS_SDK_ROOT}")
endif()

if(NOT EXISTS "${WS_SDK_READY}")
    message(STATUS "Downloading Wireshark SDK ${WS_FULL_VERSION} to: ${WS_SDK_ROOT}")
    execute_process(COMMAND ${WS_SDK_COMMAND} RESULT_VARIABLE _sdk_result)
    if(NOT _sdk_result EQUAL 0 OR NOT EXISTS "${WS_SDK_READY}")
        message(FATAL_ERROR "Failed to bootstrap Wireshark SDK")
    endif()
else()
    message(STATUS "Using local Wireshark SDK: ${WS_SDK_ROOT}")
endif()

set(PROJECT_MAJOR_VERSION "${WS_SDK_VERSION_MAJOR}")
set(PROJECT_MINOR_VERSION "${WS_SDK_VERSION_MINOR}")
set(PROJECT_PATCH_VERSION "${WS_SDK_VERSION_MICRO}")
configure_file("${WS_SRC_DIR}/ws_version.h.in" "${WS_SDK_ROOT}/include/ws_version.h" @ONLY)

set(Wireshark_VERSION "${WS_FULL_VERSION}")
set(WS_INCLUDE_DIRS
    "${WS_SRC_DIR}"
    "${WS_SRC_DIR}/epan"
    "${WS_SRC_DIR}/include"
    "${WS_SRC_DIR}/wsutil"
    "${WS_SDK_ROOT}/include"
)

if(WIN32)
    set(WS_WIN_DEPS "${WS_SDK_ROOT}/deps")

    add_library(epan UNKNOWN IMPORTED)
    set_target_properties(epan PROPERTIES
        IMPORTED_LOCATION "${WS_SDK_ROOT}/libs/wireshark.lib"
        INTERFACE_INCLUDE_DIRECTORIES "${WS_INCLUDE_DIRS};${WS_WIN_DEPS}/include;${WS_WIN_DEPS}/include/glib-2.0;${WS_WIN_DEPS}/lib/glib-2.0/include"
        INTERFACE_LINK_LIBRARIES "${WS_SDK_ROOT}/libs/wsutil.lib;${WS_WIN_DEPS}/lib/glib-2.0.lib;${WS_WIN_DEPS}/lib/gmodule-2.0.lib;${WS_WIN_DEPS}/lib/gobject-2.0.lib"
    )

    set(ZLIB_ROOT "${WS_WIN_DEPS}")

    add_compile_options(/std:c11)
else()
    add_library(epan INTERFACE IMPORTED)
    set_target_properties(epan PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${WS_INCLUDE_DIRS}")
endif()
