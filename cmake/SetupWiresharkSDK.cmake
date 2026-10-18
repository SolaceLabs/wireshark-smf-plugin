# Copyright 2026 Solace Corporation. All rights reserved.

# Check if the user provided specific version targets
if(DEFINED PLUGIN_VERSION_MAJOR AND DEFINED PLUGIN_VERSION_MINOR)
    set(WS_SDK_VERSION_MAJOR "${PLUGIN_VERSION_MAJOR}")
    set(WS_SDK_VERSION_MINOR "${PLUGIN_VERSION_MINOR}")
    set(WS_SDK_VERSION_MICRO 0)
    set(WS_FULL_VERSION "${WS_SDK_VERSION_MAJOR}.${WS_SDK_VERSION_MINOR}.${WS_SDK_VERSION_MICRO}")
    set(WS_VERSION_DEFINED TRUE)
else()
    set(WS_VERSION_DEFINED FALSE)
endif()

# Define where the SDK will be created if bootstrapping is needed
set(WS_DEPS_DIR "${CMAKE_BINARY_DIR}/_deps")
set(WS_SDK_ROOT "${WS_DEPS_DIR}/wireshark-${WS_FULL_VERSION}")
set(WS_SRC_DIR "${WS_SDK_ROOT}/src")

set(NEED_BOOTSTRAP FALSE)

if(WIN32)
    # Windows always requires bootstrapping, so we MUST have the version.
    if(NOT WS_VERSION_DEFINED)
        message(FATAL_ERROR "On Windows, you must define PLUGIN_VERSION_MAJOR and PLUGIN_VERSION_MINOR to bootstrap the Wireshark SDK")
    endif()
    set(NEED_BOOTSTRAP TRUE)
elseif(UNIX)
    # Try to find System Wireshark
    find_package(Wireshark CONFIG QUIET)

    if(Wireshark_FOUND)
        if(WS_VERSION_DEFINED)
            # Extract major.minor from system Wireshark version
            string(REPLACE "." ";" _ws_ver_list ${Wireshark_VERSION})
            list(GET _ws_ver_list 0 WS_SYSTEM_VERSION_MAJOR)
            list(GET _ws_ver_list 1 WS_SYSTEM_VERSION_MINOR)
            set(WS_SYSTEM_MAJOR_MINOR "${WS_SYSTEM_VERSION_MAJOR}.${WS_SYSTEM_VERSION_MINOR}")
            set(WS_REQUESTED_MAJOR_MINOR "${PLUGIN_VERSION_MAJOR}.${PLUGIN_VERSION_MINOR}")

            # If system found but version mismatch -> Bootstrap
            if(NOT "${WS_SYSTEM_MAJOR_MINOR}" STREQUAL "${WS_REQUESTED_MAJOR_MINOR}")
                message(STATUS "System Wireshark version (${Wireshark_VERSION}) does not match requested (${WS_REQUESTED_MAJOR_MINOR}.x). Bootstrapping local SDK...")
                set(NEED_BOOTSTRAP TRUE)
            else()
                message(STATUS "Found System Wireshark ${Wireshark_VERSION} (matches ${WS_REQUESTED_MAJOR_MINOR}.x)")
            endif()
        else()
            message(STATUS "Found System Wireshark ${Wireshark_VERSION}")
        endif()
    else()
        # System not found. Can we bootstrap?
        if(WS_VERSION_DEFINED)
            message(STATUS "System Wireshark not found. Bootstrapping local SDK for version ${WS_FULL_VERSION}...")
            set(NEED_BOOTSTRAP TRUE)
        else()
            message(FATAL_ERROR "System Wireshark not found. To bootstrap a local SDK, you must define PLUGIN_VERSION_MAJOR and PLUGIN_VERSION_MINOR")
        endif()
    endif()
endif()

if(NOT NEED_BOOTSTRAP)
    return()
endif()

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
