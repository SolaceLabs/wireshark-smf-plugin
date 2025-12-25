# Check if the user provided specific version targets
if(DEFINED PLUGIN_VERSION_MAJOR AND DEFINED PLUGIN_VERSION_MINOR)
    set(WS_FULL_VERSION "${PLUGIN_VERSION_MAJOR}.${PLUGIN_VERSION_MINOR}.0")
    set(WS_VERSION_DEFINED TRUE)
else()
    set(WS_VERSION_DEFINED FALSE)
endif()

# Define where the SDK will be created if bootstrapping is needed
set(WS_DEPS_DIR "${CMAKE_BINARY_DIR}/_deps")
set(WS_SDK_ROOT "${WS_DEPS_DIR}/wireshark-${WS_FULL_VERSION}")

if(WIN32)
    # Windows always requires bootstrapping, so we MUST have the version.
    if(NOT WS_VERSION_DEFINED)
        message(FATAL_ERROR "On Windows, you must define PLUGIN_VERSION_MAJOR and PLUGIN_VERSION_MINOR to bootstrap the Wireshark SDK")
    endif()

    if(NOT EXISTS "${WS_SDK_ROOT}/WiresharkConfig.cmake")
        message(STATUS "Wireshark SDK not found. Bootstrapping version ${WS_FULL_VERSION}...")
        message(STATUS "Artifacts will be downloaded to: ${WS_SDK_ROOT}")

        # Locate MSVC Tools
        find_program(MSVC_DUMPBIN "dumpbin")
        find_program(MSVC_LIB "lib")

        if(NOT MSVC_DUMPBIN OR NOT MSVC_LIB)
             message(FATAL_ERROR "Could not find 'dumpbin.exe' or 'lib.exe'. Ensure you are running from a Visual Studio Developer Command Prompt")
        endif()

        file(MAKE_DIRECTORY "${WS_SDK_ROOT}")

        # Run PowerShell Script
        execute_process(
            COMMAND powershell -ExecutionPolicy Bypass -File "${CMAKE_SOURCE_DIR}/cmake/scripts/prepare_sdk_win.ps1"
                    -Version "${WS_FULL_VERSION}"
                    -SdkRoot "${WS_SDK_ROOT}"
                    -DumpbinPath "${MSVC_DUMPBIN}"
                    -LibPath "${MSVC_LIB}"
            RESULT_VARIABLE _ps_result
        )

        if(NOT _ps_result EQUAL 0)
            message(FATAL_ERROR "Failed to bootstrap Wireshark SDK")
        endif()
    else()
        message(STATUS "Using local Wireshark SDK: ${WS_SDK_ROOT}")
    endif()

    # Configure CMake to use this SDK
    set(Wireshark_DIR "${WS_SDK_ROOT}" CACHE PATH "Path to Wireshark Config" FORCE)

    # Configure ZLIB from the SDK bundle
    set(VCPKG_ROOT "${WS_SDK_ROOT}/deps/installed/x64-windows")
    set(ZLIB_ROOT "${VCPKG_ROOT}" CACHE PATH "Path to ZLIB root" FORCE)
    set(ZLIB_INCLUDE_DIR "${VCPKG_ROOT}/include" CACHE PATH "Path to ZLIB include" FORCE)
    set(ZLIB_LIBRARY "${VCPKG_ROOT}/lib/zlib.lib" CACHE PATH "Path to ZLIB library" FORCE)

    # Force C11 Standard for Windows builds
    add_compile_options(/std:c11)
elseif(UNIX)
    # Try to find System Wireshark
    find_package(Wireshark CONFIG QUIET)

    set(NEED_BOOTSTRAP FALSE)

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

    if(NEED_BOOTSTRAP)
        # Deterministic path enforced by the shell script (lib/cmake/wireshark)
        set(LOCAL_CONFIG "${WS_SDK_ROOT}/lib/cmake/wireshark/WiresharkConfig.cmake")

        # Build if config doesn't exist
        if(NOT EXISTS "${LOCAL_CONFIG}")
            execute_process(
                COMMAND bash "${CMAKE_SOURCE_DIR}/cmake/scripts/prepare_sdk_unix.sh"
                        "${WS_FULL_VERSION}" "${WS_SDK_ROOT}"
                RESULT_VARIABLE _sh_result
            )

            if(NOT _sh_result EQUAL 0)
                message(FATAL_ERROR "Failed to build Wireshark SDK from source")
            endif()
        endif()

        # Check again after build
        if(EXISTS "${LOCAL_CONFIG}")
            get_filename_component(WS_CONFIG_DIR "${LOCAL_CONFIG}" DIRECTORY)
            set(Wireshark_DIR "${WS_CONFIG_DIR}" CACHE PATH "Path to Wireshark Config" FORCE)
        else()
            message(FATAL_ERROR "Bootstrap appeared to succeed, but WiresharkConfig.cmake was not found at: ${LOCAL_CONFIG}")
        endif()
    endif()
endif()
