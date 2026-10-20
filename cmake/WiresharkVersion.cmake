# Copyright 2026 Solace Corporation. All rights reserved.

set(WIRESHARK_TARGET_VERSION 4.6.0)

# CI reads the version with: cmake -P cmake/WiresharkVersion.cmake
if(CMAKE_SCRIPT_MODE_FILE)
    message("${WIRESHARK_TARGET_VERSION}")
endif()
