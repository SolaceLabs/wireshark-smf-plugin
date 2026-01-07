#!/bin/bash

# Copyright 2026 Solace Corporation. All rights reserved.

set -e
VERSION="$1"
SDK_ROOT="$2"

# Official Source URL
SRC_URL="https://www.wireshark.org/download/src/all-versions/wireshark-$VERSION.tar.xz"

mkdir -p "$SDK_ROOT"

# 1. Download & Extract
if [ ! -d "$SDK_ROOT/src" ]; then
    echo "Downloading Source..."
    TAR_FILE="$SDK_ROOT/ws.tar.xz"
    if command -v wget &> /dev/null; then wget -q "$SRC_URL" -O "$TAR_FILE"
    else curl -L -o "$TAR_FILE" "$SRC_URL"; fi

    mkdir -p "$SDK_ROOT/src"
    tar -xf "$TAR_FILE" -C "$SDK_ROOT/src" --strip-components=1
fi

# 2. Build & Install
if [ ! -f "$SDK_ROOT/lib/cmake/wireshark/WiresharkConfig.cmake" ]; then
    echo "Compiling Libs (using Ninja)..."
    mkdir -p "$SDK_ROOT/build"
    cd "$SDK_ROOT/build"

    cmake -G Ninja "$SDK_ROOT/src" \
        -DCMAKE_INSTALL_PREFIX="$SDK_ROOT" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DBUILD_wireshark=OFF -DBUILD_tshark=OFF -DBUILD_dumpcap=OFF \
        -DBUILD_capinfos=OFF -DBUILD_captype=OFF -DBUILD_randpkt=OFF \
        -DBUILD_dftest=OFF -DBUILD_editcap=OFF -DBUILD_mergecap=OFF \
        -DBUILD_reordercap=OFF -DBUILD_text2pcap=OFF -DBUILD_sharkd=OFF \
        -DBUILD_mmdbresolve=OFF -DENABLE_XXHASH=OFF -DENABLE_PCAP=OFF \
        -DENABLE_PLUGINS=OFF

    cmake --build . --target install
    cmake --build . --target install-headers
fi
