#!/bin/bash

# Copyright 2026 Solace Corporation. All rights reserved.

set -e
VERSION="$1"
SDK_ROOT="$2"

# Official Source URL
BASE_URL="https://www.wireshark.org/download/src/all-versions"
SRC_URL="$BASE_URL/wireshark-$VERSION.tar.xz"
SIG_URL="$BASE_URL/SIGNATURES-$VERSION.txt"

download() {
    if command -v wget &> /dev/null; then
        wget -q "$1" -O "$2" || { echo "Error: Failed to download $1"; exit 1; }
    else
        curl -fsSL -o "$2" "$1" || { echo "Error: Failed to download $1"; exit 1; }
    fi
}

sha256() {
    if command -v sha256sum &> /dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

mkdir -p "$SDK_ROOT"

if [ ! -d "$SDK_ROOT/src" ]; then
    echo "Downloading Source..."

    TAR_FILE="$SDK_ROOT/ws.tar.xz"
    SIG_FILE="$SDK_ROOT/SIGNATURES.txt"
    download "$SIG_URL" "$SIG_FILE"
    download "$SRC_URL" "$TAR_FILE"

    EXPECTED=$(sed -n "s/^SHA256(wireshark-$VERSION\.tar\.xz)=\([0-9a-f]\{64\}\).*/\1/p" "$SIG_FILE")
    rm -f "$SIG_FILE"
    if [ -z "$EXPECTED" ] || [ "$(sha256 "$TAR_FILE")" != "$EXPECTED" ]; then
        rm -f "$TAR_FILE"
        echo "Error: SHA256 mismatch for wireshark-$VERSION.tar.xz"
        exit 1
    fi

    rm -rf "$SDK_ROOT/src_temp"
    mkdir -p "$SDK_ROOT/src_temp"
    tar -xf "$TAR_FILE" -C "$SDK_ROOT/src_temp" --strip-components=1
    mv "$SDK_ROOT/src_temp" "$SDK_ROOT/src"
    rm -f "$TAR_FILE"
fi
