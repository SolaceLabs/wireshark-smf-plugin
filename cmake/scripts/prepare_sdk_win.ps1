# Copyright 2026 Solace Corporation. All rights reserved.

param (
    [string]$Version,
    [string]$SdkRoot
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $SdkRoot)) {
    New-Item -ItemType Directory -Force -Path $SdkRoot | Out-Null
}

Set-Location $SdkRoot
New-Item -ItemType Directory -Force -Path "libs" | Out-Null

function Fast-Download ($Url, $Name) {
    if (Test-Path $Name) {
        return
    }

    Write-Host "Downloading $Name..." -ForegroundColor Cyan

    try {
        (New-Object System.Net.WebClient).DownloadFile($Url, "$PWD\$Name")
    }
    catch {
        Write-Error "Failed to download $Url"
        exit 1
    }
}

# 1. Get source
if (-not (Test-Path "wireshark-src")) {
    $WS_SRC_URL = "https://www.wireshark.org/download/src/all-versions/wireshark-$Version.tar.xz"
    Fast-Download $WS_SRC_URL "ws.tar.xz"

    Write-Host "Extracting Source..." -ForegroundColor Cyan
    & "7z" x "ws.tar.xz" -y | Out-Null
    & "7z" x "ws.tar" -y -o"wireshark-src" | Out-Null
}

# 2. Dynamically find vcpkg artifact
Write-Host "Reading dependency info..." -ForegroundColor Cyan
$FetchFile = "$SdkRoot\wireshark-src\wireshark-$Version\cmake\modules\FetchArtifacts.cmake"

if (-not (Test-Path $FetchFile)) {
    Write-Error "FetchArtifacts.cmake not found"
    exit 1
}

$Content = Get-Content $FetchFile -Raw
if ($Content -match 'vcpkg-export/(vcpkg-export-[^ \t\r\n"]+\.zip)') {
    $VcpkgZipName = $Matches[1]
    Write-Host "Detected Artifact: $VcpkgZipName" -ForegroundColor Green
}
else {
    Write-Error "Could not parse vcpkg filename"
    exit 1
}

# 3. Download & Extract dependencies
if (-not (Test-Path "deps\installed")) {
    $DEPS_URL = "https://dev-libs.wireshark.org/windows/packages/vcpkg-export/$VcpkgZipName"
    Fast-Download $DEPS_URL "deps.zip"

    Write-Host "Extracting Dependencies..." -ForegroundColor Cyan
    & "7z" x "deps.zip" -y -o"deps_temp" | Out-Null
    $InstDir = Get-ChildItem -Path "deps_temp" -Filter "installed" -Recurse | Select-Object -First 1
    if ($InstDir) {
        New-Item -ItemType Directory -Force -Path "deps" | Out-Null
        Move-Item $InstDir.FullName "deps" -Force
    }
    Remove-Item "deps_temp" -Recurse -Force
}

# 4. Download & Extract import libs
if (-not (Test-Path "libs\libwireshark.lib")) {
    $WS_PDB_URL = "https://www.wireshark.org/download/win64/all-versions/Wireshark-pdb-$Version-x64.zip"
    Fast-Download $WS_PDB_URL "pdbs.zip"

    Write-Host "Extracting Import Libraries..." -ForegroundColor Cyan
    & "7z" e "pdbs.zip" -o"libs" "wireshark.lib" "wsutil.lib" -r -y | Out-Null

    # Rename to match CMake conventions
    if (Test-Path "libs\wireshark.lib") {
        Move-Item "libs\wireshark.lib" "libs\libwireshark.lib" -Force
    }
    if (Test-Path "libs\wsutil.lib") {
        Move-Item "libs\wsutil.lib" "libs\libwsutil.lib" -Force
    }
}

# 5. Generate headers
Write-Host "Generating Headers..." -ForegroundColor Cyan
$VerParts = $Version.Split('.')
$WsHeaderContent = @"
#ifndef __WS_VERSION_H__
#define __WS_VERSION_H__
#define WIRESHARK_VERSION_MAJOR $($VerParts[0])
#define WIRESHARK_VERSION_MINOR $($VerParts[1])
#define WIRESHARK_VERSION_MICRO $($VerParts[2])
#define WIRESHARK_VERSION_STRING "$Version"
#endif
"@
$IncPath = "$SdkRoot\wireshark-src\wireshark-$Version\include"
if (-not (Test-Path $IncPath)) {
    New-Item -ItemType Directory -Force -Path $IncPath | Out-Null
}
$WsHeaderContent | Out-File "$IncPath\ws_version.h" -Encoding ASCII

# 6. cmake config
Write-Host "Generating Config..." -ForegroundColor Cyan
$SDK_C = $SdkRoot.Replace('\', '/')
$DEPS_ROOT = "$SDK_C/deps/installed/x64-windows"
$Config = @"
set(Wireshark_VERSION "$Version")
set(Wireshark_INSTALL_PREFIX "$SDK_C/wireshark-bin")
add_library(epan SHARED IMPORTED)
set_target_properties(epan PROPERTIES
    IMPORTED_LOCATION "$SDK_C/wireshark-bin/libwireshark.dll"
    IMPORTED_IMPLIB   "$SDK_C/libs/libwireshark.lib"
    INTERFACE_INCLUDE_DIRECTORIES "$SDK_C/wireshark-src/wireshark-$Version;$SDK_C/wireshark-src/wireshark-$Version/epan;$SDK_C/wireshark-src/wireshark-$Version/include;$SDK_C/wireshark-src/wireshark-$Version/wsutil;$DEPS_ROOT/include;$DEPS_ROOT/include/glib-2.0;$DEPS_ROOT/lib/glib-2.0/include"
    INTERFACE_LINK_LIBRARIES      "$SDK_C/libs/libwsutil.lib;$DEPS_ROOT/lib/glib-2.0.lib;$DEPS_ROOT/lib/gmodule-2.0.lib;$DEPS_ROOT/lib/gobject-2.0.lib"
)
"@
$Config | Out-File "$SdkRoot\WiresharkConfig.cmake" -Encoding ASCII
Write-Host "SDK Ready" -ForegroundColor Green
