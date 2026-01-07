# Copyright 2026 Solace Corporation. All rights reserved.

param (
    [string]$Version,
    [string]$SdkRoot,
    [string]$DumpbinPath,
    [string]$LibPath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DumpbinPath)) { Write-Error "dumpbin missing"; exit 1 }
$ToolDir = Split-Path -Parent $DumpbinPath
$Env:PATH = "$ToolDir;$Env:PATH"

if (-not (Test-Path $SdkRoot)) { New-Item -ItemType Directory -Force -Path $SdkRoot | Out-Null }
Set-Location $SdkRoot
New-Item -ItemType Directory -Force -Path "libs" | Out-Null

function Fast-Download ($Url, $Name) {
    if (Test-Path $Name) { return }
    Write-Host "Downloading $Name..." -ForegroundColor Cyan
    try { (New-Object System.Net.WebClient).DownloadFile($Url, "$PWD\$Name") }
    catch { Write-Error "Failed to download $Url"; exit 1 }
}

# 1. Get source
$WS_SRC_URL = "https://www.wireshark.org/download/src/all-versions/wireshark-$Version.tar.xz"
Fast-Download $WS_SRC_URL "ws.tar.xz"

if (-not (Test-Path "wireshark-src")) {
    Write-Host "Extracting Source..." -ForegroundColor Cyan
    & "7z" x "ws.tar.xz" -y | Out-Null; & "7z" x "ws.tar" -y -o"wireshark-src" | Out-Null
}

# 2. Dynamically find vcpkg artifact
Write-Host "Reading dependency info..." -ForegroundColor Cyan
$FetchFile = "$SdkRoot\wireshark-src\wireshark-$Version\cmake\modules\FetchArtifacts.cmake"
if (-not (Test-Path $FetchFile)) { Write-Error "FetchArtifacts.cmake not found"; exit 1 }

$Content = Get-Content $FetchFile -Raw
if ($Content -match 'vcpkg-export/(vcpkg-export-[^ \t\r\n"]+\.zip)') {
    $VcpkgZipName = $Matches[1]
    Write-Host "Detected Artifact: $VcpkgZipName" -ForegroundColor Green
} else { Write-Error "Could not parse vcpkg filename"; exit 1 }

$DEPS_URL = "https://dev-libs.wireshark.org/windows/packages/vcpkg-export/$VcpkgZipName"
$WS_PAF_URL = "https://www.wireshark.org/download/win64/all-versions/WiresharkPortable64_$Version.paf.exe"

# 3. Download & Extract binaries
Fast-Download $DEPS_URL "deps.zip"
Fast-Download $WS_PAF_URL "portable.exe"

Write-Host "Extracting Binaries..." -ForegroundColor Cyan
if (-not (Test-Path "deps\installed")) {
    & "7z" x "deps.zip" -y -o"deps_temp" | Out-Null
    $InstDir = Get-ChildItem -Path "deps_temp" -Filter "installed" -Recurse | Select-Object -First 1
    if ($InstDir) { New-Item -ItemType Directory -Force -Path "deps" | Out-Null; Move-Item $InstDir.FullName "deps" -Force }
    Remove-Item "deps_temp" -Recurse -Force
}

if (-not (Test-Path "wireshark-bin")) {
    & "7z" x "portable.exe" -y -o"portable_temp" | Out-Null
    Move-Item "portable_temp\App\Wireshark" "wireshark-bin"
    Remove-Item -Recurse -Force "portable_temp"
}

# 4. Generate import libs
Write-Host "Generating .lib files..." -ForegroundColor Cyan
function Gen-Lib ($dll) {
    $dllPath = "$SdkRoot\wireshark-bin\$dll.dll"
    if (-not (Test-Path $dllPath)) { Write-Error "Missing $dll.dll"; return }
    $def = "$SdkRoot\libs\$dll.def"
    $lib = "$SdkRoot\libs\$dll.lib"

    $dump = & $DumpbinPath /exports "$dllPath"
    $lines = @("LIBRARY $dll", "EXPORTS")

    foreach ($line in $dump) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
        $sym = $null
        if ($parts.Count -ge 4 -and $parts[0] -match "^\d+$" -and $parts[2] -match "^[0-9A-Fa-f]+$") { $sym = $parts[3] }
        elseif ($parts.Count -ge 3 -and $parts[0] -match "^\d+$") { $sym = $parts[2] }

        if ($sym -ne $null -and $sym -ne "[NONAME]" -and $sym -ne "summary") { $lines += "    $sym" }
    }
    $lines | Out-File $def -Encoding ASCII
    & $LibPath /def:$def /out:$lib /machine:x64 /nologo
}
Gen-Lib "libwireshark"
Gen-Lib "libwsutil"

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
if (-not (Test-Path $IncPath)) { New-Item -ItemType Directory -Force -Path $IncPath | Out-Null }
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
