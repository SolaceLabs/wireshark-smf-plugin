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

    Write-Host "Downloading $Url as $Name..."

    try {
        (New-Object System.Net.WebClient).DownloadFile($Url, "$PWD\$Name")
    }
    catch {
        Write-Error "Failed to download $Url"
        exit 1
    }
}

function Get-ReleaseHash ($FileName) {
    Fast-Download "https://www.wireshark.org/download/src/all-versions/SIGNATURES-$Version.txt" "SIGNATURES.txt"

    $Pattern = "SHA256\(" + [regex]::Escape($FileName) + "\)=([0-9a-fA-F]{64})"
    if ((Get-Content "SIGNATURES.txt" -Raw) -match $Pattern) {
        return $Matches[1]
    }
    Write-Error "No SHA256 for $FileName in SIGNATURES-$Version.txt"
    exit 1
}

function Assert-Hash ($Name, $Expected) {
    if ((Get-FileHash $Name -Algorithm SHA256).Hash -ne $Expected) {
        Remove-Item $Name -Force
        Write-Error "SHA256 mismatch for $Name"
        exit 1
    }
}

# 1. Get source
if (-not (Test-Path "src")) {
    $WS_SRC_URL = "https://www.wireshark.org/download/src/all-versions/wireshark-$Version.tar.xz"
    Fast-Download $WS_SRC_URL "ws.tar.xz"
    Assert-Hash "ws.tar.xz" (Get-ReleaseHash "wireshark-$Version.tar.xz")

    Write-Host "Extracting Source..."
    & "7z" x "ws.tar.xz" -y | Out-Null
    & "7z" x "ws.tar" -y | Out-Null
    Rename-Item "wireshark-$Version" "src"
    Remove-Item "ws.tar.xz", "ws.tar" -Force
}

# 2. Dynamically find vcpkg artifact
Write-Host "Reading dependency info..."
$FetchFile = "$SdkRoot\src\cmake\modules\FetchArtifacts.cmake"

if (-not (Test-Path $FetchFile)) {
    Write-Error "FetchArtifacts.cmake not found in the Wireshark $Version source"
    exit 1
}

$Content = Get-Content $FetchFile -Raw
if ($Content -match 'add_artifact\(vcpkg-export/(vcpkg-export-[^ \t\r\n"]*x64-windows-ws\.zip)\s+([0-9a-fA-F]{64})') {
    $VcpkgZipName = $Matches[1]
    $VcpkgZipHash = $Matches[2]
    Write-Host "Detected Artifact: $VcpkgZipName"
}
else {
    Write-Error ("Could not find the x64 vcpkg-export package in FetchArtifacts.cmake for Wireshark $Version. " +
        "Find the add_artifact(...) line that provides GLib for x64 Windows in $FetchFile " +
        "and update cmake/scripts/prepare_sdk_win.ps1 to match it.")
    exit 1
}

# 3. Download & Extract dependencies
if (-not (Test-Path "deps")) {
    $DEPS_URL = "https://dev-libs.wireshark.org/windows/packages/vcpkg-export/$VcpkgZipName"
    Fast-Download $DEPS_URL "deps.zip"
    Assert-Hash "deps.zip" $VcpkgZipHash

    Write-Host "Extracting Dependencies..."
    & "7z" x "deps.zip" -y -o"deps_temp" | Out-Null
    $GlibLib = Get-ChildItem -Path "deps_temp" -Filter "glib-2.0.lib" -Recurse |
        Where-Object { $_.FullName -notmatch "\\debug\\" } |
        Select-Object -First 1
    if (-not $GlibLib) {
        Write-Error ("Release glib-2.0.lib not found in $VcpkgZipName. " +
            "The package layout changed in Wireshark ${Version}: inspect the archive " +
            "and update cmake/scripts/prepare_sdk_win.ps1 to match it.")
        exit 1
    }
    Move-Item $GlibLib.Directory.Parent.FullName "deps"
    Remove-Item "deps_temp", "deps.zip" -Recurse -Force
}

# 4. Download & Extract import libs
if (-not (Test-Path "libs\wsutil.lib")) {
    $WS_PDB_URL = "https://www.wireshark.org/download/win64/all-versions/Wireshark-pdb-$Version-x64.zip"
    Fast-Download $WS_PDB_URL "pdbs.zip"

    Write-Host "Extracting Import Libraries..."
    & "7z" e "pdbs.zip" -o"libs" "wireshark.lib" "wsutil.lib" -r -y | Out-Null
    Remove-Item "pdbs.zip" -Force
}

Remove-Item "SIGNATURES.txt" -Force -ErrorAction SilentlyContinue
Write-Host "SDK Ready"
