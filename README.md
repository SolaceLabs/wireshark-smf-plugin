[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

# Wireshark SMF Plugin

## Overview
This project is a plugin for wireshark that will dissect Solace SMF protocol.

## Getting Started Quickly

**Note: Wireshark SMF Plugin is currently supported on Wireshark 4.0.x, 4.2.x, 4.4.x, and 4.6.x**

1. Install [Wireshark](https://www.wireshark.org/download.html).

2. Download the corresponding zip file for your platform (Click on "Releases" and in the releases page, click on "Assets" to see the downloadable contents).

3. Unzip the folder and place the .dll (Windows) or .so (Mac/Linux) file in the Wireshark plugin folder, under `epan`. The plugin folder path varies for each OS.

### Windows Plugin Folder
Personal Plugin Folder:

`%APPDATA%\Wireshark\plugins\4.6\epan`

Global Plugin Folder:

`C:\Program Files\Wireshark\plugins\4.0\plugins\epan`

### macOS/Linux Plugin Folder
Personal Plugin Folder:

`~/.local/lib/wireshark/plugins/epan`

See [Wireshark Documentation on Plugin Folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) for more information on installing plugins.

### Finding Plugin Folders and Verify Installation

1. Open Wireshark
2. Navigate to `Help>About Wireshark`
3. Under the `Folders` tab, you can find the location for global and personal folders
4. After installing the plugin, verify that the plugin is loaded by searching `smf` under the `Plugins` tab

## Building Manually
Go to an appropriate directory and execute:
```
git clone --recurse-submodules git@github.com:SolaceLabs/wireshark-smf-plugin.git
```
Note: If you plan to submit changes, create a fork first and clone from the fork.

### Windows
#### Windows Build
Follow instructions in https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWindows

The following are some deviations from the above instructions.
Use a cmd prompt with admin privilege:
```
cd base-directory-of-wireshark-smf-plugin
mkdir build
mklink CMakeListsCustom.txt ..\src\CMakeListsCustom.txt
cd plugins\epan
mklink /D smf ..\..\..\src\smf
```
In vscode, my task.json looks like this:
```json
{
	"version": "2.0.0",
	"tasks": [
        {
            "label": "Pre-Build Files (cmake)",
            "type": "shell",
            "group":"build",
            "options": {
                "cwd": "build",
                "env": {
                    "WIRESHARK_BASE_DIR": "C:\\my-path\\wireshark-smf-plugin",
                    "QT6_DIR": "C:\\Qt\\6.7.3\\msvc2022_64",
                    "WIRESHARK_VERSION_EXTRA": "-YourExtraVersionInfo"
                }
            },
            "command": "cmake -DVCSVERSION_OVERRIDE=\"Git v3.1.0 packaged as 3.1.0-1\" -G “Visual Studio 17 2022” -A x64 ..\\wireshark",
            "problemMatcher": [
                "$msCompile"
            ]
        },
        {
            "label": "Build wireshark (msbuild)",
            "type": "shell",
            "group":{
                "kind": "build",
                "isDefault": true
            },
            "options": {
                "cwd": "build",
                "env": {
                    "WIRESHARK_BASE_DIR": "C:\\my-path\\wireshark-smf-plugin",
                    "QT6_BASE_DIR": "C:\\Qt\\6.7.3\\msvc2022_64",
                    "WIRESHARK_VERSION_EXTRA": "-YourExtraVersionInfo"
                }
            },
            "command": "msbuild /m /p:Configuration=Debug Wireshark.sln",
            "problemMatcher": [
                "$msCompile"
            ]
        },
        {
            "label": "Clean wireshark (msbuild)",
            "type": "shell",
            "group":"build",
            "options": {
                "cwd": "build",
                "env": {
                    "WIRESHARK_BASE_DIR": "C:\\my-path\\wireshark-smf-plugin",
                    "QT6_BASE_DIR": "C:\\Qt\\6.7.3\\msvc2022_64",
                    "WIRESHARK_VERSION_EXTRA": "-YourExtraVersionInfo"
                }
            },
            "command": "msbuild /m /p:Configuration=Debug Wireshark.sln /t:Clean"
        }
	]
}
```

Note 1: To start VSCode, start from the "X64 Native Tools Command Prompt" (search for this in Windows search box), then type "code" to start VSCode.

Note 2: The VCSVERSION_OVERRIDE is needed because the compile failed to find the approparite git repository.

### Linux
    Wireshark is best built from source on Linux following the steps outlined at wireshark.org.

    That said, if you already have a wireshark running on Linux and just need to build the plugin you can do the following:
...
    # clone the repo
    git clone --recurse-submodules <your-fork>/wireshark-smf-plugin.git
    # enter the repo
    cd wireshark-smf-plugin/
    # symlink out plugin into wireshark 
    ln -s ../../../src/smf wireshark/plugins/epan/smf
    # create a build directory and enter it
    mkdir build
    cd build
    # configure cmake,   turn off all options for building wireshark and just build the plugin
    cmake ../wireshark -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCUSTOM_PLUGIN_SRC_DIR="plugins/epan/smf" $(sed -n 's/^option(\(BUILD_\S\+\).*ON)$/-D\1=OFF/p' ../wireshark/CMakeOptions.txt)
    # build the plugins
    ninja plugins
...

### MacOS
    TODO

## Version Naming Convention
As this plugin is designed for use in Wireshark, the MAJOR.MINOR match the Wireshark versions. I.E. SMF Plugin 4.0.x indicates support for all patches of Wireshark 4.0.

The PATCH version of the plugin differentiates versions of the SMF Plugin.  As long as the MAJOR.MINOR of the plugin match the corresponding MAJOR.MINOR Wireshark version, then they are compatible.

## Resources
This is not an officially supported Solace product.

For more information try these resources:
- Ask the [Solace Community](https://solace.community)
- The Solace Developer Portal website at: https://solace.dev

## Contributing
Contributions are encouraged! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors
See the list of [contributors](https://github.com/SolaceLabs/wireshark-smf-plugin/graphs/contributors) who participated in this project.

## License
Wireshark SMF Plugin is licensed under the GNU GPLv2. See the [LICENSE](license.txt) file for details.

## Disclaimer

There is no warranty, expressed or implied, associated with this product.
Use at your own risk.
