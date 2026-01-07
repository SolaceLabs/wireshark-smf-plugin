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
Personal Plugin Folder (version specific, use the wireshark major.minor):

`%APPDATA%\Wireshark\plugins\4.6\epan`

Global Plugin Folder (version specific, use the wireshark major.minor):

`C:\Program Files\Wireshark\plugins\4.6\epan`

### Linux Plugin Folder
Personal Plugin Folder:

`~/.local/lib/wireshark/plugins/4.6/epan`

### macOS Plugin Folder
Personal Plugin Directory:

`~/.local/lib/wireshark/plugins/4-6/epan`

> [!IMPORTANT]
> If you get an error message saying `library load disallowed by system policy` when lauching wireshark, you must run this command to allow the plugin to load:
> ```sh
> sudo xattr -d com.apple.quarantine ~/.local/lib/wireshark/plugins/4-6/epan/smf.so
> ```

See [Wireshark Documentation on Plugin Folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) for more information on installing plugins.

### Finding Plugin Folders and Verify Installation

1. Open Wireshark
2. Navigate to `Help>About Wireshark`
3. Under the `Folders` tab, you can find the location for global and personal folders
4. After installing the plugin, verify that the plugin is loaded by searching `smf` under the `Plugins` tab

## Building Manually
> [!NOTE]
> If you plan to submit changes, create a fork first and clone from the fork.

### Using wireshark packaged with your Linux distribution

1. Install the dependencies
```sh
# ubuntu
sudo apt install cmake gcc git ninja-build wireshark-dev

# fedora
sudo dnf install cmake gcc git ninja wireshark-devel

# arch linux
sudo pacman -Syu cmake gcc git ninja wireshark-cli
```

2. Clone the repo
```sh
git clone https://github.com/SolaceLabs/wireshark-smf-plugin
# or
git clone <your-fork>/wireshark-smf-plugin
```

3. Enter the repo
```sh
cd wireshark-smf-plugin
```

4. Configure cmake
```sh
# optionally add "-DCMAKE_EXPORT_COMPILE_COMMANDS=1" to export the "compile_commands.json"
cmake -G Ninja -B build
```

5. (optional) If you chose to export the compile commands, you can copy them from build or create a symbolic link
```sh
ln -s build/compile_commands.json
```

6. Build the plugin
```sh
cmake --build build
```

You can then find the plugin at `build/smf.so`.

### Using a specific version of Wireshark
> [!NOTE]
> On Windows, you must use the Visual Studio Developer Command Prompt when running the `cmake` commands.

1. Install the dependencies
```sh
# windows
choco install -y visualstudio2022community visualstudio2022-workload-nativedesktop cmake git ninja 7zip

# ubuntu
apt install build-essential bison cmake curl flex git ninja-build libc-ares-dev libgcrypt20-dev libglib2.0-dev libxml2-dev zlib1g-dev

# fedora
dnf install bison cmake curl flex gcc gcc-c++ git ninja-build c-ares-devel glib2-devel libgcrypt-devel libxml2-devel zlib-devel

# arch linux
sudo pacman -Syu c-ares cmake flex gcc git ninja python
```

2. Clone the repo
```sh
git clone https://github.com/SolaceLabs/wireshark-smf-plugin
# or
git clone <your-fork>/wireshark-smf-plugin
```

3. Enter the repo
```sh
cd wireshark-smf-plugin
```

4. Configure cmake
```sh
# optionally add "-DCMAKE_EXPORT_COMPILE_COMMANDS=1" to export the "compile_commands.json"
# you must specific a major / minor version
cmake -G Ninja -B build -DPLUGIN_VERSION_MAJOR=4 -DPLUGIN_VERSION_MINOR=6
```

5. (optional) If you chose to export the compile commands, you can copy them from build or create a symbolic link
```sh
ln -s build/compile_commands.json
```

6. Build the plugin
```sh
cmake --build build
```

You can then find the plugin at `build/smf.so` or `build/smf.dll`.

### MacOS
TODO: Build out-of-tree. See github workflow for working steps.

## Version Naming Convention
As this plugin is designed for use in Wireshark, the MAJOR.MINOR match the Wireshark versions. I.E. SMF Plugin 4.0.x indicates support for all patches of Wireshark 4.0.

The PATCH version of the plugin differentiates versions of the SMF Plugin. As long as the MAJOR.MINOR of the plugin match the corresponding MAJOR.MINOR Wireshark version, then they are compatible.

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
