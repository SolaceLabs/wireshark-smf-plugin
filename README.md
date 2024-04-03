[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

# Wireshark SMF Plugin

## Overview
This project is a plugin for wireshark that will dissect Solace SMF protocol.

## Getting Started Quickly

**Note: Wireshark SMF Plugin is currently supported on Wireshark 4.0.x**

1. Install [Wireshark 4.0](https://www.wireshark.org/download.html).

2. Download the corresponding zip file for your platform.

3. Unzip the folder and place the .dll (Windows) or .so (Mac/Linux) file in the Wireshark plugin folder, under `epan`. The plugin folder path varies for each OS.

### Windows Plugin Folder
Personal Plugin Folder: 

`%APPDATA%\Roaming\Wireshark\plugins\4.0\epan`

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
