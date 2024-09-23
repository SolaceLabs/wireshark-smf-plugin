**Note: this plugin is only compatible with Wireshark 4.4.x**

## Installation Instructions

1. Install [Wireshark 4.4](https://www.wireshark.org/download.html).

2. Download the corresponding zip file for your platform.

3. Unzip the folder and place the .dll (Windows) or .so (Mac/Linux) file in the Wireshark plugin folder, under `epan`. The plugin folder path varies for each OS.

### Windows Plugin Folder
Personal Plugin Folder: 

`%APPDATA%\Roaming\Wireshark\plugins\4.4\epan`

Global Plugin Folder: 

`C:\Program Files\Wireshark\plugins\4.4\plugins\epan`

### macOS/Linux Plugin Folder
Personal Plugin Folder: 

`~/.local/lib/wireshark/plugins/epan`

See [Wireshark Documentation on Plugin Folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) for more information on installing plugins. 

## Finding Plugin Folders and Verify Installation

1. Open Wireshark
2. Navigate to `Help>About Wireshark`
3. Under the `Folders` tab, you can find the location for global and personal folders
4. After installing the plugin, verify that the plugin is loaded by searching `smf` under the `Plugins` tab
