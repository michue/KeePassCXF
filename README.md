# KeePassCXF

[![GitHub](https://img.shields.io/badge/GitHub-michue%2FKeePassCXF-black?logo=github&style=for-the-badge)](https://github.com/michue/KeePassCXF) [![GitHub Release](https://img.shields.io/github/v/release/michue/KeePassCXF?include_prereleases&style=for-the-badge)](https://github.com/michue/KeePassCXF/releases/latest) [![GitHub Release Date](https://img.shields.io/github/release-date-pre/michue/KeePassCXF?style=for-the-badge)](https://github.com/michue/KeePassCXF/releases/latest)

**[Installation](#installation)** | **[User Guide](docs/user-guide.md)** | **[FAQ & Troubleshooting](docs/troubleshooting-faq.md)** | **[Corporate Deployment](docs/corporate-deployment.md)**

A KeePass plugin for importing and exporting credentials using the FIDO Alliance [Credential Exchange Format (CXF)](https://fidoalliance.org/fido-alliance-credential-exchange-specifications-overview/). 


## Requirements

- [KeePass](https://keepass.info/) 2.54 or later

**Current limitations:**

* The plugin currently only imports and exports passkey credentials. Other credential types are ignored for now. 
* The standard CXF 1.0 has been proposed in March 2026 and might change in future.

## How to use

The plugin integrates with KeePass's built-in Import and Export dialogs and shows up in the group *Password Managers*. There you can simply select *Client Exchange Format (CXF)* as the file type.

## Installation

1. Download the latest `KeePassCXFPlugin-*.zip` package from [Releases](https://github.com/michue/KeePassCXF/releases)
2. Copy `KeePassCXF.dll` or `KeePassCXF.plgx` into KeePass's `plugins` folder (the usual [installation procedure](https://keepass.info/help/v2/plugins.html#setup) for KeePass plugins)

## Building

### Prerequisites

| Requirement | Notes |
|---|---|
| Visual Studio 2026 | With .NET desktop development workload |
| .NET Framework 4.8 SDK | For KeePassCFXPlugin |
| KeePass.exe (2.54, compile reference) | Place at `build\KeePass.exe` - minimum supported version, used only for compilation |
| KeePass.exe (current, for debugging) | Place at `build\KeePass\KeePass.exe` - your installed/current version, used to launch KeePass during development |

Requires Visual Studio with .NET desktop development tools, the .NET SDK selected by `global.json`, and the .NET Framework 4.8 targeting pack.

Then run the build script as Administrator - builds the MSIX, signs it, and installs:

### Build and test the plugin

```powershell
dotnet build src/KeePassCXFPlugin/KeePassCXFPlugin.csproj -c Release
```

The build process copies the plugin into `build\KeePass\plugins`. Run `build\KeePass\KeePass.exe` to test the plugin.

To install the plugin, copy the DLL from `build\Release\` to your KeePass `plugins` folder and (re)start KeePass.

### Run the tests

```powershell
dotnet test --project src/KeePassPasskeyPlugin.Tests/KeePassPasskeyPlugin.Tests.csproj
```

### Debug in KeePass

Open the solution `KeePassCXF.slnx` in Visual Studio. Choose the `Debug` configuration, select `KeePassCXFPlugin` as the startup project and select `KeePass` as launch configuration.

## Mentions

The initial project scaffolding was adapted from [KeePassPasskey](https://github.com/yusei36/KeePassPasskey) by Uwe Kögel.

## License

Copyright © 2026 Michael Hüpkes

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

See [LICENSE](LICENSE) for the full license text.
