# :arrows_clockwise: Nutanix Prism Element As Built Report Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] Unreleased

### Added
- Add CodeQL workflow
- Add GitHub release workflow to add post to Bluesky social platform
- Add reporting for AHV networking (Experimental feature)

### Fixed
- Fix [SSL error](https://learn.microsoft.com/en-us/dotnet/fundamentals/syslib-diagnostics/syslib0014) in PowerShell 7
- Fix SNMP section not displaying content
- Fix License feature section showing blank values
- Fix colour placeholders in `README.md`

### Changed
- Refactor code to utilise private functions
- Update module manifest `RequiredModules` updated for AsBuiltReport.Core 1.4.3
- Change table column widths for list tables to 40/60
- Update bug and feature request templates
- Add try/catch code blocks for improved error handling
- Update PSScriptAnalyzer settings

## [1.2.1] - 2022-07-07

### Fixed
- Fix license reporting in AOS 6.x ([Fix #16](https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/issues/16))
- Fix colour placeholders in `README.md`

### Changed
- Update sample reports
- Exclude some section headings from TOC to improve formatting

## [1.2.0] - 2021-07-13

### Added
- Add PowerShell 7 compatibility
- Add reporting of Secure Boot for host hardware

### Fixed
- Fix reporting of clusters with AHV Storage Only nodes (Fixes #10)
- Fix reporting of containers used capacity

## [1.1.2] - 2020-09-24
### Added
- Add system licensing health check

### Fixed
- Improve table formatting
- Improve verbose logging

### Removed
- Remove support for PowerShell Core / 7 due to a [known issue](https://github.com/PowerShell/PowerShell/issues/12993).

## [1.1.0] - 2020-07-16
### Added
- Add Nutanix logo to the cover page
- Add headers, footers & table captions/numbering
- Add Data Protection health checks
- Add reporting for;
    - Witness Server
    - Images
    - Healthchecks
    - Volume Groups

### Changed
- Update default style to closely align with Nutanix image/colour branding
- Expande reporting for AHV
    - VM Disks
    - VM NICs
    - VM Snapshots

### Fixed
- Improve error handling when working with Nutanix Prism APIs
- Improve script execution for running report on Nutanix clusters with different hypervisor types
- Improve table formatting

## [1.0.1] - 2020-05-21
### Fixed
- Compatibility with AOS 5.10 and later

## [0.1.0] - 2019-10-18
### Added
- Initial release