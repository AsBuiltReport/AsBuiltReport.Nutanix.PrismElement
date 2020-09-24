# :arrows_counterclockwise: Nutanix Prism Element As Built Report Changelog

## [1.1.2] 2020-09-24
### Added
- Added system licensing health check

### Fixed
- Improved table formatting
- Improved verbose logging

### Removed
- Removed support for PowerShell Core / 7 due to a [known issue](https://github.com/PowerShell/PowerShell/issues/12993).

## [1.1.0] 2020-07-16
### Added
- Added Nutanix logo to the cover page
- Added headers, footers & table captions/numbering
- Added Data Protection health checks
- Added reporting for;
    - Witness Server
    - Images
    - Healthchecks
    - Volume Groups

### Changed
- Updated default style to closely align with Nutanix image/colour branding
- Expanded reporting for AHV
    - VM Disks
    - VM NICs
    - VM Snapshots

### Fixed
- Improved error handling when working with Nutanix Prism APIs
- Improved script execution for running report on Nutanix clusters with different hypervisor types
- Improved table formatting

## [1.0.1] 2020-05-21
### Fixed
- Compatibility with AOS 5.10 and later

## [0.1.0] - 2019-10-18
### Added
- Initial release