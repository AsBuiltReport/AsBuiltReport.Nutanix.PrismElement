<p align="center">
    <a href="https://www.asbuiltreport.com/" alt="AsBuiltReport"></a>
            <img src='https://raw.githubusercontent.com/AsBuiltReport/AsBuiltReport/master/AsBuiltReport.png' width="8%" height="8%" /></a>
</p>
<p align="center">
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.Nutanix.PrismElement/" alt="PowerShell Gallery Version">
        <img src="https://img.shields.io/powershellgallery/v/AsBuiltReport.Nutanix.PrismElement.svg" /></a>
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.Nutanix.PrismElement/" alt="PS Gallery Downloads">
        <img src="https://img.shields.io/powershellgallery/dt/AsBuiltReport.Nutanix.PrismElement.svg" /></a>
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.Nutanix.PrismElement/" alt="PS Platform">
        <img src="https://img.shields.io/powershellgallery/p/AsBuiltReport.Nutanix.PrismElement.svg" /></a>
</p>
<p align="center">
    <a href="https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/graphs/commit-activity" alt="GitHub Last Commit">
        <img src="https://img.shields.io/github/last-commit/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/master.svg" /></a>
    <a href="https://raw.githubusercontent.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/master/LICENSE" alt="GitHub License">
        <img src="https://img.shields.io/github/license/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement.svg" /></a>
    <a href="https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/graphs/contributors" alt="GitHub Contributors">
        <img src="https://img.shields.io/github/contributors/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement.svg"/></a>
</p>
<p align="center">
    <a href="https://twitter.com/AsBuiltReport" alt="Twitter">
            <img src="https://img.shields.io/twitter/follow/AsBuiltReport.svg?style=social"/></a>
</p>

<p align="center">
    <a href='https://ko-fi.com/B0B7DDGZ7' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://cdn.ko-fi.com/cdn/kofi1.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
</p>

# Nutanix Prism Element As Built Report

## :books: Sample Reports
### Sample Report - Default Style
Sample Nutanix Prism Element As Built Report with health checks, using default report style.

![Sample Nutanix Prism Element As Built Report](https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/blob/master/Samples/Sample%20Prism%20Element%20As%20Built%20Report.jpg "Sample Nutanix Prism Element As Built Report")

Sample Nutanix Prism Element As Built Report HTML file: [Sample Nutanix Prism Element As Built Report.html](https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/blob/master/Samples/Sample%20Nutanix%20Prism%20Element%20As%20Built%20Report.html "Sample Nutanix Prism Element As Built Report")
# :beginner: Getting Started
Below are the instructions on how to install, configure and generate a Nutanix Prism As Built report.

## :floppy_disk: Supported Versions
### **Prism / AOS**
The Nutanix Prism Element As Built Report supports the following AOS versions;
- AOS 5.x
- AOS 6.x

### **PowerShell**
This report is compatible with the following PowerShell versions;

| Windows PowerShell 5.1 | PowerShell 7 |
|:----------------------:|:------------:|
|   :white_check_mark:   |  :white_check_mark:  |

## :wrench: System Requirements

Each of the following modules will be automatically installed by following the [module installation](https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement#package-module-installation) procedure.

These modules may also be manually installed.

| Module Name        | Minimum Required Version |                              PS Gallery                               |                                   GitHub                                    |
|--------------------|:------------------------:|:---------------------------------------------------------------------:|:---------------------------------------------------------------------------:|
| PScribo            |          0.10.0           |      [Link](https://www.powershellgallery.com/packages/PScribo)       |         [Link](https://github.com/iainbrighton/PScribo/tree/master)         |
| AsBuiltReport.Core |          1.2.0           | [Link](https://www.powershellgallery.com/packages/AsBuiltReport.Core) | [Link](https://github.com/AsBuiltReport/AsBuiltReport.Core/releases/latest) |

### :closed_lock_with_key: Required Privileges
A user with Prism `Cluster Admin` privileges is required to generate a Nutanix Prism Element As Built Report.

## :package: Module Installation

### **PowerShell**
Open a PowerShell terminal window and install the required modules as follows;
```powershell
install-module -Name AsBuiltReport.Nutanix.PrismElement
```

### **GitHub**
If you are unable to use the PowerShell Gallery, you can still install the module manually. Ensure you repeat the following steps for the [system requirements](https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement#wrench-system-requirements) also.

1. Download the [latest release](https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement/releases/latest) zip from GitHub
2. Extract the zip file
3. Copy the folder `AsBuiltReport.Nutanix.PrismElement` to a path that is set in `$env:PSModulePath`. By default this could be `C:\Program Files\WindowsPowerShell\Modules` or `C:\Users\<user>\Documents\WindowsPowerShell\Modules`
4. Open a PowerShell terminal window and unblock the downloaded files with
    ```powershell
    $path = (Get-Module -Name AsBuiltReport.Nutanix.PrismElement -ListAvailable).ModuleBase; Unblock-File -Path $path\*.psd1; Unblock-File -Path $path\Src\Public\*.ps1; Unblock-File -Path $path\Src\Private\*.ps1
    ```
5. Close and reopen the PowerShell terminal window.

_Note: You are not limited to installing the module to those example paths, you can add a new entry to the environment variable PSModulePath if you want to use another path._

## :pencil2: Configuration
The Nutanix Prism As Built Report utilises a JSON file to allow configuration of report information, options, detail and healthchecks.

A Nutanix Prism report configuration file can be generated by executing the following command;
```powershell
New-AsBuiltReportConfig -Report Nutanix.PrismElement -FolderPath <User specified folder> -Filename <Optional>
```

Executing this command will copy the default Nutanix Prism report configuration file to a user specified folder.

All report settings can then be configured via the report configuration file.

The following provides information of how to configure each schema within the report's configuration file.

### Report
The **Report** schema provides configuration of the Nutanix Prism report information


| Sub-Schema         | Setting      | Default                               | Description                                                  |
|--------------------|--------------|---------------------------------------|--------------------------------------------------------------|
| Name               | User defined | Nutanix Prism Element As Built Report | The name of the As Built Report                              |
| Version            | User defined | 1.0                                   | The report version                                           |
| Status             | User defined | Released                              | The report release status                                    |
| ShowCoverPageImage | true / false | true                                  | Toggle to enable/disable the display of the cover page image |
| ShowHeaderFooter   | true / false | true                                  | Toggle to enable/disable document headers & footers          |
| ShowTableCaptions  | true / false | true                                  | Toggle to enable/disable table captions/numbering            |

### Options
The **Options** schema allows certain options within the report to be toggled on or off.

There are currently no options defined for this report.

### InfoLevel
The **InfoLevel** schema allows configuration of each section of the report at a granular level.

There are 4 levels (0-3) of detail granularity for each section as follows;

| Setting | InfoLevel         | Description                                                                                                                        |
|:-------:|-------------------|------------------------------------------------------------------------------------------------------------------------------------|
|    0    | Disabled          | Does not collect or display any information                                                                                        |
|    1    | Enabled / Summary | Provides summarised information for a collection of objects                                                                        |
|    2    | Detailed          | Provides detailed information for a collection of objects                                                                          |
|    3    | Adv Detailed      | Provides detailed information for individual objects, as well as information for associated objects (Disks, VM Disks, VM NICs etc) |
|    4    | Comprehensive     | Provides comprehensive information for individual objects                                                                          |

The table below outlines the default and maximum **InfoLevel** settings for each section.

| Sub-Schema     | Default Setting | Maximum Setting |
|----------------|:---------------:|:---------------:|
| Cluster        |        1        |        1        |
| System         |        2        |        4        |
| Hosts          |        2        |        3        |
| Storage        |        2        |        3        |
| VM             |        2        |        3        |
| DataProtection |        2        |        3        |

### Healthcheck
The **Healthcheck** schema is used to toggle health checks on or off.

#### Cluster
The **Cluster** schema is used to configure health checks for the Nutanix cluster.

| Sub-Schema      | Setting      | Default | Description                                              | Highlight                                                                                                                                                                                 |
|-----------------|--------------|---------|----------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Timezone        | true/false   | false   | Enables/Disables the timezone setting health check       |                                                                                                                                                                                           |
| TimezoneSetting | User Defined | UTC     | Checks the configured timezone for the Nutanix cluster   | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Not compliant with user defined setting                                                                                          |
| DataResiliency  | true/false   | true    | Checks the data resiliency status of the Nutanix cluster | ![OK](https://via.placeholder.com/15/36D068/000000?text=+) Data relisency status is possible <br>![Critical](https://via.placeholder.com/15/F55656/000000?text=+) Data relisency status is not possible |

#### CVM
The **CVM** schema is used to configure health checks for the Nutanix Controller Virtual Machine (CVM).

| Sub-Schema | Setting    | Default | Description                          | Highlight                                                                   |
|------------|------------|---------|--------------------------------------|-----------------------------------------------------------------------------|
| PowerState | true/false | true    | Highlights if the CVM is powered off | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) CVM is powered off |

#### System
The **System** schema is used to configure health checks for the entire system.

| Sub-Schema | Setting    | Default | Description                                        | Highlight                                                                                     |
|------------|------------|---------|----------------------------------------------------|-----------------------------------------------------------------------------------------------|
| ImageState | true/false | false   | Highlights images which are in an inactive state   | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Image is in an inactive state        |
| Licensing  | true/false | true    | Highlights if no license is applied to the cluster | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) No license is applied to the cluster |

#### Hardware
The **Hardware** schema is used to configure health checks for Nutanix hardware.

| Sub-Schema | Setting    | Default | Description                                       | Highlight                                                                           |
|------------|------------|---------|---------------------------------------------------|-------------------------------------------------------------------------------------|
| DiskStatus | true/false | true    | Highlights disks where their status is not normal | ![Critical](https://via.placeholder.com/15/F55656/000000?text=+) Disk status is not normal |
| DiskMode   | true/false | true    | Highlights disks which are offline                | ![Critical](https://via.placeholder.com/15/F55656/000000?text=+) Disk mode is offline      |

#### Storage
The **Storage** schema is used to configure health checks for Nutanix storage containers.

| Sub-Schema     | Setting    | Default | Description                                                                    | Highlight                                                                                   |
|----------------|------------|---------|--------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| Compression    | true/false | false   | Highlights storage containers which do not have compression enabled            | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Compression is disabled            |
| CacheDedupe    | true/false | false   | Highlights storage containers which do not have cache deduplication enabled    | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Cache deduplication is disabled    |
| CapacityDedupe | true/false | false   | Highlights storage containers which do not have capacity deduplication enabled | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Capacity deduplication is disabled |
| ErasureCoding  | true/false | false   | Highlights storage containers which do not have erasure coding enabled         | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Erasure coding is disabled         |

#### VM
The **VM** schema is used to configure health checks for virtual machines.

| Sub-Schema         | Setting    | Default | Description                               | Highlight                                                                       |
|--------------------|------------|---------|-------------------------------------------|---------------------------------------------------------------------------------|
| PowerState         | true/false | true    | Highlights VMs which are powered off      | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) VM is powered off      |
| NicConnectionState | true/false | true    | Highlights VM NICs which are disconnected | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) VM NIC is disconnected |

#### DataProtection
The **DataProtection** schema is used to configure health checks for Nutanix data protection.

| Sub-Schema          | Setting    | Default | Description                                    | Highlight                                                                                 |
|---------------------|------------|---------|------------------------------------------------|-------------------------------------------------------------------------------------------|
| CompressOnWire      | true/false | false   | Highlights if line compression is disabled     | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Line compression is disabled     |
| BandwidthThrottling | true/false | false   | Highlights if bandwidth throttling is disabled | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Bandwidth throttling is disabled |
| Proxy               | true/false | false   | Highlights if proxy setting is disabled        | ![Warning](https://via.placeholder.com/15/FFBC0B/000000?text=+) Proxy setting is disabled        |

## :computer: Examples

```powershell
# Generate a Nutanix Prism Element As Built Report for Nutanix cluster '172.16.30.110' using specified credentials. Export report to HTML & DOCX formats. Use default report style. Append timestamp to report filename. Save reports to 'C:\Users\Tim\Documents'
PS C:\> New-AsBuiltReport -Report Nutanix.PrismElement -Target '172.16.30.110' -Username 'admin' -Password 'nutanix/4u' -Format Html,Word -OutputFolderPath 'C:\Users\Tim\Documents' -Timestamp

# Generate a Nutanix Prism Element As Built Report for Nutanix cluster '172.16.30.110' using specified credentials and report configuration file. Export report to Text, HTML & DOCX formats. Use default report style. Save reports to 'C:\Users\Tim\Documents'. Display verbose messages to the console.
PS C:\> New-AsBuiltReport -Report Nutanix.PrismElement -Target '172.16.30.110' -Username 'admin' -Password 'nutanix/4u' -Format Text,Html,Word -OutputFolderPath 'C:\Users\Tim\Documents' -Verbose

# Generate a Nutanix Prism Element As Built Report for Nutanix cluster '172.16.30.110' using stored credentials. Export report to HTML & Text formats. Use default report style. Highlight environment issues within the report. Save reports to 'C:\Users\Tim\Documents'.
PS C:\> $Creds = Get-Credential
PS C:\> New-AsBuiltReport -Report Nutanix.PrismElement -Target '172.16.30.110' -Credential $Creds -Format Html,Text -OutputFolderPath 'C:\Users\Tim\Documents' -EnableHealthCheck

# Generate a single Nutanix Prism Element As Built Report for Nutanix clusters '172.16.30.110' and '172.16.30.130' using specified credentials. Report exports to WORD format by default. Apply custom style to the report. Reports are saved to the user profile folder by default.
PS C:\> New-AsBuiltReport -Report Nutanix.PrismElement -Target '172.16.30.110','172.16.30.130' -Username 'admin' -Password 'nutanix/4u' -StyleFilePath 'C:\Scripts\Styles\MyCustomStyle.ps1'

# Generate a Nutanix Prism Element As Built Report for Nutanix cluster '172.16.30.110' using specified credentials. Export report to HTML & DOCX formats. Use default report style. Reports are saved to the user profile folder by default. Attach and send reports via e-mail.
PS C:\> New-AsBuiltReport -Report Nutanix.PrismElement -Target '172.16.30.110' -Username 'admin' -Password 'nutanix/4u' -Format Html,Word -OutputFolderPath 'C:\Users\Tim\Documents' -SendEmail
```