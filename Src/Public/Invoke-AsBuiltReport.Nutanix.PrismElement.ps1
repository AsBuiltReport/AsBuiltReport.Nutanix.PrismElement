function Invoke-AsBuiltReport.Nutanix.PrismElement {
    <#
    .SYNOPSIS  
        PowerShell script to document the configuration of Nutanix Prism infrastucture in Word/HTML/XML/Text formats
    .DESCRIPTION
        Documents the configuration of Nutanix Prism infrastucture in Word/HTML/XML/Text formats using PScribo.
    .NOTES
        Version:        1.1.0
        Author:         Tim Carman
        Twitter:        @tpcarman
        Github:         tpcarman
        Credits:        Iain Brighton (@iainbrighton) - PScribo module
                        
    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement
    #>

    param (
        [String[]] $Target,
        [PSCredential] $Credential,
        [String]$StylePath
    )

    # Import JSON Configuration for Options and InfoLevel
    $InfoLevel = $ReportConfig.InfoLevel
    $Options = $ReportConfig.Options
    # Used to set values to TitleCase where required
    $TextInfo = (Get-Culture).TextInfo

    # If custom style not set, use default style
    if (!$StylePath) {
        & "$PSScriptRoot\..\..\AsBuiltReport.Nutanix.PrismElement.Style.ps1"
    }

    #region Workaround for SelfSigned Cert an force TLS 1.2
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
        $certCallback = @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback
        {
            public static void Ignore()
            {
                if(ServicePointManager.ServerCertificateValidationCallback ==null)
                {
                    ServicePointManager.ServerCertificateValidationCallback += 
                        delegate
                        (
                            Object obj, 
                            X509Certificate certificate, 
                            X509Chain chain, 
                            SslPolicyErrors errors
                        )
                        {
                            return true;
                        };
                }
            }
        }
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    #endregion Workaround for SelfSigned Cert an force TLS 1.2

    foreach ($NtnxPE in $Target) {

        #region API Collections
        $NtnxCluster = Get-NtnxApi -Version 2 -Uri '/cluster'
        $NtnxVMs = (Get-NtnxApi -Version 1 -Uri '/vms').entities
        $NtnxVirtualDisks = (Get-NtnxApi -Version 1 -Uri '/virtual_disks').entities
        $NtnxSnapshots = (Get-NtnxApi -Version 2 -Uri '/snapshots').entities
        $NtnxContainers = (Get-NtnxApi -Version 2 -Uri '/storage_containers').entities | Sort-Object Name
        $NtnxHosts = (Get-NtnxApi -Version 2 -Uri '/hosts').entities | Sort-Object Name
        $NtnxNetworks = (Get-NtnxApi -Version 2 -Uri '/networks').entities | Sort-Object Name
        $NtnxStoragePools = (Get-NtnxApi -Version 1 -Uri '/storage_pools').entities | Sort-Object Name
        $NtnxFtStatus = (Get-NtnxApi -Version 2 -Uri '/cluster/domain_fault_tolerance_status')
        $NtnxCVMs = (Get-NtnxApi -Version 1 -Uri '/vms').entities | Where-Object { $_.controllerVm }
        $NtnxWitness = Get-NtnxApi -Version 2 -Uri '/cluster/metro_witness'
        $NtnxNfsWhitelist = Get-NtnxApi -Version 2 -Uri '/cluster/nfs_whitelist'
        $NtnxAuthConfig = Get-NtnxApi -Version 2 -Uri '/authconfig'
        $NtnxImagesConfig = (Get-NtnxApi -Version 2 -Uri '/images').entities | Sort-Object Name
        $NtnxSmtpConfig = Get-NtnxApi -Version 2 -Uri '/cluster/smtp'
        $NtnxAlertsConfig = Get-NtnxApi -Version 2 -Uri 'alerts/configuration'
        $NtnxSnmpConfig = Get-NtnxApi -Version 2 -Uri '/snmp'   
        $NtnxLicense = Get-NtnxApi -Version 1 -Uri '/license/'
        $NtnxHealthChecks = (Get-NtnxApi -Version 2 -Uri '/health_checks').entities | Sort-Object name
        $NtnxDisks = (Get-NtnxApi -Version 2 -Uri '/disks').entities | Sort-Object Id
        $NtnxVolumeGroups = (Get-NtnxApi -Version 2 -Uri '/volume_groups').entities | Sort-Object Name
        $NtnxProtectionDomains = (Get-NtnxApi -Version 2 -Uri '/protection_domains').entities
        $NtnxRemoteSites = Get-NtnxApi -Version 1 -Uri '/remote_sites'
        $NtnxPDReplications = (Get-NtnxApi -Version 2 -Uri '/protection_domains/replications').entities
        $NtnxDrSnapshots = (Get-NtnxApi -Version 2 -Uri '/remote_sites/dr_snapshots').entities
        $NtnxUnprotectedVMs = (Get-NtnxApi -Version 2 -Uri '/protection_domains/unprotected_vms').entities
        if ($NtnxCluster.hypervisor_types -eq 'kVMware') {
            $NtnxDatastores = Get-NtnxApi -Version 2 -Uri '/storage_containers/datastores' | Sort-Object datastore_name
        }
        #endregion API Collections

        #region Lookups
        $NtnxContainerLookup = @{}
        foreach ($NtnxContainer in $NtnxContainers) {
            $NtnxContainerLookup.($NtnxContainer.storage_container_uuid) = $NtnxContainer.Name
        }

        $NtnxHostLookup = @{}
        foreach ($NtnxHost in $NtnxHosts) {
            $NtnxHostLookup.($NtnxHost.uuid) = $NtnxHost.hypervisor_address
        }

        $NtnxNetworkLookup = @{}
        $NtnxNetworkVlanLookup = @{}
        foreach ($NtnxNetwork in $NtnxNetworks) {
            $NtnxNetworkLookup.($NtnxNetwork.uuid) = $NtnxNetwork.name
            $NtnxNetworkVlanLookup.($NtnxNetwork.uuid) = $NtnxNetwork.vlan_id
        }

        $NtnxStoragePoolLookup = @{}
        foreach ($NtnxStoragePool in $NtnxStoragePools) {
            foreach ($DiskUuid in $NtnxStoragePool.diskUuids) {
                $NtnxStoragePoolLookup.($DiskUuid) = $NtnxStoragePool.name
            }
        }

        # Excludes CVMs and VMs not running on a container
        $NtnxVirtualMachines = $NtnxVMs | Where-Object { ($_.controllervm -eq $false) -and ($_.runningOnNdfs -eq $true) } | Sort-Object vmName
        $NtnxVirtualMachineLookup = @{}
        foreach ($NtnxVirtualMachine in $NtnxVirtualMachines) {
            $NtnxVirtualMachineLookup.($NtnxVirtualMachine.uuid) = $NtnxVirtualMachine.vmName
        }
        #endregion Lookups

        Section -Style Heading1 $NtnxCluster.name {
            #region Cluster Section
            if ($InfoLevel.Cluster -gt 0) {
                if ($NtnxCluster) { 
                    Section -Style Heading2 'Cluster' {
                        #region Hardware
                        Section -Style Heading3 'Hardware' {
                            $NtnxFtDomainStatus = $NtnxFtStatus | Where-Object { $_.domain_type -eq $NtnxCluster.fault_tolerance_domain_type }
                            $ClusterSummary = [PSCustomObject]@{
                                'Cluster Name' = $NtnxCluster.Name 
                                'Storage Type' = Switch ($NtnxCluster.storage_type) {
                                    'all_flash' { 'All Flash' }
                                    'all_hdd' { 'All HDD' }
                                    'mixed' { 'Hybrid' }
                                } 
                                'Hypervisor Types' = ($NtnxCluster.hypervisor_types).TrimStart('k').Replace('Kvm', 'AHV').Replace('VMware', 'ESXi') -join ', '
                                'Number of Nodes' = $NtnxCluster.num_nodes
                                'Number of Blocks' = ($NtnxCluster.block_serials | Select-Object -Unique).count
                                'Block Serial(s)' = ($NtnxCluster.block_serials | Sort-Object) -join ', ' 
                                'Fault Tolerance Domain Type' = $TextInfo.ToTitleCase(($NtnxCluster.fault_tolerance_domain_type.ToLower()))
                                'Data Resiliency Status' = if ($NtnxFtDomainStatus.component_fault_tolerance_status.static_configuration.number_of_failures_tolerable -gt 0) {
                                    "OK"
                                } else {
                                    "Critical"
                                }
                                "Desired Redundancy Factor" = "RF $($NtnxCluster.cluster_redundancy_state.desired_redundancy_factor)"
                                'Version' = $NtnxCluster.version 
                                'NCC Version' = ($NtnxCluster.ncc_version).TrimStart("ncc-") 
                                'Timezone' = $NtnxCluster.timezone
                            }
                            if ($Healthcheck.Cluster.Timezone) {
                                $ClusterSummary | Where-Object { $_.'Timezone' -ne $Healthcheck.Cluster.TimezoneSetting } | Set-Style -Style Warning -Property 'Timezone'
                            }
                            if ($Healthcheck.Cluster.DataResiliency) {
                                $ClusterSummary | Where-Object { $_.'Data Resiliency Status' -eq 'OK' } | Set-Style -Style OK -Property 'Data Resiliency Status'
                                $ClusterSummary | Where-Object { $_.'Data Resiliency Status' -ne 'OK' } | Set-Style -Style Critical -Property 'Data Resiliency Status'
                            }
                            $TableParams = @{
                                Name = "Cluster Summary - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $ClusterSummary | Table @TableParams
                        }
                        #endregion Hardware

                        #region Network
                        Section -Style Heading3 'Network' {
                            $Networks = [PSCustomObject]@{
                                'Virtual IP Address' = $NtnxCluster.cluster_external_ipaddress 
                                'iSCSI Data Services IP Address' = Switch ($NtnxCluster.cluster_external_data_services_ipaddress) {
                                    $null { '--' }
                                    default { $NtnxCluster.cluster_external_data_services_ipaddress }
                                }
                                'External Subnet' = $NtnxCluster.external_subnet
                                'Internal Subnet' = $NtnxCluster.internal_subnet 
                                'DNS Server(s)' = $NtnxCluster.name_servers -join ', ' 
                                'NTP Server(s)' = ($NtnxCluster.ntp_servers | Sort-Object) -join ', '
                            }
                            $TableParams = @{
                                Name = "Network - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $Networks | Table @TableParams
                        }
                        #endregion Network

                        #region Controller VMs
                        Section -Style Heading3 'Controller VMs' {
                            $ControllerVMs = foreach ($NtnxCVM in $NtnxCVMs) {
                                [PSCustomObject]@{
                                    'Name' = $NtnxCVM.vmName 
                                    'Power State' = $TextInfo.ToTitleCase($NtnxCVM.powerState)
                                    'Host' = $NtnxCVM.hostName 
                                    'IP Address' = $NtnxCVM.ipAddresses[0] 
                                    'Cores' = $NtnxCVM.numVCPUs 
                                    'Memory' = "$([math]::Round(($NtnxCVM.memoryCapacityinBytes) / 1073741824, 2)) GiB"
                                }
                            }
                            if ($Healthcheck.CVM.PowerState) {
                                $ControllerVMs | Where-Object { $_.'Power State' -ne 'on' } | Set-Style -Style Critical -Property 'Power State'
                            }
                            $TableParams = @{
                                Name = "Controller VMs - $($NtnxCluster.Name)"
                                ColumnWidths = 28, 10, 20, 20, 10, 12
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $ControllerVMs | Sort-Object Host | Table @TableParams
                        }
                        #endregion Controller VMs

                        #region Witness
                        if ($NtnxWitness) {
                            Section -Style Heading3 'Witness Server' {
                                $Witness = [PSCustomObject]@{
                                    'Witness Name' = $NtnxWitness.witness_name
                                    'IP Address' = $NtnxWitness.ip_addresses -join ', '
                                }
                                $TableParams = @{
                                    Name = "Witness Server - $($NtnxCluster.Name)"
                                    ColumnWidths = 50, 50
                                }
                                if ($Options.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $Witness | Table @TableParams
                            }
                        }
                        #endregion Witness
                    }
                }
            }
            #endregion Cluster Section

            #region System Section
            if ($InfoLevel.System -gt 0) {
                Section -Style Heading2 'System' {
                    #region Global Filesystem Whitelists
                    if ($NtnxNfsWhitelist) {
                        Section -Style Heading3 'Global Filesystem Whitelists' {
                            $NtnxNfsWhitelists = [PSCustomObject]@{
                                'Global Filesystem Whitelists' = $NtnxNfsWhitelist -join [Environment]::NewLine
                            }
                            $TableParams = @{
                                Name = "Filesystem Whitelists - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $NtnxNfsWhitelists | Table @TableParams
                        }
                    }
                    #endregion Global Filesystem Whitelists

                    #region Authentication
                    if ($NtnxAuthConfig) {
                        Section -Style Heading3 'Authentication' {
                            Section -Style Heading4 'Authentication Types' {
                                $AuthenticationTypes = [PSCustomObject]@{
                                    'Authentication Types' = $TextInfo.ToTitleCase(($NtnxAuthConfig.auth_type_list.Replace('_', ' ') -join ', ').ToLower())
                                }
                                $TableParams = @{
                                    Name = "Authentication Types - $($NtnxCluster.Name)"
                                    List = $true
                                    ColumnWidths = 50, 50
                                }
                                if ($Options.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $AuthenticationTypes | Table @TableParams
                            }
                            if ($NtnxAuthConfig.directory_list) {
                                Section -Style Heading4 'Directory List' {
                                    $DirectoryList = [PSCustomObject]@{
                                        'Directory Type' = $TextInfo.ToTitleCase(($NtnxAuthConfig.directory_list.directory_type).ToLower()).Replace("_"," ")
                                        'Directory Name' = $NtnxAuthConfig.directory_list.name
                                        'Domain' = $NtnxAuthConfig.directory_list.domain
                                        'URL' = $NtnxAuthConfig.directory_list.directory_url
                                        'Connection Type' = $NtnxAuthConfig.directory_list.connection_type
                                        'Group Search Type' = $TextInfo.ToTitleCase(($NtnxAuthConfig.directory_list.group_search_type).ToLower()).Replace("_"," ")
                                    }
                                    $TableParams = @{
                                        Name = "Directory List - $($NtnxCluster.Name)"
                                        List = $true
                                        ColumnWidths = 50, 50
                                    }
                                    if ($Options.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $DirectoryList | Table @TableParams
                                }
                            }
                        }
                    }
                    #endregion Authentication

                    #region Image Configurations
                    if ($NtnxImagesConfig) {
                        Section -Style Heading3 'Image Configuration' {
                            $Images = foreach ($NtnxImage in $NtnxImagesConfig) {
                                [PSCustomObject]@{
                                    'Image Name' = $NtnxImage.name
                                    'Annotation' = $NtnxImage.annotation
                                    'Type' = Switch ($NtnxImage.image_type) {
                                        'DISK_IMAGE' { 'DISK' }
                                        'ISO_IMAGE' { 'ISO' }
                                    }
                                    'State' = $TextInfo.ToTitleCase(($NtnxImage.image_state).ToLower())
                                    'Size' = Switch ($NtnxImage.vm_disk_size) {
                                        $null { '--' }
                                        default { "$([math]::Round(($NtnxImage.vm_disk_size) / 1073741824, 2)) GiB" }
                                    }
                                }
                            }
                            if ($Healthcheck.System.ImageState) {
                                $Images | Where-Object { $_.'State' -ne 'Active' } | Set-Style -Style Warning #-Property 'State'
                            }
                            $TableParams = @{
                                Name = "Image Configuration - $($NtnxCluster.Name)"
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $Images | Table @TableParams
                        } 
                    }
                    #endregion Image Configuration

                    #region SMTP
                    if ($NtnxSmtpConfig.Address) {
                        Section -Style Heading3 'SMTP Server' {
                            $SmtpConfig = [PSCustomObject]@{
                                'Address' = $NtnxSmtpConfig.address 
                                'Port' = $NtnxSmtpConfig.port 
                                'Username' = Switch ($NtnxSmtpConfig.username) {
                                    $null { "None" }
                                    default { $NtnxSmtpConfig.username }
                                }
                                'Password' = Switch ($NtnxSmtpConfig.password) {
                                    $null { "None" }
                                    default { $NtnxSmtpConfig.password }
                                }
                                'Secure Mode' = $TextInfo.ToTitleCase(($NtnxSmtpConfig.secure_mode).ToLower())
                                'From Email Address' = $NtnxSmtpConfig.from_email_address
                            }
                            $TableParams = @{
                                Name = "SMTP Server - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $SmtpConfig | Table @TableParams
                        }
                    }
                    #endregion SMTP

                    #region Alerts Configuration
                    if ($NtnxAlertConfig) {
                        Section -Style Heading3 'Alert Email Configuration' {
                            $AlertConfig = [PSCustomObject]@{
                                'Email Every Alert' = Switch ($NtnxAlertsConfig.enable) {
                                    $true { 'Yes' }
                                    $false { 'No' }
                                } 
                                'Email Daily Alert' = Switch ($NtnxAlertsConfig.enable_email_digest) {
                                    $true { 'Yes' }
                                    $false { 'No' }
                                } 
                                'Nutanix Support Email' = $NtnxAlertsConfig.default_nutanix_email 
                                'Additional Email Recipients' = $NtnxAlertsConfig.email_contact_list -join ', '                         
                            }
                            $TableParams = @{
                                Name = "Alert Email Configuration - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $AlertConfig | Table @TableParams
                        }
                    }
                    #endregion Alerts Configuration

                    #region SNMP Configuration
                    if ($NtnxSnmpConfig.Enabled) {
                        Section -Style Heading3 'SNMP Configuration' {
                            $SnmpConfig = [PSCustomObject]@{
                                'Enabled' = Switch ($NtnxSnmpConfig.enabled) {
                                    $true { 'Yes' }
                                    $false { 'No' }
                                }              
                                'Transports' = Switch ($NtnxSnmpConfig.snmp_transports) {
                                    $null { 'Not configured' }
                                    default { $NtnxSnmpConfig.snmp_transports -join ',' }
                                }
                                'Users' = Switch ($NtnxSnmpConfig.snmp_users) {
                                    $null { 'Not configured' }
                                    default { $NtnxSnmpConfig.snmp_users -join ',' }
                                }
                                'Traps' = Switch ($NtnxSnmpConfig.snmp_traps) {
                                    $null { 'Not configured' }
                                    default { $NtnxSnmpConfig.snmp_traps -join ',' }
                                }    
                            }
                            $TableParams = @{
                                Name = "SNMP Configuration - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $SnmpConfig | Table @TableParams
                        }
                    }
                    #endregion SNMP Configuration

                    #region Syslog Configuration
                    <#
                    if ($NtnxSyslogConfig) {
                        Section -Style Heading3 'Syslog Configuration' {
                            # ToDo: Syslog Configuration
                        }
                    }
                    #>
                    #endregion Syslog Configuration
                    
                    #region Licensing
                    if ($NtnxLicense) {
                        Section -Style Heading3 'Licensing' {
                            $Licensing = [PSCustomObject]@{
                                'Cluster' = $NtnxCluster.name 
                                'License' = $NtnxLicense.category
                            }
                            $TableParams = @{
                                Name = "Licensing - $($NtnxCluster.Name)"
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $Licensing | Table @TableParams

                            if ($InfoLevel.System -gt 2) {
                                #region Licensing Features
                                Section -Style Heading4 'Features' {
                                    $NtnxLicenseAllowanceMap = $NtnxLicense.allowanceMap
                                    foreach ($NtnxLicenseType in $NtnxLicenseAllowanceMap[0].PSObject.Properties) {
                                        Set-Variable -Name ('__{0}' -f $NtnxLicenseType.Name) -Value ($NtnxLicenseAllowanceMap | Select-Object -ExpandProperty $($NtnxLicenseType.Name))
                                    }
                                    
                                    $NtnxLicenseValues = Get-Variable -Name '__*'
                                    $LicensingFeatures = foreach ($NtnxLicenseValue in $NtnxLicenseValues.value) {
                                        [PSCustomObject]@{
                                            'Feature' = $NtnxLicenseValue.displayname
                                            'Permitted' = Switch ($NtnxLicenseValue.allowancesType) {
                                                'BOOLEAN' {
                                                    Switch ($NtnxLicenseValue.BoolValue.BoolValue) {
                                                        $true { 'Yes' }
                                                        $false { 'No' }
                                                    } 
                                                }
                                                'INTEGER_LIST' { ($NtnxLicenseValue.intValues).intValue }
                                            }
                                        }
                                    }
                                    $TableParams = @{
                                        Name = "Licensing Features - $($NtnxCluster.Name)"
                                        ColumnWidths = 50, 50
                                    }
                                    if ($Options.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $LicensingFeatures | Sort-Object 'Feature' | Table @TableParams
                                }
                                #endregion Licensing Features
                            }
                        }
                    }
                    #endregion Licensing

                    #region Health Checks
                    if ($NtnxHealthChecks) {
                        Section -Style Heading3 'Health Checks' {
                            #region Health Checks Summary Information
                            if ($InfoLevel.System -lt 4) {
                                $HealthChecks = [PSCustomObject]@{
                                        'All Checks' = $NtnxHealthChecks.Count
                                        #'Passed' = ''
                                        #'Failed' = ''
                                        #'Warning' = ''
                                        #'Error' = ''
                                        #'Off' = ''
                                        'Scheduled' = ($NtnxHealthChecks | Where-Object {$_.check_type -eq 'scheduled'}).Count
                                        'Not Scheduled' = ($NtnxHealthChecks | Where-Object {$_.check_type -eq 'not_scheduled'}).Count
                                        'Event Triggered' = ($NtnxHealthChecks | Where-Object {$_.check_type -eq 'event_driven'}).Count
                                    }
                                $TableParams = @{
                                    Name = "Health Checks - $($NtnxCluster.Name)"
                                    #List = $true
                                    #ColumnWidths = 50, 50
                                    ColumnWidths = 25, 25, 25, 25
                                }
                                if ($Options.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $HealthChecks | Table @TableParams
                            }
                            #endregion Health Checks Summary Information

                            #region Health Checks Comprehensive Information
                            if ($InfoLevel.System -eq 4) {
                                foreach ($NtnxHealthCheck in $NtnxHealthChecks) {
                                    Section -Style Heading4 "$($NtnxHealthCheck.name)" {
                                        $HealthChecksFull = [PSCustomObject]@{
                                            'Health Check' = $NtnxHealthCheck.name
                                            'Description' = $NtnxHealthCheck.description
                                            'Enabled' = Switch ($NtnxHealthCheck.enabled) {
                                                $true { 'Yes' }
                                                $false { 'No' }
                                            }
                                            'Auto Resolve' = Switch ($NtnxHealthCheck.auto_resolve) {
                                                $true { 'Yes' }
                                                $false { 'No' }
                                            }
                                            'Check Type' = $NtnxHealthCheck.check_type
                                            'Schedule Interval (secs)' = $NtnxHealthCheck.schedule_interval_in_secs
                                            'Affected Entities' = ($NtnxHealthCheck.affected_entity_types | Sort-Object) -join ', '
                                            'Classifications' = ($NtnxHealthCheck.classifications | Sort-Object) -join ', '
                                            'Causes' = $NtnxHealthCheck.causes
                                            'Resolutions' = $NtnxHealthCheck.resolutions
                                            'Scope' = ($NtnxHealthCheck.scope).TrimStart('k')
                                        }
                                        $TableParams = @{
                                            Name = "Health Check $($NtnxHealthCheck.name) - $($NtnxCluster.Name)"
                                            List = $true
                                            ColumnWidths = 50, 50
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $HealthChecksFull | Table @TableParams
                                    }
                                }
                            }
                            #endregion Health Checks Comprehensive Information
                        }
                    }
                    #endregion Health Checks
                }
            }
            #endregion System Section
            
            #region Hosts Section
            if (($InfoLevel.Hosts -gt 0) -and ($NtnxHosts)) {             
                Section -Style Heading2 'Hosts' {
                    #region Host Hardware Summary
                    if ($InfoLevel.Hosts -eq 1) {
                        Section -Style Heading3 'Hardware Summary' {
                            $NtnxHostSummary = [PSCustomObject]@{
                                'Hosts' = ($NtnxHosts | Where-Object { $_.Serial | Select-Object -Unique }).Count
                                'Blocks' = ($NtnxHosts | Where-Object { $_.Block_Serial | Select-Object -Unique }).Count
                                'Total CPU GHz' = [math]::Round(($NtnxHosts | Measure-Object -Property 'cpu_capacity_in_hz' -Sum).Sum / 1000000000, 1)
                                'Total Memory GiB' = [math]::Round(($NtnxHosts | Measure-Object -Property 'memory_capacity_in_bytes' -Sum).Sum / 1073741824, 2)
                                #ToDo: Total # Disks (SSD/HDD)
                                #ToDo: # of Network Switches
                            }
                            $TableParams = @{
                                Name = "Hardware Summary - $($NtnxCluster.Name)"
                                ColumnWidths = 25, 25, 25, 25
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $NtnxHostSummary | Table @TableParams
                        }
                    }
                    #endregion Host Hardware Summary
                    
                    #region Host Hardware Detailed
                    if ($InfoLevel.Hosts -ge 2) {
                        #region NtnxHost ForEach Loop
                        foreach ($NtnxHost in $NtnxHosts) {
                            #region Host Information
                            Section -Style Heading3 $NtnxHost.Name {
                                #region Host Hardware
                                Section -Style Heading4 'Hardware' {
                                    $NtnxHostConfig = [PSCustomObject]@{
                                        'Host Name' = $NtnxHost.name
                                        'Host Type' = $TextInfo.ToTitleCase(($NtnxHost.host_type).ToLower()).Replace("_"," ")
                                        'Node Serial' = $NtnxHost.serial 
                                        'Block Serial' = $NtnxHost.block_serial 
                                        'Block Model' = $NtnxHost.block_model_name 
                                        #'BMC Version' = $NtnxHost.bmc_version 
                                        #'BIOS Version' = $NtnxHost.bios_version
                                        'Storage Capacity' = "$([math]::Round(($NtnxHost.usage_stats.'storage.capacity_bytes') / 1099511627776, 2)) TiB"
                                        'Memory' = "$([math]::Round(($NtnxHost.memory_capacity_in_bytes) / 1073741824, 2)) GiB"
                                        'CPU Capacity' = "$([math]::Round(($NtnxHost.cpu_capacity_in_hz) / 1000000000, 1)) GHz"
                                        'CPU Model' = $NtnxHost.cpu_model
                                        'Number of CPU Cores' = $NtnxHost.num_cpu_cores
                                        'Number of Sockets' = $NtnxHost.num_cpu_sockets
                                        #ToDo: 'Number of Disks'
                                        #ToDo: 'Number of NICs'
                                        'Number of VMs' = $NtnxHost.num_vms
                                        'Oplog Disk %' = "$($NtnxHost.oplog_disk_pct) %"
                                        'Oplog Disk Size' = "$([math]::Round(($NtnxHost.oplog_disk_size) / 1073741824, 1)) GiB"
                                        'Monitored' = $NtnxHost.monitored
                                        'Hypervisor' = $NtnxHost.hypervisor_full_name
                                        #ToDo: 'Datastores'
                                    }
                                    $TableParams = @{
                                        Name = "Host Hardware Specifications - $($NtnxCluster.Name)"
                                        List = $true
                                        ColumnWidths = 50, 50
                                    }
                                    if ($Options.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $NtnxHostConfig | Table @TableParams
                                }
                                #endregion Host Hardware

                                #region Host Network
                                Section -Style Heading4 'Network' {
                                    $NtnxHostNetworks = [PSCustomObject]@{
                                        'Hypervisor IP Address' = $NtnxHost.hypervisor_address 
                                        'CVM IP Address' = $NtnxHost.service_vmexternal_ip 
                                        'IPMI IP Address' = Switch ($NtnxHost.ipmi_address) {
                                            $null { '--' }
                                            default { $NtnxHost.ipmi_address }
                                        }
                                    }
                                    $TableParams = @{
                                        Name = "Host Network Specifications - $($NtnxCluster.Name)"
                                    }
                                    if ($Options.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $NtnxHostNetworks | Table @TableParams
                                }
                                #endregion Host Network 

                                #region Host Disks
                                $NtnxHostDisks = $NtnxDisks | Where-Object { $_.node_uuid -eq $NtnxHost.uuid } | Sort-Object 'Location'
                                if ($NtnxHostDisks) {
                                    Section -Style Heading5 'Disks' {
                                        $HostDisks = foreach ($NtnxHostDisk in $NtnxHostDisks) {
                                            [PSCustomObject]@{
                                                'Location' = $NtnxHostDisk.location
                                                'Disk ID' = (($NtnxHostDisk.id) -split ('::'))[1]
                                                'Serial Number' = $NtnxHostDisk.disk_hardware_config.serial_number
                                                'Vendor' = $NtnxHostDisk.disk_hardware_config.vendor
                                                'Model' = $NtnxHostDisk.disk_hardware_config.model
                                                'Firmware' = $NtnxHostDisk.disk_hardware_config.current_firmware_version
                                                'Storage Tier' = $NtnxHostDisk.storage_tier_name
                                                'Used (Physical)' = "$([math]::Round(($NtnxHostDisk.usage_stats.'storage.usage_bytes') / 1073741824, 2)) GiB"
                                                'Capacity (Logical)' = "$([math]::Round(($NtnxHostDisk.disk_size) / 1099511627776, 2)) TiB"
                                                'Host Name' = $NtnxHost.name
                                                'Hypervisor' = $NtnxHostDisk.host_name
                                                'Storage Pool' = $NtnxStoragePoolLookup."$($NtnxHostDisk.disk_uuid)"
                                                'Self Encryption Drive' = Switch ($NtnxHostDisk.self_encrypting_drive) {
                                                    $true { 'Present' }
                                                    $false { 'Not Present' } 
                                                }
                                                'Status' = $TextInfo.ToTitleCase(($NtnxHostDisk.disk_status).ToLower())
                                                'Mode' = Switch ($NtnxHostDisk.online) {
                                                    $true { 'Online' }
                                                    $false { 'Offline' }  
                                                }
                                            }
                                        }
                                        if ($Healthcheck.Hardware.DiskStatus) {
                                            $HostDisks | Where-Object { $_.'Status' -ne 'normal' } | Set-Style -Style Critical -Property 'Status'
                                        }
                                        if ($Healthcheck.Hardware.DiskMode) {
                                            $HostDisks | Where-Object { $_.'Mode' -ne 'Online' } | Set-Style -Style Critical -Property 'Mode'
                                        }  
                                        if ($InfoLevel.Hosts -gt 2) {
                                            foreach ($NtnxHostDisk in $HostDisks) {
                                                Section -Style Heading5 "Disk $($NtnxHostDisk.Location)" {
                                                    $TableParams = @{
                                                        Name = "Host Disk $($NtnxHostDisk.Location) Specifications - $($NtnxCluster.Name)"
                                                        List = $true
                                                        ColumnWidths = 50, 50
                                                    }
                                                    if ($Options.ShowTableCaptions) {
                                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                                    }
                                                    $NtnxHostDisk | Table @TableParams
                                                }
                                            }
                                        } else {
                                            $TableParams = @{
                                                Name = "Host Disk Specifications - $($NtnxCluster.Name)"
                                                Columns = 'Location', 'Disk ID', 'Serial Number', 'Firmware', 'Storage Tier', 'Capacity (Logical)', 'Status', 'Mode'
                                            }
                                            if ($Options.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $HostDisks | Table @TableParams
                                        }
                                    }
                                }
                                #endregion Host Disks

                                #region Host Datastores (VMware Hosts Only)
                                if ($NtnxDatastores) {
                                    Section -Style Heading4 'Datastores' {
                                        $NtnxDatastores = $NtnxDatastores | Where-Object { $_.host_uuid -eq $NtnxHost.uuid }
                                        $NtnxHostDatastores = foreach ($NtnxHostDatastore in $NtnxDatastores) {
                                            [PSCustomObject]@{
                                                'Datastore' = $NtnxHostDatastore.datastore_name
                                                'Container' = $NtnxHostDatastore.storage_container_name
                                                'Free Capacity TiB' = [math]::Round(($NtnxHostDatastore.free_space) / 1099511627776, 2)
                                                'Used Capacity TiB' = [math]::Round((($NtnxHostDatastore.capacity) - ($NtnxHostDatastore.free_space)) / 1099511627776, 2)
                                                'Maximum Capacity TiB' = [math]::Round(($NtnxHostDatastore.capacity) / 1099511627776, 2)
                                                'VMs' = ($NtnxHostDatastore.vm_names).Count
                                            }
                                        }
                                        $TableParams = @{
                                            Name = "Host Datastores - $($NtnxCluster.Name)"
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $NtnxHostDatastores | Sort-Object 'Datastore' | Table @TableParams
                                    }
                                }
                                #endregion Host Datastores
                            }
                            #endregion Host Information
                        }
                        #endregion NtnxHost ForEach Loop  
                    }
                    #endregion Host Hardware Detailed
                }               
            }
            #endregion Hosts Section

            #region Storage Section
            if ($InfoLevel.Storage -gt 0) {
                Section -Style Heading2 'Storage' {
                    #region Containers
                    if ($NtnxContainers) {
                        Section -Style Heading3 'Containers' {
                            $Containers = foreach ($NtnxContainer in $NtnxContainers) {
                                [PSCustomObject]@{
                                    'Container' = $NtnxContainer.name 
                                    'Replication Factor' = "RF $($NtnxContainer.replication_factor)"
                                    #ToDo: 'Protection Domain'
                                    #ToDo: 'Datastore'
                                    'Compression' = Switch ($NtnxContainer.compression_enabled) {
                                        $true { 'On' }
                                        $false { 'Off' }
                                    }
                                    'Compression Delay' = Switch ($NtnxContainer.compression_delay_in_secs) {
                                        $null { '' }
                                        default { "$(($NtnxContainer.compression_delay_in_secs)*60) mins" }
                                    }
                                    'Cache Deduplication' = $TextInfo.ToTitleCase($NtnxContainer.finger_print_on_write)
                                    'Capacity Deduplication' = $TextInfo.ToTitleCase(($NtnxContainer.on_disk_dedup).ToLower())
                                    'Erasure Coding' = $TextInfo.ToTitleCase($NtnxContainer.erasure_code)
                                    'Free Capacity (Logical) TiB' = [math]::Round(($NtnxContainer.usage_stats.'storage.user_unreserved_free_bytes') / 1099511627776, 2)
                                    'Used Capacity TiB' = [math]::Round(((($NtnxContainer.usage_stats.'storage.user_capacity_bytes') - ($NtnxContainer.usage_stats.'storage.reserved_capacity_bytes')) - ($NtnxContainer.usage_stats.'storage.user_unreserved_free_bytes')) / 1099511627776, 2)
                                    'Maximum Capacity TiB' = [math]::Round((($NtnxContainer.usage_stats.'storage.user_capacity_bytes') - ($NtnxContainer.usage_stats.'storage.reserved_capacity_bytes')) / 1099511627776, 2)
                                    #ToDo: 'Reserved Capacity'
                                    'Advertised Capacity TiB' = [math]::Round(($NtnxContainer.advertised_capacity) / 1099511627776, 2)
                                    #ToDo: 'Data Reduction Ratio'
                                    #ToDo: 'Data Reduction Savings'
                                    #ToDo: 'Effective Free'
                                    #ToDo: 'Overall Efficiency'
                                    'Filesystem Whitelists Inherited' = $NtnxContainer.nfs_whitelist_inherited
                                    'Filesystem Whitelists' = $NtnxContainer.nfs_whitelist -join ', '
                                }
                            }
                            if ($Healthcheck.Storage.Compression) {
                                $Containers | Where-Object { $_.'Compression' -ne 'on' } | Set-Style -Style Warning -Property 'Compression'
                            }
                            if ($Healthcheck.Storage.CacheDedupe) {
                                $Containers | Where-Object { $_.'Cache Deduplication' -ne 'on' } | Set-Style -Style Warning -Property 'Cache Deduplication'
                            }
                            if ($Healthcheck.Storage.CapacityDedupe) {
                                $Containers | Where-Object { $_.'Capacity Deduplication' -ne 'on' } | Set-Style -Style Warning -Property 'Capacity Deduplication'
                            }
                            if ($Healthcheck.Storage.ErasureCoding) {
                                $Containers | Where-Object { $_.'Erasure Coding' -ne 'on' } | Set-Style -Style Warning -Property 'Erasure Coding'
                            }
                            if ($InfoLevel.Storage -gt 2) {
                                foreach ($Container in $Containers) {
                                    Section -Style Heading4 "$($Container.Container)" {
                                        $TableParams = @{
                                            Name = "Containers - $($NtnxCluster.Name)"
                                            List = $true
                                            ColumnWidths = 50, 50
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $Container | Table @TableParams
                                    }
                                }
                            } else {
                                $TableParams = @{
                                    Name = "Containers - $($NtnxCluster.Name)"
                                    Columns = 'Container' , 'Replication Factor', 'Compression', 'Cache Deduplication', 'Capacity Deduplication', 'Erasure Coding', 'Free Capacity (Logical) TiB', 'Used Capacity TiB', 'Maximum Capacity TiB' 
                                }
                                if ($Options.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $Containers | Table @TableParams
                            }
                        }
                    }
                    #endregion Containers

                    #region Volume Groups
                    if ($NtnxVolumeGroups) {
                        Section -Style Heading3 'Volume Groups' {
                            $VolumeGroups = foreach ($NtnxVolumeGroup in $NtnxVolumeGroups) {
                                [PSCustomObject]@{
                                    'Volume Group' = $NtnxVolumeGroup.Name
                                    'Number of Virtual Disks' = ($NtnxVolumeGroup.disk_list).Count
                                    'Flash Mode' = Switch ($NtnxVolumeGroup.flash_mode_enabled) {
                                        $true { 'Enabled' }
                                        default { 'Disabled' }
                                    }
                                    'Initiators' = $($NtnxVolumeGroups.attachment_list.iscsi_initiator_name | Sort-Object) -join ', '
                                    'Target IQN Prefix' = $NtnxVolumeGroup.iscsi_target
                                }
                            }
                            if ($InfoLevel.Storage -eq 1) {
                                $TableParams = @{
                                    Name = "Volume Groups - $($NtnxCluster.Name)"
                                    ColumnWidths = 22, 16, 12, 25, 25
                                }
                                if ($Options.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $VolumeGroups | Table @TableParams
                            } else {
                                foreach ($NtnxVolumeGroup in $NtnxVolumeGroups) {
                                    Section -Style Heading4 $($NtnxVolumeGroup.Name) {
                                        $VolumeGroup = [PSCustomObject]@{
                                            'Volume Group' = $NtnxVolumeGroup.Name
                                            'Number of Virtual Disks' = ($NtnxVolumeGroup.disk_list).Count
                                            'Flash Mode' = Switch ($NtnxVolumeGroup.flash_mode_enabled) {
                                                $true { 'Enabled' }
                                                default { 'Disabled' }
                                            }
                                            'Initiators' = $($NtnxVolumeGroups.attachment_list.iscsi_initiator_name | Sort-Object) -join ', '
                                            'Target IQN Prefix' = $NtnxVolumeGroup.iscsi_target
                                        }
                                        $TableParams = @{
                                            Name = "Volume Group $($NtnxVolumeGroup.Name) - $($NtnxCluster.Name)"
                                            List = $true
                                            ColumnWidths = 50, 50
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $VolumeGroup | Table @TableParams

                                        if ($InfoLevel.Storage -ge 3) {
                                            Section -Style Heading4 'Virtual Disks' {
                                                $VirtualGroupDisks = $NtnxVolumeGroup.disk_list | Sort-Object Index
                                                $NtnxVirtualGroupDisks = foreach ($VirtualGroupDisk in $VirtualGroupDisks) {
                                                    [PSCustomObject]@{
                                                        'Virtual Disk' = $VirtualGroupDisk.Index
                                                        'Total Capacity GiB' = [math]::Round(($VirtualGroupDisk.vmdisk_size_bytes) / 1073741824, 0)
                                                        'Container' = $NtnxContainerLookup."$($VirtualGroupDisk.storage_container_uuid)"
                                                        'Disk Path' = $VirtualGroupDisk.vmdisk_path 
                                                    }
                                                }
                                                $TableParams = @{
                                                    Name = "Virtual Disks - $($NtnxVolumeGroup.Name)"
                                                    ColumnWidths = 15, 15, 35, 35
                                                }
                                                if ($Options.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $NtnxVirtualGroupDisks | Table @TableParams
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    #endregion Volume Groups

                    #region Storage Pools
                    if ($NtnxStoragePools) {
                        Section -Style Heading3 'Storage Pools' {
                            $StoragePools = foreach ($NtnxStoragePool in $NtnxStoragePools) {
                                [PSCustomObject]@{
                                    'Storage Pool' = $NtnxStoragePool.name
                                    'Disks' = ($NtnxStoragePool.disks).count 
                                    'Free Capacity TiB' = [math]::Round((($NtnxStoragePool.capacity) - ($NtnxStoragePool.usageStats.'storage.disk_physical_usage_bytes')) / 1099511627776, 2)
                                    'Used Capacity TiB' = [math]::Round(($NtnxStoragePool.usageStats.'storage.disk_physical_usage_bytes') / 1099511627776, 2)
                                    'Maximum Capacity TiB' = [math]::Round(($NtnxStoragePool.capacity) / 1099511627776, 2)
                                } 
                            }
                            $TableParams = @{
                                Name = "Storage Pools - $($NtnxCluster.Name)"
                                ColumnWidths = 22, 12, 22, 22, 22
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $StoragePools | Sort-Object 'Storage Pool' | Table @TableParams
                        }
                    }
                    #endregion Storage Pools

                    #region VMWare Datastores
                    if ($NtnxDatastores) {
                        Section -Style Heading3 'VMware Datastores' {
                            $NfsDatastores = foreach ($NtnxDatastore in $NtnxDatastores) {
                                [PSCustomObject]@{
                                    'Datastore' = $NtnxDatastore.datastore_name
                                    'Host' = $NtnxDatastore.host_ip_address
                                    'Container' = $NtnxDatastore.storage_container_name
                                    'Free Capacity TiB' = [math]::Round(($NtnxDatastore.free_space) / 1099511627776, 2)
                                    'Used Capacity TiB' = [math]::Round((($NtnxDatastore.capacity) - ($NtnxDatastore.free_space)) / 1099511627776, 2)
                                    'Maximum Capacity TiB' = [math]::Round(($NtnxDatastore.capacity) / 1099511627776, 2)
                                    'Number of VMs' = ($NtnxDatastore.vm_names).Count
                                    'Virtual Machines' = Switch (($NtnxDatastore.vm_names).Count -gt 0) {
                                        $true { ($NtnxDatastore.vm_names | Sort-Object) -join ', ' }
                                        $false { '--' }

                                    }
                                } 
                            }
                            if ($InfoLevel.Storage -eq 1) {
                                $TableParams = @{
                                    Name = "VMware Datastores - $($NtnxCluster.Name)"
                                    Columns = 'Datastore', 'Host', 'Container', 'Free Capacity TiB', 'Used Capacity TiB', 'Maximum Capacity TiB', 'Number of VMs'
                                    ColumnWidths = 15, 15, 15, 15, 15, 15, 10
                                }
                                if ($Options.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $NfsDatastores | Sort-Object Datastore, Host | Table @TableParams
                            } else {
                                foreach ($NfsDatastore in $NfsDatastores) {
                                    Section -Style Heading4 $($NfsDatastore.Datastore) {
                                        $TableParams = @{
                                            Name = "Datastore $($NfsDatastore.Datastore) - $($NfsDatastore.Host)"
                                            List = $true
                                            ColumnWidths = 50, 50
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $NfsDatastore | Sort-Object Datastore, Host | Table @TableParams
                                    }
                                }
                            }
                        }
                    }
                    #endregion VMware Datastores
                }
            }
            #endregion Storage Section

            #region Virtual Machines Section
            if (($InfoLevel.VM -gt 0) -and ($NtnxVirtualMachines)) {
                Section -Style Heading2 'Virtual Machines' {
                    #region VM Summary Information
                    if ($InfoLevel.VM -eq 1) {
                        $VMSummary = foreach ($NtnxVM in $NtnxVirtualMachines) {
                            [PSCustomObject]@{
                                'VM Name' = $NtnxVM.vmName
                                'Power State' = $TextInfo.ToTitleCase($NtnxVM.powerState)
                                'Cores' = $NtnxVM.numVCpus
                                'Memory' = "$([math]::Round(($NtnxVM.memoryCapacityInBytes) / 1073741824, 0)) GiB"
                                'IP Addresses' = $NtnxVM.ipAddresses -join ', '
                                'Disk Capacity' = "$([math]::Round(($NtnxVM.diskCapacityinBytes) / 1073741824, 2)) GiB"                                
                            }
                        }
                        if ($Healthcheck.VM.PowerState) {
                            $VMSummary | Where-Object { $_.'Power State' -eq 'off' } | Set-Style -Style Warning -Property 'Power State'
                        }
                        $TableParams = @{
                            Name = "Virtual Machines - $($NtnxCluster.Name)"
                            ColumnWidths = 24, 11, 11, 11, 28, 15
                        }
                        if ($Options.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $VMSummary | Table @TableParams
                    }
                    #endregion VM Summary Information

                    #region VM Detailed Information
                    if ($InfoLevel.VM -ge 2) {
                        foreach ($NtnxVM in $NtnxVirtualMachines) {
                            Section -Style Heading3 "$($NtnxVM.vmName)" {
                                $VirtualMachines = [PSCustomObject]@{
                                    'VM Name' = $NtnxVM.vmName
                                    'Description' = Switch ($NtnxVM.description) {
                                        $null { '--' }
                                        default { $NtnxVM.description }
                                    }
                                    'Power State' = $TextInfo.ToTitleCase($NtnxVM.powerState)
                                    'Host' = Switch ($NtnxVM.hostName) {
                                        $null { '--' }
                                        default { $NtnxVM.hostName }
                                    }
                                    'Host IP' = Switch ($NtnxHostLookup."$($NtnxVM.hostUuid)") {
                                        $null { '--' }
                                        default { $NtnxHostLookup."$($NtnxVM.hostUuid)" }
                                    }
                                    'Memory' = "$([math]::Round(($NtnxVM.memoryCapacityInBytes) / 1073741824, 0)) GiB"
                                    'Cores' = $NtnxVM.numVCpus
                                    'Network Adapters' = $NtnxVM.numNetworkAdapters
                                    'Operating System' = Switch ($NtnxVM.guestOperatingSystem) {
                                        $null { '--' }
                                        default { $NtnxVM.guestOperatingSystem }
                                    } 
                                    'IP Addresses' = $NtnxVM.ipAddresses -join ', '
                                    'Storage Container' = $NtnxContainerLookup."$($NtnxVM.containerUuids)"
                                    'Virtual Disks' = ($NtnxVM.nutanixVirtualDisks).Count
                                    'Disk Capacity' = "$([math]::Round(($NtnxVM.diskCapacityinBytes) / 1073741824, 2)) GiB"
                                    #ToDo: Total Logical Capacity
                                    'NGT Enabled' = Switch ($NtnxVM.nutanixGuestTools.enabled) {
                                        $true { 'Yes' }
                                        $false { 'No' }
                                    }
                                    'NGT Mounted' = Switch ($NtnxVM.nutanixGuestTools.toolsMounted) {
                                        $true { 'Yes' }
                                        $false { 'No' }
                                    }
                                    'Protection Domain' = Switch ($NtnxVM.protectionDomainName) {
                                        $null { '--' }
                                        default { $NtnxVM.protectionDomainName }
                                    }
                                }
                                if ($Healthcheck.VM.PowerState) {
                                    $VirtualMachines | Where-Object { $_.'Power State' -eq 'off' } | Set-Style -Style Warning -Property 'Power State'
                                }
                                $TableParams = @{
                                    Name = "$($NtnxVM.vmName) - $($NtnxCluster.Name)"
                                    List = $true
                                    ColumnWidths = 50, 50
                                }
                                if ($Options.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $VirtualMachines | Table @TableParams

                                #region VM Virtual Disks
                                $NtnxVMVirtualDisks = $NtnxVirtualDisks | Where-Object {$_.attachedVMName -eq $($NtnxVM.vmName)} | Sort-Object diskAddress
                                if ($NtnxVMVirtualDisks) {
                                    Section -Style Heading4 'Virtual Disks' {
                                        $VMVirtualDisks = foreach ($NtnxVMVirtualDisk in $NtnxVMVirtualDisks) {
                                            [PSCustomObject]@{
                                                'Virtual Disk' = $NtnxVMVirtualDisk.diskAddress
                                                'Total Capacity' = "$([math]::Round(($NtnxVMVirtualDisk.diskCapacityInBytes) / 1073741824, 0)) GiB" 
                                                #ToDo: Total Logical Capacity 
                                                #ToDo: Add Container results for Hyper-V
                                                'Container' = Switch ( $NtnxVM.hypervisorType ) {
                                                    'kKVM' { $NtnxContainerLookup."$($NtnxVMVirtualDisk.containerUuid)" }
                                                    'kVMware' { ($NtnxVMVirtualDisk.nutanixNFSFilePath).Split('/')[1] }
                                                }
                                                #'Flash Mode'
                                            }
                                        }
                                        $TableParams = @{
                                            Name = "Virtual Disks - $($NtnxVM.vmName)"
                                            ColumnWidths = 33, 33, 34
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $VMVirtualDisks | Table @TableParams
                                    }
                                }
                                #endregion VM Virtual Disks

                                #region VM NICs
                                $NtnxVMNics = (Get-NtnxApi -Version 2 -Uri $('/vms/' + $($NtnxVM.uuid) + '/nics')).entities | Sort-Object network_uuid
                                if ($NtnxVMNics) {
                                    Section -Style Heading4 'VM NICs' {
                                        $VMNics = foreach ($NtnxVMNic in $NtnxVMNics) {
                                            [PSCustomObject]@{
                                                #ToDo: Find a way to get the 'Port Name' for VMware
                                                'Network Name' = $NtnxNetworkLookup."$($NtnxVMNic.network_uuid)"
                                                'Adapter Type' = $NtnxVMNic.adapter_type 
                                                'VLAN ID' = $NtnxNetworkVlanLookup."$($NtnxVMNic.network_uuid)"
                                                'MAC Address' = $NtnxVMNic.mac_address
                                                'IP Address' = ($NtnxVMNic.ip_address | Sort-Object) -join ', '
                                                'IP Addresses' = ($NtnxVMNic.ip_addresses | Sort-Object) -join ', '
                                                'Connected' = Switch ($NtnxVMNic.is_connected) {
                                                    $true { 'Yes' }
                                                    $false { 'No' }
                                                }
                                            }
                                        }
                                        if ($Healthcheck.VM.NicConnectionState) {
                                            $VMNics | Where-Object { $_.'Connected' -ne 'Yes' } | Set-Style -Style Warning #-Property 'Connected'
                                        }
                                        $TableParams = @{
                                            Name = "VM NICs - $($NtnxVM.vmName)"
                                            
                                        }
                                        # Build different table format based on hypervisor type
                                        Switch ( $NtnxVM.hypervisorType ) {
                                            'kVMware' {
                                                $TableParams['Columns'] = 'Adapter Type', 'MAC Address', 'IP Address', 'Connected'
                                                $TableParams['ColumnWidths'] = 25, 25, 25, 25
                                            }
                                            'kKVM' {
                                                $TableParams['Columns'] = 'Network Name', 'VLAN ID', 'MAC Address', 'IP Addresses', 'Connected'
                                                $TableParams['ColumnWidths'] = 20, 20, 20, 20, 20
                                            }
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $VMNics | Sort-Object 'Network Name' | Table @TableParams
                                    }
                                }
                                #endregion VM NICs

                                #region VM Snapshots
                                $NtnxVMSnapshots = $NtnxSnapshots | Where-Object {$_.vm_uuid -eq $NtnxVM.uuid}
                                if ($NtnxVMSnapshots) {
                                    Section -Style Heading3 'VM Snapshots' {
                                        $VMSnapshots = foreach ($NtnxVMSnapshot in $NtnxVMSnapshots) {
                                            $NtnxVMSnapshotTime = $NtnxVMSnapshot.created_time/1000
                                            $NtnxVMSnapshotDateTime = (Get-Date '1/1/1970').AddMilliseconds($NtnxVMSnapshotTime)
                                            [PSCustomObject]@{
                                                'Create Time' = $NtnxVMSnapshotDateTime
                                                'Snapshot Name' = $NtnxVMSnapshot.snapshot_name
                                                #'VM' = $NtnxVirtualMachineLookup."$($NtnxVMSnapshot.vm_uuid)"
                                            }
                                        }
                                        $TableParams = @{
                                            Name = "VM Snapshots - $($NtnxVM.vmName)"
                                        }
                                        if ($Options.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $VMSnapshots | Table @TableParams
                                    }
                                }
                                #endregion VM Snapshots
                            }
                        }
                    }
                    #endregion VM Detailed Information
                }
            }
            #endregion Virtual Machines Section

            #region Data Protection Section
            if (($InfoLevel.DataProtection -gt 0) -and ($NtnxProtectionDomains -or $NtnxRemoteSites)) {
                Section -Style Heading2 'Data Protection' {
                    #region Protection Domains
                    if ($NtnxProtectionDomains) {
                        Section -Style Heading3 'Protection Domains' {
                            $ProtectionDomains = foreach ($NtnxProtectionDomain in $NtnxProtectionDomains) {
                                [PSCustomObject]@{
                                    'Name' = $NtnxProtectionDomain.name 
                                    'Active' = Switch ($NtnxProtectionDomain.active) {
                                        $true { 'Yes' }
                                        $false { 'No' }
                                    }
                                    'Remote Site(s)' = $NtnxProtectionDomain.replication_links.remote_site_name 
                                    'Pending Replications' = $NtnxProtectionDomain.pending_replication_count 
                                    'Ongoing Replications' = $NtnxProtectionDomain.ongoing_replication_count 
                                    'Written Bytes' = $NtnxProtectionDomain.total_user_written_bytes     
                                }
                            }
                            $TableParams = @{
                                Name = "Protection Domains - $($NtnxCluster.Name)"
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $ProtectionDomains | Sort-Object 'Name' | Table @TableParams 
                        }
                    }
                    #endregion Protection Domains
                    
                    #region Protection Domain Replication
                    if (($InfoLevel.DataProtection -eq 3) -and ($NtnxPDReplications)) {
                        Section -Style Heading3 'Protection Domain Replication' {
                            $ProtectionDomainReplications = foreach ($NtnxPDReplication in $NtnxPDReplications) {
                                [PSCustomObject]@{
                                    'Name' = $NtnxPDReplication.protection_domain_name 
                                    'Remote Sites' = $NtnxPDReplication.remote_site_name -join ', '
                                    'Snapshot ID' = $NtnxPDReplication.snapshot_id 
                                    'Data Completed' = "$([math]::Round(($NtnxPDReplication.completed_bytes) / 1099511627776, 2)) TiB" 
                                    '% Complete' = $NtnxPDReplication.completed_percentage
                                    'Minutes to Complete' = [math]::Round(($NtnxPDReplication.replication_time_to_complete_secs) / 60, 2)
                                }
                            }
                            $TableParams = @{
                                Name = "Protection Domain Replication - $($NtnxCluster.Name)"
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $ProtectionDomainReplications | Sort-Object 'Name' | Table @TableParams 
                        }
                    }
                    #endregion Protection Domain Replication                   
                    
                    #region Protection Domain Snapshots
                    if (($InfoLevel.DataProtection -eq 3) -and ($NtnxDrSnapshots)) {
                        Section -Style Heading3 'Protection Domain Snapshots' {
                            $ProtectionDomainSnapshots = foreach ($NtnxDrSnapshot in $NtnxDrSnapshots) {
                                [PSCustomObject]@{
                                    'Protection Domain' = $NtnxDrSnapshot.protection_domain_name 
                                    'State' = ($NtnxDrSnapshot.state).ToLower() 
                                    'Snapshot ID' = $NtnxDrSnapshot.snapshot_id 
                                    'Consistency Groups' = $NtnxDrSnapshot.consistency_groups -join ', '
                                    'Remote Site(s)' = $NtnxDrSnapshot.remote_site_names -join ', '
                                    'Size in Bytes' = $NtnxDrSnapshot.size_in_bytes
                                }
                            }
                            $TableParams = @{
                                Name = "Protection Domain Snapshots - $($NtnxCluster.Name)"
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $ProtectionDomainSnapshots | Sort-Object 'Protection Domain' | Table @TableParams
                        }
                    }
                    #endregion Protection Domain Snapshots

                    #region Unprotected VMs
                    if ($NtnxUnprotectedVMs) {
                        Section -Style Heading3 'Unprotected VMs' {
                            $UnprotectedVMs = foreach ($NtnxUnprotectedVM in $NtnxUnprotectedVMs) {
                                [PSCustomObject]@{
                                    'VM Name' = $NtnxUnprotectedVM.vm_name 
                                    'Power State' = $TextInfo.ToTitleCase($NtnxUnprotectedVM.power_state)
                                    'Operating System' = Switch ($NtnxUnprotectedVM.guest_operating_system) {
                                        $null { '--' }
                                        default { $NtnxUnprotectedVM.guest_operating_system }
                                    }
                                    'Cores' = $NtnxUnprotectedVM.num_vcpus
                                    'Network Adapters' = $NtnxUnprotectedVM.num_network_adapters 
                                    'Disk Capacity' = "$([math]::Round(($NtnxUnprotectedVM.disk_capacity_in_bytes) / 1073741824, 2)) GiB" 
                                    'Host' = $NtnxUnprotectedVM.host_name
                                }
                            }
                            $TableParams = @{
                                Name = "Unprotected VMs - $($NtnxCluster.Name)"
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $UnprotectedVMs | Sort-Object 'VM Name' | Table @TableParams 
                        }
                    }
                    #endregion Unprotected VMs

                    #region Remote Sites
                    if ($NtnxRemoteSites) {
                        Section -Style Heading3 'Remote Sites' {
                            $RemoteSites = foreach ($NtnxRemoteSite in $NtnxRemoteSites) {
                                [PSCustomObject]@{
                                    'Name' = $NtnxRemoteSite.name 
                                    'Capabilities' = ($TextInfo.ToTitleCase(($NtnxRemoteSite.capabilities).ToLower()) | Sort-Object) -join ', ' 
                                    'Remote Addresses' = "$(($NtnxRemoteSite.remoteIpPorts | Get-Member -MemberType NoteProperty).Name):2020"
                                    'Metro Ready' = Switch ($NtnxRemoteSite.metroReady) {
                                        $true { 'Yes' }
                                        $false { 'No' }
                                    }
                                    'Use SSH Tunnel' = Switch ($NtnxRemoteSite.sshEnabled) {
                                        $true { 'Yes' }
                                        $false { 'No' }
                                    }
                                    'Compress On Wire' = Switch ($NtnxRemoteSite.compressionEnabled) {
                                        $true { 'On' }
                                        $false { 'Off' }
                                    }
                                    'Enable Proxy' = Switch ($NtnxRemoteSite.proxyEnabled) {
                                        $true { 'On' }
                                        $false { 'Off' }
                                    }
                                    'Bandwidth Throttling' = Switch ($NtnxRemoteSite.bandwidthPolicyEnabled) {
                                        $true { 'On' }
                                        $false { 'Off' }
                                    }                    
                                }
                            }
                            if ($Healthcheck.DataProtection.CompressOnWire) {
                                $RemoteSites | Where-Object { $_.'Compress On Wire' -eq 'On' } | Set-Style -Style Warning -Property 'Compress On Wire'
                            }
                            if ($Healthcheck.DataProtection.CompressOnWire) {
                                $RemoteSites | Where-Object { $_.'Enable Proxy' -eq 'On' } | Set-Style -Style Warning -Property 'Enable Proxy'
                            }
                            if ($Healthcheck.DataProtection.CompressOnWire) {
                                $RemoteSites | Where-Object { $_.'Bandwidth Throttling' -eq 'On' } | Set-Style -Style Warning -Property 'Bandwidth Throttling'
                            }
                            $TableParams = @{
                                Name = "Remote Sites - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 50, 50
                            }
                            if ($Options.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $RemoteSites | Sort-Object 'Name' | Table @TableParams
                        }
                    }
                    #endregion Remote Sites
                }
            }
            #endregion Data Protection Section
        }
    }
}