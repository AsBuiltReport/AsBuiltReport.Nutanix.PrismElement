function Invoke-AsBuiltReport.Nutanix.PrismElement {
    <#
    .SYNOPSIS  
        PowerShell script to document the configuration of Nutanix Prism infrastucture in Word/HTML/XML/Text formats
    .DESCRIPTION
        Documents the configuration of Nutanix Prism infrastucture in Word/HTML/XML/Text formats using PScribo.
    .NOTES
        Version:        1.0.0
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

    foreach ($Ntnx in $Target) {
        #region System Connection
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        $api_v1 = "https://" + $ntnx + ":9440/PrismGateway/services/rest/v1"
        $api_v2 = "https://" + $ntnx + ":9440/PrismGateway/services/rest/v2.0"
        $auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + $password ))
        $Header = @{"Authorization" = "Basic $auth" }
        #endregion System Connection

        #region API Collections
        $NtnxAlertsConfig = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/alerts/configuration/') -Headers $Header
        $NtnxAuthConfig = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/authconfig/') -Headers $Header
        $NtnxContainers = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/storage_containers/') -Headers $Header).entities
        $NtnxCluster = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/cluster/') -Headers $Header
        #$NtnxWitness = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/cluster/metro_witness/') -Headers $Header
        $NtnxSmtpConfig = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/cluster/smtp/') -Headers $Header
        $NtnxSnmpConfig = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/snmp/') -Headers $Header
        $NtnxFtStatus = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/cluster/domain_fault_tolerance_status/') -Headers $Header
        $NtnxDisks = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/disks/') -Headers $Header).entities
        $NtnxHosts = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/hosts/') -Headers $Header).entities
        $NtnxNetworks = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/networks/') -Headers $Header).entities
        $NtnxStoragePools = (Invoke-RestMethod -Method Get -Uri ($api_v1 + '/storage_pools/') -Headers $Header).entities
        $NtnxVMs = (Invoke-RestMethod -Method Get -Uri ($api_v1 + '/vms/') -Headers $Header).entities
        $NtnxCVMs = (Invoke-RestMethod -Method Get -Uri ($api_v1 + '/vms/') -Headers $Header).entities | Where-Object { $_.controllerVm }
        $NtnxNfsWhitelist = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/cluster/nfs_whitelist/') -Headers $Header
        $NtnxHealthChecks = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/health_checks/') -Headers $Header
        $NtnxLicense = Invoke-RestMethod -Method Get -Uri ($api_v1 + '/license/') -Headers $Header
        $NtnxProtectionDomains = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/protection_domains/') -Headers $Header).entities
        $NtnxPDReplications = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/protection_domains/replications/') -Headers $Header).entities
        $NtnxUnprotectedVMs = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/protection_domains/unprotected_vms/') -Headers $Header).entities
        $NtnxRemoteSites = Invoke-RestMethod -Method Get -Uri ($api_v1 + '/remote_sites/') -Headers $Header
        $NtnxDrSnapshots = (Invoke-RestMethod -Method Get -Uri ($api_v2 + '/remote_sites/dr_snapshots/') -Headers $Header).entities
        #endregion API Collections

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
                                $ClusterSummary | Where-Object { $_.'Timezone' -ne $Healthcheck.Cluster.Timezone } | Set-Style -Style Critical -Property 'Timezone'
                            }
                            if ($Healthcheck.Cluster.DataResiliency) {
                                $ClusterSummary | Where-Object { $_.'Data Resiliency Status' -ne 'OK' } | Set-Style -Style Critical -Property 'Data Resiliency Status'
                            }
                            $ClusterSummary | Table -List -Name 'Cluster Summary' -ColumnWidths 50, 50
                        }
                        #endregion Hardware

                        #region Network
                        Section -Style Heading3 'Network' {
                            $Network = [PSCustomObject]@{
                                'Cluster Virtual IP Address' = $NtnxCluster.cluster_external_ipaddress 
                                'iSCSI Data Services IP Address' = $NtnxCluster.cluster_external_data_services_ipaddress 
                                'External Subnet' = $NtnxCluster.external_subnet
                                'Internal Subnet' = $NtnxCluster.internal_subnet 
                                'DNS Server(s)' = $NtnxCluster.name_servers -join ', ' 
                                'NTP Server(s)' = ($NtnxCluster.ntp_servers | Sort-Object) -join ', '
                            }
                            $Network | Table -List -Name 'Network' -ColumnWidths 50, 50
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
                                    'CPUs' = $NtnxCVM.numVCPUs 
                                    'Memory' = "$([math]::Round(($NtnxCVM.memoryCapacityinBytes) / 1GB, 2)) GB"
                                }
                            }
                            if ($Healthcheck.CVM.PowerState) {
                                $ControllerVMs | Where-Object { $_.'Power State' -ne 'on' } | Set-Style -Style Critical -Property 'Power State'
                            }
                            $ControllerVMs | Sort-Object Host | Table -Name 'Controller VMs'
                        }
                        #endregion Controller VMs
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
                            $NtnxNfsWhitelists | Table -List -Name 'Filesystem Whitelists' -ColumnWidths 50, 50
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
                                $AuthenticationTypes | Table -List -Name 'Authentication Types' -ColumnWidths 50, 50
                            }
                            if ($NtnxAuthConfig.directory_list) {
                                Section -Style Heading4 'Directory List' {
                                    $DirectoryList = [PSCustomObject]@{
                                        'Directory Type' = $TextInfo.ToTitleCase(($NtnxAuthConfig.directory_list.directory_type).ToLower())
                                        'Directory Name' = $NtnxAuthConfig.directory_list.name
                                        'Domain' = $NtnxAuthConfig.directory_list.domain
                                        'URL' = $NtnxAuthConfig.directory_list.directory_url
                                        'Connection Type' = $NtnxAuthConfig.directory_list.connection_type
                                        'Group Search Type' = $TextInfo.ToTitleCase(($NtnxAuthConfig.directory_list.group_search_type).ToLower())
                                    }
                                    $DirectoryList | Table -List -Name 'Directory List' -ColumnWidths 50, 50
                                }
                            }
                        }
                    }
                    #endregion Authentication

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
                            $SmtpConfig | Table -List -Name 'SMTP Server' -ColumnWidths 50, 50
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
                            $AlertConfig | Table -List -Name 'Alert Email Configuration' -ColumnWidths 50, 50
                        }
                    }
                    #endregion Alerts Configuration

                    #region SNMP Configuration
                    if ($NtnxSnmpConfig.Enabled) {
                        Section -Style Heading3 'SNMP Configuration' {
                            $SnmpConfig = [PSCustomObject]@{
                                'Enabled' = $NtnxSnmpConfig.enabled              
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
                            $SnmpConfig | Table -List -Name 'SNMP Configuration' -ColumnWidths 50, 50
                        }
                    }
                    #endregion SNMP Configuration

                    #region Syslog Configuration
                    if ($NtnxSyslogConfig) {
                        Section -Style Heading3 'Syslog Configuration' {
                            # ToDo: Syslog Configuration
                        }
                    }
                    #endregion Syslog Configuration
                    
                    #region Licensing
                    if ($NtnxLicense) {
                        Section -Style Heading3 'Licensing' {
                            $Licensing = [PSCustomObject]@{
                                'Cluster' = $NtnxCluster.name 
                                'License' = $NtnxLicense.category
                            }
                            if ($Healthcheck.System.License) {
                                $Licensing | Where-Object { $_.'License' -ne $Healthcheck.System.License } | Set-Style -Style Warning -Property 'License'
                            }
                            $Licensing | Table -Name 'Licensing' -ColumnWidths 50, 50

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
                                    $LicensingFeatures | Sort-Object 'Feature' | Table -Name 'Licensing Features' -ColumnWidths 50, 50
                                }
                                #endregion Licensing Features
                            }
                        }
                    }
                    #endregion Licensing
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
                            $NtnxHostSummary | Table -Name 'Hardware Summary' -ColumnWidths 25, 25, 25, 25
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
                                        'Host Type' = $TextInfo.ToTitleCase(($NtnxHost.host_type).ToLower())
                                        'Node Serial' = $NtnxHost.serial 
                                        'Block Serial' = $NtnxHost.block_serial 
                                        'Block Model' = $NtnxHost.block_model_name 
                                        #'BMC Version' = $NtnxHost.bmc_version 
                                        #'BIOS Version' = $NtnxHost.bios_version
                                        'Storage Capacity' = "$([math]::Round(($NtnxHost.usage_stats.'storage.capacity_bytes') / 1099511627776, 2)) TiB"
                                        'Memory' = "$([math]::Round(($NtnxHost.memory_capacity_in_bytes) / 1073741824, 2)) GiB"
                                        'CPU Capacity' = "$([math]::Round(($NtnxHost.cpu_capacity_in_hz) / 1000000000, 1)) GHz"
                                        'CPU Model' = $NtnxHost.cpu_model
                                        'No. of CPU Cores' = $NtnxHost.num_cpu_cores
                                        'No. of Sockets' = $NtnxHost.num_cpu_sockets
                                        #ToDo: 'No. of Disks'
                                        #ToDo: 'No. of NICs'
                                        'No. of VMs' = $NtnxHost.num_vms
                                        'Oplog Disk %' = "$($NtnxHost.oplog_disk_pct) %"
                                        'Oplog Disk Size' = "$([math]::Round(($NtnxHost.oplog_disk_size) / 1073741824, 1)) GiB"
                                        'Monitored' = $NtnxHost.monitored
                                        'Hypervisor' = $NtnxHost.hypervisor_full_name
                                        #ToDo: 'Datastores'
                                    }
                                    $NtnxHostConfig | Table -List -Name 'Host Hardware Specifications' -ColumnWidths 50, 50
                                }
                                #endregion Host Hardware

                                #region Host Network
                                Section -Style Heading4 'Network' {
                                    $NtnxHostNetworks = [PSCustomObject]@{
                                        'Hypervisor IP Address' = $NtnxHost.hypervisor_address 
                                        'CVM IP Address' = $NtnxHost.service_vmexternal_ip 
                                        'IPMI IP Address' = $NtnxHost.ipmi_address
                                    }
                                    $NtnxHostNetworks | Table -Name 'Host Network Specifications'
                                }
                                #endregion Host Network 

                                #region Host Disks
                                if ($NtnxDisks) {
                                    Section -Style Heading5 'Disks' {
                                        $NtnxDisks = $NtnxDisks | Where-Object { $_.cvm_ip_address -eq $NtnxHost.service_vmexternal_ip } | Sort-Object 'Location'
                                        $NtnxHostDisks = foreach ($NtnxDisk in $NtnxDisks) {
                                            [PSCustomObject]@{
                                                'Location' = $NtnxDisk.location
                                                'Disk ID' = (($NtnxDisk.id) -split ('::'))[1]
                                                'Serial Number' = $NtnxDisk.disk_hardware_config.serial_number
                                                'Vendor' = $NtnxDisk.disk_hardware_config.vendor
                                                'Model' = $NtnxDisk.disk_hardware_config.model
                                                'Firmware' = $NtnxDisk.disk_hardware_config.current_firmware_version
                                                'Storage Tier' = $NtnxDisk.storage_tier_name
                                                'Host Name' = $NtnxHost.name
                                                'Hypervisor' = $NtnxDisk.host_name
                                                'Used (Physical)' = "$([math]::Round(($NtnxDisk.usage_stats.'storage.usage_bytes') / 1073741824, 2)) GiB"
                                                'Capacity (Logical)' = "$([math]::Round(($NtnxDisk.disk_size) / 1099511627776, 2)) TiB"
                                                'Self Encryption Drive' = Switch ($NtnxDisk.self_encrypting_drive) {
                                                    $true { 'Present' }
                                                    $false { 'Not Present' } 
                                                }
                                                'Status' = $TextInfo.ToTitleCase(($NtnxDisk.disk_status).ToLower())
                                                'Mode' = Switch ($NtnxDisk.online) {
                                                    $true { 'Online' }
                                                    $false { 'Offline' }  
                                                }
                                            }
                                        }
                                        if ($Healthcheck.Hardware.DiskStatus) {
                                            $NtnxHostDisks | Where-Object { $_.'Status' -ne 'normal' } | Set-Style -Style Critical -Property 'Status'
                                        }
                                        if ($Healthcheck.Hardware.DiskMode) {
                                            $NtnxHostDisks | Where-Object { $_.'Mode' -ne 'Online' } | Set-Style -Style Critical -Property 'Mode'
                                        }   
                                        if ($InfoLevel.Hosts -gt 2) {
                                            foreach ($NtnxHostDisk in $NtnxHostDisks) {
                                                Section -Style Heading5 "Disk $($NtnxHostDisk.Location)" {
                                                    $NtnxHostDisk | Table -List -Name "Host Disk $($NtnxHostDisk.Location) Specifications" -ColumnWidths 50, 50
                                                }
                                            }
                                        } else {
                                            $NtnxHostDisks | Table -Name 'Host Disk Specifications' -Columns 'Location', 'Disk ID', 'Serial Number', 'Firmware', 'Storage Tier', 'Capacity (Logical)', 'Status', 'Mode'
                                        }
                                    }
                                }
                                #endregion Host Disks

                                <#
                                #region Host Datastores
                                if (($NtnxDatastores) -and ($NtnxCluster.hypervisor_types -eq 'kVMware')) {
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
                                        $NtnxHostDatastores | Sort-Object 'Datastore' | Table -Name 'Host Datastores'
                                    }
                                }
                                #endregion Host Datastores
                                #>
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
                            $StoragePools | Sort-Object 'Storage Pool' | Table -Name 'Storage Pools'
                        }
                    }
                    #endregion Storage Pools

                    #region Containers
                    if ($NtnxContainers) {
                        Section -Style Heading3 'Containers' {
                            $Containers = foreach ($NtnxContainer in ($NtnxContainers | Sort-Object Name)) {
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
                                foreach ($container in $Containers) {
                                    Section -Style Heading4 "$($Container.Container)" {
                                        $Container | Table -List -Name 'Containers' -ColumnWidths 50, 50
                                    }
                                }
                            } else {
                                $Containers | Table -Name 'Containers' -Columns 'Container' , 'Replication Factor', 'Compression', 'Cache Deduplication', 'Capacity Deduplication', 'Erasure Coding', 'Free Capacity (Logical) TiB', 'Used Capacity TiB', 'Maximum Capacity TiB' 
                            }
                        }
                    }
                    #endregion Containers
                    #region Datastores
                    if ($NtnxCluster.hypervisor_types -eq 'kVMware') {
                        $NtnxDatastores = Invoke-RestMethod -Method Get -Uri ($api_v2 + '/storage_containers/datastores/') -Headers $Header
                        if ($NtnxDatastores) {
                            Section -Style Heading3 'Datastores' {
                                $Datastores = foreach ($NtnxDatastore in $NtnxDatastores) {
                                    [PSCustomObject]@{
                                        'Datastore' = $NtnxDatastore.datastore_name
                                        'Container' = $NtnxDatastore.storage_container_name
                                        'Free Capacity TiB' = [math]::Round(($NtnxDatastore.free_space) / 1099511627776, 2)
                                        'Used Capacity TiB' = [math]::Round((($NtnxDatastore.capacity) - ($NtnxDatastore.free_space)) / 1099511627776, 2)
                                        'Maximum Capacity TiB' = [math]::Round(($NtnxDatastore.capacity) / 1099511627776, 2)
                                        'VMs' = ($NtnxDatastore.vm_names).Count
                                    } 
                                }
                                $Datastores | Sort-Object 'Datastore' | Table -Name 'NFS Datastores'
                            }
                        }
                    }
                    #endregion Datastores
                }
            }
            #endregion Storage Section

            <#
            #region Virtual Machines Section
            if (($InfoLevel.VM -gt 0) -and ($NtnxVMs)) {
                # Excludes CVMs and VMs not running on a container
                $NtnxVirtualMachines = $NtnxVMs | Where-Object { ($_.controllervm -eq $false) -and ($_.runningOnNdfs -eq $true) } | Sort-Object vmName
                Section -Style Heading2 'Virtual Machines' {
                    $NtnxVMConfigs = foreach ($NtnxVM in $NtnxVirtualMachines) {
                        [PSCustomObject]@{
                            'VM' = $NtnxVM.vmName 
                            'Power State' = $TextInfo.ToTitleCase($NtnxVM.powerState) 
                            'Operating System' = $NtnxVM.guestOperatingSystem 
                            'IP Addresses' = $NtnxVM.ipAddresses -join ', '
                            'vCPUs' = $NtnxVM.numVCpus
                            'Memory' = "$([math]::Round(($NtnxVM.memoryCapacityInBytes) / 1GB, 0)) GB" 
                            'NICs' = $NtnxVM.numNetworkAdapters 
                            'Disk Capacity' = "$([math]::Round(($NtnxVM.diskCapacityinBytes) / 1GB, 2)) GB"
                            'Host' = $NtnxVM.hostName
                        }
                    }
                    if ($Healthcheck.VM.PowerState) {
                        $NtnxVMConfigs | Where-Object { $_.'Power State' -eq 'off' } | Set-Style -Style Warning -Property 'Power State'
                    }
                    if ($InfoLevel.VM -gt 2) {
                        foreach ($NtnxVMConfig in $NtnxVMConfigs) {
                            Section -Style Heading3 "$($NtnxVMConfig.VM)" {
                                $NtnxVMConfig | Table -List -Name "$($NtnxVMConfig.VM)" -ColumnWidths 50, 50
                            }
                        }
                    } else {
                        $NtnxVMConfigs | Table -Name 'Virtual Machines' -Columns 'VM', 'Power State', 'vCPUs', 'Memory', 'Disk Capacity'
                    }
                }
            }
            #endregion Virtual Machines Section
            #>

            #region Data Protection Section
            if (($InfoLevel.DataProtection -gt 0) -and ($NtnxProtectionDomains -or $NtnxRemoteSites)) {
                Section -Style Heading2 'Data Protection' {
                    #region Protection Domains
                    if ($NtnxProtectionDomains) {
                        Section -Style Heading3 'Protection Domains' {
                            $ProtectionDomains = foreach ($NtnxProtectionDomain in $NtnxProtectionDomains) {
                                [PSCustomObject]@{
                                    'Name' = $NtnxProtectionDomain.name 
                                    'Active' = $NtnxProtectionDomain.active 
                                    'Remote Site(s)' = $NtnxProtectionDomain.replication_links.remote_site_name 
                                    'Pending Replications' = $NtnxProtectionDomain.pending_replication_count 
                                    'Ongoing Replications' = $NtnxProtectionDomain.ongoing_replication_count 
                                    'Written Bytes' = $NtnxProtectionDomain.total_user_written_bytes     
                                }
                            }
                            $ProtectionDomains | Sort-Object 'Name' | Table -Name 'Protection Domains' 
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
                            $ProtectionDomainReplications | Sort-Object 'Name' | Table -Name 'Protection Domain Replication' 
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
                            $ProtectionDomainSnapshots | Sort-Object 'Protection Domain' | Table -Name 'Protection Domain Snapshots' 
                        }
                    }
                    #endregion Protection Domain Snapshots                   

                    #region Unprotected VMs
                    $NtnxUnprotectedVMs = $NtnxVMs | Where-Object { ($_.controllervm -eq $false) -and ($_.runningOnNdfs -eq $false) }
                    if ($NtnxUnprotectedVMs) {
                        Section -Style Heading3 'Unprotected VMs' {
                            $UnprotectedVMs = foreach ($NtnxUnprotectedVM in $NtnxUnprotectedVMs) {
                                [PSCustomObject]@{
                                    'VM Name' = $NtnxUnprotectedVM.vmName 
                                    'Power State' = $TextInfo.ToTitleCase($NtnxUnprotectedVM.powerState)
                                    'Operating System' = $NtnxUnprotectedVM.guestOperatingSystem 
                                    'CPUs' = $NtnxUnprotectedVM.numVCPUs 
                                    'NICs' = $NtnxUnprotectedVM.numNetworkAdapters 
                                    'Disk Capacity' = "$([math]::Round(($NtnxUnprotectedVM.diskCapacityinBytes) / 1GB, 2)) GB" 
                                    'Host' = $NtnxUnprotectedVM.hostName
                                }
                            }
                            $UnprotectedVMs | Sort-Object 'VM Name' | Table -Name 'Unprotected VMs' 
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
                            $RemoteSites | Sort-Object 'Name' | Table -Name 'Remote Sites' -List -ColumnWidths 50, 50
                        }
                    }
                    #endregion Remote Sites
                }
            }
            #endregion Data Protection Section
        }
    }
}