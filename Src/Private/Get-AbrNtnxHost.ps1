function Get-AbrNtnxHost {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Nutanix host information.
    .DESCRIPTION
        Documents the configuration of Nutanix Prism Element in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.1.0
        Author:         Tim Carman
        Twitter:        @tpcarman
        Github:         tpcarman
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement
    #>

    [CmdletBinding()]
    param (

    )

    begin {
        Write-PScriboMessage "Host InfoLevel set at $($InfoLevel.Host)."

    }

    process {
        try{
            if ($InfoLevel.Host -gt 0) {
                Write-PScriboMessage "Performing Host API reference calls"
                $NtnxDisks = (Get-NtnxApi -Version 2 -Uri '/disks').entities | Sort-Object Id
                if ($NtnxHosts) {
                    Section -Style Heading2 'Hosts' {
                        #region Host Hardware Summary
                        if ($InfoLevel.Host -eq 1) {
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
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $NtnxHostSummary | Table @TableParams
                            }
                        }
                        #endregion Host Hardware Summary

                        #region Host Hardware Detailed
                        if ($InfoLevel.Host -ge 2) {
                            #region NtnxHost ForEach Loop
                            foreach ($NtnxHost in $NtnxHosts) {
                                #region Host Information
                                Section -Style Heading3 $NtnxHost.Name {
                                    #region Host Hardware
                                    Section -Style Heading4 'Hardware' {
                                        $NtnxHostConfig = [PSCustomObject]@{
                                            'Name' = $NtnxHost.name
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
                                            'Monitored' = if ($NtnxHost.monitored) { 'Yes' } else { 'No' }
                                            'Hypervisor' = $NtnxHost.hypervisor_full_name
                                            #ToDo: 'Datastores'
                                            'Secure Boot Enabled' = if ($NtnxHost.is_secure_booted) { 'Yes' } else { 'No' }
                                        }
                                        $TableParams = @{
                                            Name = "Host Hardware Specifications - $($NtnxCluster.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
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
                                            'IPMI IP Address' = if ($null -ne $NtnxHost.ipmi_address) { $NtnxHost.ipmi_address } else { '--' }
                                        }
                                        $TableParams = @{
                                            Name = "Host Network Specifications - $($NtnxCluster.Name)"
                                            ColumnWidths = 33, 34, 33
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $NtnxHostNetworks | Table @TableParams
                                    }
                                    #endregion Host Network

                                    #region Host Disks
                                    $NtnxHostDisks = $NtnxDisks | Where-Object { $_.node_uuid -eq $NtnxHost.uuid } | Sort-Object 'Location'
                                    if ($NtnxHostDisks) {
                                        Section -Style Heading4 'Disks' {
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
                                                    'Self Encryption Drive' = if ($NtnxHostDisk.self_encrypting_drive) { 'Present' } else { 'Not Present' }
                                                    'Status' = $TextInfo.ToTitleCase(($NtnxHostDisk.disk_status).ToLower())
                                                    'Mode' = if ($NtnxHostDisk.online) { 'Online' } else { 'Offline' }
                                                }
                                            }
                                            if ($Healthcheck.Hardware.DiskStatus) {
                                                $HostDisks | Where-Object { $_.'Status' -ne 'normal' } | Set-Style -Style Critical -Property 'Status'
                                            }
                                            if ($Healthcheck.Hardware.DiskMode) {
                                                $HostDisks | Where-Object { $_.'Mode' -ne 'Online' } | Set-Style -Style Critical -Property 'Mode'
                                            }
                                            if ($InfoLevel.Host -ge 3) {
                                                foreach ($NtnxHostDisk in $HostDisks) {
                                                    Section -Style Heading5 -ExcludeFromTOC "Disk $($NtnxHostDisk.Location)" {
                                                        $TableParams = @{
                                                            Name = "Host Disk $($NtnxHostDisk.Location) Specifications - $($NtnxCluster.Name)"
                                                            List = $true
                                                            ColumnWidths = 40, 60
                                                        }
                                                        if ($Report.ShowTableCaptions) {
                                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                                        }
                                                        $NtnxHostDisk | Table @TableParams
                                                    }
                                                }
                                            } else {
                                                $TableParams = @{
                                                    Name = "Host Disk Specifications - $($NtnxCluster.Name)"
                                                    Columns = 'Location', 'Disk ID', 'Serial Number', 'Firmware', 'Storage Tier', 'Capacity (Logical)', 'Status', 'Mode'
                                                    ColumnWidths = 10, 10, 25, 12, 10, 13, 10, 10
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $HostDisks | Table @TableParams
                                            }
                                        }
                                    }
                                    #endregion Host Disks

                                    #region Host Datastores (VMware Hosts Only)
                                    if (($NtnxDatastores) -and ($NtnxHost.hypervisor_type -eq 'kVMware')) {
                                        Section -Style Heading4 'Datastores' {
                                            $NtnxHostDatastores = $NtnxDatastores | Where-Object { $_.host_uuid -eq $NtnxHost.uuid }
                                            $NtnxHostDatastoreInfo = foreach ($NtnxHostDatastore in $NtnxHostDatastores) {
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
                                                ColumnWidths = 18, 18, 18, 18, 18, 10
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $NtnxHostDatastoreInfo | Sort-Object 'Datastore' | Table @TableParams
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
                } else {
                    Write-PScriboMessage -IsWarning "No hosts were found."
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "Host Section: $($_.Exception.Message)"
        }
    }

    end {}
}