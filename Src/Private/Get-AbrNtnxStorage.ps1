function Get-AbrNtnxStorage {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Nutanix storage information.
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
        Write-PScriboMessage "Storage InfoLevel set at $($InfoLevel.Storage)."
    }

    process {
        try{
            if ($InfoLevel.Storage -gt 0) {
                Write-PScriboMessage "Performing Storage API reference calls"
                $NtnxVolumeGroups = (Get-NtnxApi -Version 2 -Uri '/volume_groups').entities | Sort-Object Name
                if ($NtnxCluster.hypervisor_types -contains 'kVMware') {
                    $NtnxDatastores = Get-NtnxApi -Version 2 -Uri '/storage_containers/datastores' | Sort-Object datastore_name
                }
                if ($NtnxContainers -or $NtnxStoragePools -or $NtnxVolumeGroups -or $NtnxDatastores) {
                    Section -Style Heading2 'Storage' {
                        #region Containers
                        if ($NtnxContainers) {
                            Section -Style Heading3 'Containers' {
                                $Containers = foreach ($NtnxContainer in $NtnxContainers) {
                                    [PSCustomObject]@{
                                        'Name' = $NtnxContainer.name
                                        'Replication Factor' = "RF $($NtnxContainer.replication_factor)"
                                        #ToDo: 'Protection Domain'
                                        #ToDo: 'Datastore'
                                        'Compression' = if ($NtnxContainer.compression_enabled) { 'On' } else { 'Off' }
                                        'Compression Delay' = if ($null -ne $NtnxContainer.compression_delay_in_secs) { "$(($NtnxContainer.compression_delay_in_secs)*60) mins" } else { '--' }
                                        'Cache Deduplication' = $TextInfo.ToTitleCase($NtnxContainer.finger_print_on_write)
                                        'Capacity Deduplication' = $TextInfo.ToTitleCase(($NtnxContainer.on_disk_dedup).ToLower())
                                        'Erasure Coding' = $TextInfo.ToTitleCase($NtnxContainer.erasure_code)
                                        'Free Capacity (Logical) TiB' = [math]::Round(($NtnxContainer.usage_stats.'storage.user_unreserved_free_bytes') / 1099511627776, 2)
                                        'Used Capacity TiB' = [math]::Round((($NtnxContainer.usage_stats.'storage.user_capacity_bytes') - ($NtnxContainer.usage_stats.'storage.user_unreserved_free_bytes')) / 1099511627776, 2)
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
                                        Section -Style Heading4 -ExcludeFromTOC "$($Container.Container)" {
                                            $TableParams = @{
                                                Name = "Containers - $($NtnxCluster.Name)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $Container | Table @TableParams
                                        }
                                    }
                                } else {
                                    $TableParams = @{
                                        Name = "Containers - $($NtnxCluster.Name)"
                                        Columns = 'Name' , 'Replication Factor', 'Compression', 'Cache Deduplication', 'Capacity Deduplication', 'Erasure Coding', 'Free Capacity (Logical) TiB', 'Used Capacity TiB', 'Maximum Capacity TiB'
                                    }
                                    if ($Report.ShowTableCaptions) {
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
                                        'Flash Mode' = if ($NtnxVolumeGroup.flash_mode_enabled) { 'Enabled' } else { 'Disabled' }
                                        'Initiators' = $($NtnxVolumeGroups.attachment_list.iscsi_initiator_name | Sort-Object) -join ', '
                                        'Target IQN Prefix' = $NtnxVolumeGroup.iscsi_target
                                    }
                                }
                                if ($InfoLevel.Storage -eq 1) {
                                    $TableParams = @{
                                        Name = "Volume Groups - $($NtnxCluster.Name)"
                                        ColumnWidths = 22, 16, 12, 25, 25
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $VolumeGroups | Table @TableParams
                                } else {
                                    foreach ($NtnxVolumeGroup in $NtnxVolumeGroups) {
                                        Section -Style Heading4 -ExcludeFromTOC $($NtnxVolumeGroup.Name) {
                                            $VolumeGroup = [PSCustomObject]@{
                                                'Volume Group' = $NtnxVolumeGroup.Name
                                                'Number of Virtual Disks' = ($NtnxVolumeGroup.disk_list).Count
                                                'Flash Mode' = if ($NtnxVolumeGroup.flash_mode_enabled) { 'Enabled' } else { 'Disabled' }
                                                'Initiators' = $($NtnxVolumeGroups.attachment_list.iscsi_initiator_name | Sort-Object) -join ', '
                                                'Target IQN Prefix' = $NtnxVolumeGroup.iscsi_target
                                            }
                                            $TableParams = @{
                                                Name = "Volume Group $($NtnxVolumeGroup.Name) - $($NtnxCluster.Name)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $VolumeGroup | Table @TableParams

                                            if ($InfoLevel.Storage -ge 3) {
                                                Section -Style Heading4 -ExcludeFromTOC 'Virtual Disks' {
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
                                                    if ($Report.ShowTableCaptions) {
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
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $StoragePools | Sort-Object 'Storage Pool' | Table @TableParams
                            }
                        }
                        #endregion Storage Pools

                        #region VMware Datastores
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
                                        'Virtual Machines' = if (($NtnxDatastore.vm_names).Count -gt 0) { ($NtnxDatastore.vm_names | Sort-Object) -join ', ' } else { '--' }
                                    }
                                }
                                if ($InfoLevel.Storage -eq 1) {
                                    $TableParams = @{
                                        Name = "VMware Datastores - $($NtnxCluster.Name)"
                                        Columns = 'Datastore', 'Host', 'Container', 'Free Capacity TiB', 'Used Capacity TiB', 'Maximum Capacity TiB', 'Number of VMs'
                                        ColumnWidths = 15, 15, 15, 15, 15, 15, 10
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $NfsDatastores | Sort-Object Datastore, Host | Table @TableParams
                                } else {
                                    foreach ($NfsDatastore in ($NfsDatastores | Sort-Object Datastore | Sort-Object Host)) {
                                        Section -Style Heading4 -ExcludeFromTOC $($NfsDatastore.Datastore) {
                                            $TableParams = @{
                                                Name = "Datastore $($NfsDatastore.Datastore) - $($NfsDatastore.Host)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
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
                } else {
                    Write-PScriboMessage -IsWarning "No storage devices found."
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "Storage Section: $($_.Exception.Message)"
        }
    }

    end {}
}