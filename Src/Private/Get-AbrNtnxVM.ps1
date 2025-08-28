function Get-AbrNtnxVM {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Nutanix virtual machine information.
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
        Write-PScriboMessage "VM InfoLevel set at $($InfoLevel.VM)."
    }

    process {
        try{
            if ($InfoLevel.VM -gt 0) {
                Write-PScriboMessage "Performing VM API reference calls"
                $NtnxVirtualDisks = (Get-NtnxApi -Version 1 -Uri '/virtual_disks').entities
                $NtnxSnapshots = (Get-NtnxApi -Version 2 -Uri '/snapshots').entities
                if ($NtnxVirtualMachines) {
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
                            if ($Report.ShowTableCaptions) {
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
                                        'Description' = if ($null -ne $NtnxVM.description) { $NtnxVM.description } else { '--' }
                                        'Power State' = $TextInfo.ToTitleCase($NtnxVM.powerState)
                                        'Host' = if ($null -ne $NtnxVM.hostName) { $NtnxVM.hostName } else { '--' }
                                        'Host IP' = if ($null -ne $NtnxHostLookup."$($NtnxVM.hostUuid)") { $NtnxHostLookup."$($NtnxVM.hostUuid)" } else { '--' }
                                        'Memory' = "$([math]::Round(($NtnxVM.memoryCapacityInBytes) / 1073741824, 0)) GiB"
                                        'Cores' = $NtnxVM.numVCpus
                                        'Network Adapters' = $NtnxVM.numNetworkAdapters
                                        'Operating System' = if ($null -ne $NtnxVM.guestOperatingSystem) { $NtnxVM.guestOperatingSystem } else { '--' }
                                        'IP Addresses' = $NtnxVM.ipAddresses -join ', '
                                        'Storage Container' = $NtnxContainerLookup."$($NtnxVM.containerUuids)"
                                        'Virtual Disks' = ($NtnxVM.nutanixVirtualDisks).Count
                                        'Disk Capacity' = "$([math]::Round(($NtnxVM.diskCapacityinBytes) / 1073741824, 2)) GiB"
                                        #ToDo: Total Logical Capacity
                                        'NGT Enabled' = if ($NtnxVM.nutanixGuestTools.enabled) { 'Yes' } else { 'No' }
                                        'NGT Mounted' = if ($NtnxVM.nutanixGuestTools.toolsMounted) { 'Yes' } else { 'No' }
                                        'Protection Domain' = if ($NtnxVM.protectionDomainName) { $NtnxVM.protectionDomainName } else { '--' }
                                    }
                                    if ($Healthcheck.VM.PowerState) {
                                        $VirtualMachines | Where-Object { $_.'Power State' -eq 'off' } | Set-Style -Style Warning -Property 'Power State'
                                    }
                                    $TableParams = @{
                                        Name = "$($NtnxVM.vmName) - $($NtnxCluster.Name)"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $VirtualMachines | Table @TableParams

                                    #region VM Virtual Disks
                                    $NtnxVMVirtualDisks = $NtnxVirtualDisks | Where-Object {$_.attachedVMName -eq $($NtnxVM.vmName)} | Sort-Object diskAddress
                                    if ($NtnxVMVirtualDisks) {
                                        Section -Style Heading4 -ExcludeFromTOC 'Virtual Disks' {
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
                                                ColumnWidths = 33, 34, 33
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $VMVirtualDisks | Table @TableParams
                                        }
                                    }
                                    #endregion VM Virtual Disks

                                    #region VM NICs
                                    $NtnxVMNics = (Get-NtnxApi -Version 2 -Uri $('/vms/' + $($NtnxVM.uuid) + '/nics')).entities | Sort-Object network_uuid
                                    if ($NtnxVMNics) {
                                        Section -Style Heading4 -ExcludeFromTOC 'VM NICs' {
                                            $VMNics = foreach ($NtnxVMNic in $NtnxVMNics) {
                                                [PSCustomObject]@{
                                                    #ToDo: Find a way to get the 'Port Name' for VMware
                                                    'Network Name' = $NtnxNetworkLookup."$($NtnxVMNic.network_uuid)"
                                                    'Adapter Type' = $NtnxVMNic.adapter_type
                                                    'VLAN ID' = $NtnxNetworkVlanLookup."$($NtnxVMNic.network_uuid)"
                                                    'MAC Address' = $NtnxVMNic.mac_address
                                                    'IP Address' = ($NtnxVMNic.ip_address | Sort-Object) -join ', '
                                                    'IP Addresses' = ($NtnxVMNic.ip_addresses | Sort-Object) -join ', '
                                                    'Connected' = if ($NtnxVMNic.is_connected) { 'Yes' } else { 'No' }
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
                                            if ($Report.ShowTableCaptions) {
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
                                                ColumnWidths = 50, 50
                                            }
                                            if ($Report.ShowTableCaptions) {
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
            }
        } catch {
            Write-PScriboMessage -IsWarning "VM Section: $($_.Exception.Message)"
        }
    }

    end {}
}