function Get-AbrNtnxDataProtection {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Nutanix data protection information.
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
        Write-PScriboMessage "Data Protection InfoLevel set at $($InfoLevel.DataProtection)."
    }

    process {

        try {
            if ($InfoLevel.DataProtection -gt 0)  {
                Write-PScriboMessage "Performing Data Protection API reference calls"
                $NtnxProtectionDomains = (Get-NtnxApi -Version 2 -Uri '/protection_domains').entities
                $NtnxRemoteSites = Get-NtnxApi -Version 1 -Uri '/remote_sites'
                $NtnxPDReplications = (Get-NtnxApi -Version 2 -Uri '/protection_domains/replications').entities
                $NtnxDrSnapshots = (Get-NtnxApi -Version 2 -Uri '/remote_sites/dr_snapshots').entities
                $NtnxUnprotectedVMs = (Get-NtnxApi -Version 2 -Uri '/protection_domains/unprotected_vms').entities
                if ($NtnxProtectionDomains -or $NtnxRemoteSites) {
                    Section -Style Heading2 'Data Protection' {
                        #region Protection Domains
                        if ($NtnxProtectionDomains) {
                            Section -Style Heading3 'Protection Domains' {
                                $ProtectionDomains = foreach ($NtnxProtectionDomain in $NtnxProtectionDomains) {
                                    [PSCustomObject]@{
                                        'Name' = $NtnxProtectionDomain.name
                                        'Active' = if ($NtnxProtectionDomain.active) { 'Yes' } else { 'No' }
                                        'Remote Site(s)' = $NtnxProtectionDomain.replication_links.remote_site_name
                                        'Pending Replications' = $NtnxProtectionDomain.pending_replication_count
                                        'Ongoing Replications' = $NtnxProtectionDomain.ongoing_replication_count
                                        'Written Bytes' = $NtnxProtectionDomain.total_user_written_bytes
                                    }
                                }
                                $TableParams = @{
                                    Name = "Protection Domains - $($NtnxCluster.Name)"
                                    ColumnWidths = 36, 10, 15, 13, 13, 13
                                }
                                if ($Report.ShowTableCaptions) {
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
                                    ColumnWidths = 25, 15, 15, 15, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
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
                                        'Name' = $NtnxDrSnapshot.protection_domain_name
                                        'State' = ($NtnxDrSnapshot.state).ToLower()
                                        'Snapshot ID' = $NtnxDrSnapshot.snapshot_id
                                        'Consistency Groups' = $NtnxDrSnapshot.consistency_groups -join ', '
                                        'Remote Site(s)' = $NtnxDrSnapshot.remote_site_names -join ', '
                                        'Size in Bytes' = $NtnxDrSnapshot.size_in_bytes
                                    }
                                }
                                $TableParams = @{
                                    Name = "Protection Domain Snapshots - $($NtnxCluster.Name)"
                                    ColumnWidths = 15, 15, 15, 25, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $ProtectionDomainSnapshots | Sort-Object 'Name' | Table @TableParams
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
                                        'Operating System' = if ($null -ne $NtnxUnprotectedVM.guest_operating_system) { $NtnxUnprotectedVM.guest_operating_system } else { '--'}
                                        'Cores' = $NtnxUnprotectedVM.num_vcpus
                                        'Network Adapters' = $NtnxUnprotectedVM.num_network_adapters
                                        'Disk Capacity' = "$([math]::Round(($NtnxUnprotectedVM.disk_capacity_in_bytes) / 1073741824, 2)) GiB"
                                        'Host' = $NtnxUnprotectedVM.host_name
                                    }
                                }
                                $TableParams = @{
                                    Name = "Unprotected VMs - $($NtnxCluster.Name)"
                                    ColumnWidths = 22, 10, 19, 10, 10, 10, 19
                                }
                                if ($Report.ShowTableCaptions) {
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
                                        'Metro Ready' = if ($NtnxRemoteSite.metroReady) { 'Yes' } else { 'No' }
                                        'Use SSH Tunnel' = if ($NtnxRemoteSite.sshEnabled) { 'Yes' } else { 'No' }
                                        'Compress On Wire' = if ($NtnxRemoteSite.compressionEnabled) { 'On' } else { 'Off' }
                                        'Enable Proxy' = if ($NtnxRemoteSite.proxyEnabled) { 'On' } else { 'Off' }
                                        'Bandwidth Throttling' = if ($NtnxRemoteSite.bandwidthPolicyEnabled) { 'On' } else { 'Off' }
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
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $RemoteSites | Sort-Object 'Name' | Table @TableParams
                            }
                        }
                        #endregion Remote Sites
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "Data Protection Section: $($_.Exception.Message)"
        }
    }

    end {}
}