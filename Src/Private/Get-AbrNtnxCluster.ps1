function Get-AbrNtnxCluster {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Nutanix cluster information.
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
        Write-PScriboMessage "Cluster InfoLevel set at $($InfoLevel.Cluster)."
    }

    process {
        try{
            if ($InfoLevel.Cluster -gt 0) {
                $NtnxFtStatus = (Get-NtnxApi -Version 2 -Uri '/cluster/domain_fault_tolerance_status')
                $NtnxCVMs = (Get-NtnxApi -Version 1 -Uri '/vms').entities | Where-Object { $_.controllerVm }
                $NtnxWitness = Get-NtnxApi -Version 2 -Uri '/cluster/metro_witness'
                Section -Style Heading2 'Cluster' {
                    #region Hardware
                    Section -Style Heading3 'Hardware' {
                        $NtnxFtDomainStatus = $NtnxFtStatus | Where-Object { $_.domain_type -eq $NtnxCluster.fault_tolerance_domain_type }
                        $ClusterSummary = [PSCustomObject]@{
                            'Name' = $NtnxCluster.Name
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
                            'Data Resiliency Status' = if ($NtnxFtDomainStatus.component_fault_tolerance_status.static_configuration.number_of_failures_tolerable -gt 0) { "OK" } else { "Critical" }
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
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $ClusterSummary | Table @TableParams
                    }
                    #endregion Hardware

                    #region Network
                    Section -Style Heading3 'Network' {
                        $Networks = [PSCustomObject]@{
                            'Virtual IP Address' = $NtnxCluster.cluster_external_ipaddress
                            'iSCSI Data Services IP Address' = if ($null -ne $NtnxCluster.cluster_external_data_services_ipaddress) { $NtnxCluster.cluster_external_data_services_ipaddress } else { '--' }
                            'External Subnet' = $NtnxCluster.external_subnet
                            'Internal Subnet' = $NtnxCluster.internal_subnet
                            'DNS Server(s)' = $NtnxCluster.name_servers -join ', '
                            'NTP Server(s)' = ($NtnxCluster.ntp_servers | Sort-Object) -join ', '
                        }
                        $TableParams = @{
                            Name = "Network - $($NtnxCluster.Name)"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
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
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $ControllerVMs | Sort-Object 'IP Address' | Table @TableParams
                    }
                    #endregion Controller VMs

                    #region Witness
                    if ($NtnxWitness) {
                        Section -Style Heading3 'Witness Server' {
                            $Witness = [PSCustomObject]@{
                                'Name' = $NtnxWitness.witness_name
                                'IP Address' = $NtnxWitness.ip_addresses -join ', '
                            }
                            $TableParams = @{
                                Name = "Witness Server - $($NtnxCluster.Name)"
                                ColumnWidths = 50, 50
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $Witness | Table @TableParams
                        }
                    }
                    #endregion Witness
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "Cluster Section: $($_.Exception.Message)"
        }
    }
    end {}
}