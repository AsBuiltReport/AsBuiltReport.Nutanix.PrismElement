function Get-AbrNtnxNetwork {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Nutanix network information.
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
        Write-PScriboMessage "Network InfoLevel set at $($InfoLevel.Network)."
    }

    process {
        try {
            if ($InfoLevel.Network -gt 0) {
<#
# JSON data for testing purposes
$jsonString = @"
{
  "metadata": {
    "grand_total_entities": 2,
    "total_entities": 2
  },
  "entities": [
    {
      "logical_timestamp": 8,
      "vlan_id": 0,
      "ip_config": {
        "prefix_length": 0,
        "ipam_enabled": false,
        "free_ips": -1,
        "assigned_ips": -1,
        "num_macs": 2,
        "dhcp_options": {},
        "pool": []
      },
      "uuid": "f64102bc-6ea1-438a-b5d1-39af84c98811",
      "virtual_switch_uuid": "e23c7de0-9210-4ad0-88e3-e4407e3b79f5",
      "name": "MANAGEMENT_ONLY_DO_NOT_USE",
      "vswitch_name": "br0"
    },
    {
      "logical_timestamp": 284,
      "vlan_id": 0,
      "ip_config": {
        "network_address": "192.168.1.0",
        "prefix_length": 24,
        "ipam_enabled": true,
        "free_ips": 240,
        "assigned_ips": 16,
        "num_macs": 13,
        "default_gateway": "192.168.1.1",
        "dhcp_options": {
          "domain_name": "ntnxlab",
          "domain_name_servers": "192.168.1.2",
          "domain_search": "ntnxlab.local"
        },
        "pool": [
          {
            "range": "192.168.1.30 192.168.1.250",
            "num_free_ips": 211,
            "num_total_ips": 221
          }
        ],
        "dhcp_server_address": "192.168.1.254"
      },
      "uuid": "0c01ef72-ee06-4941-bfa5-c8222f1dfea7",
      "virtual_switch_uuid": "e23c7de0-9210-4ad0-88e3-e4407e3b79f5",
      "name": "IPAM_Default",
      "vswitch_name": "br0"
    }
  ]
}
"@

# Convert from JSON
$NetworkData = $jsonString | ConvertFrom-Json
$NtnxNetworks = $NetworkData.entities | Sort-Object Name
#>
                if ($NtnxNetworks) {
                    Section -Style Heading2 'Network' {
                        #region Networks Summary
                        if ($InfoLevel.Network -eq 1) {
                            $Networks = foreach ($NtnxNetwork in $NtnxNetworks) {
                                [PSCustomObject]@{
                                    'Name' = $NtnxNetwork.name
                                    'VLAN ID' = if ($NtnxNetwork.vlan_id -eq 0) { 'Native (0)' } else { $NtnxNetwork.vlan_id }
                                    'Virtual Switch' = if ($NtnxNetwork.vswitch_name) { $NtnxNetwork.vswitch_name } else { '--' }
                                    'IPAM' = if ($NtnxNetwork.ip_config.ipam_enabled) { 'Enabled' } else { 'Disabled' }
                                    'Network/CIDR' = if ($NtnxNetwork.ip_config.network_address -and $NtnxNetwork.ip_config.prefix_length -gt 0) {
                                        "$($NtnxNetwork.ip_config.network_address)/$($NtnxNetwork.ip_config.prefix_length)"
                                    } else { '--' }
                                    'Default Gateway' = if ($NtnxNetwork.ip_config.default_gateway) { $NtnxNetwork.ip_config.default_gateway } else { '--' }
                                    'Assigned IPs' = if ($NtnxNetwork.ip_config.assigned_ips -ge 0) { $NtnxNetwork.ip_config.assigned_ips } else { '--' }
                                    'Free IPs' = if ($NtnxNetwork.ip_config.free_ips -ge 0) { $NtnxNetwork.ip_config.free_ips } else { '--' }
                                }
                            }

                            # Health checks
                            if ($Healthcheck.Network.IPAM) {
                                $Networks | Where-Object { $_.'IPAM' -eq 'Disabled' -and $_.'Network/CIDR' -ne '--' } | Set-Style -Style Warning -Property 'IPAM'
                            }
                            if ($Healthcheck.Network.Gateway) {
                                $Networks | Where-Object { $_.'Default Gateway' -eq '--' -and $_.'IPAM' -eq 'Enabled' } | Set-Style -Style Warning -Property 'Default Gateway'
                            }

                            $TableParams = @{
                                Name = "Networks - $($NtnxCluster.Name)"
                                ColumnWidths = 20, 12, 15, 10, 18, 15, 10, 10
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $Networks | Sort-Object 'Name' | Table @TableParams
                        }
                        #endregion Networks Summary

                        #region Networks Detailed (InfoLevel 2 & 3)
                        if ($InfoLevel.Network -ge 2) {
                            foreach ($NtnxNetwork in $NtnxNetworks) {
                                Section -Style Heading3 "$($NtnxNetwork.name)" {
                                    $NetworkConfig = [PSCustomObject]@{
                                        'Name' = $NtnxNetwork.name
                                        'UUID' = $NtnxNetwork.uuid
                                        'Virtual Switch' = if ($NtnxNetwork.vswitch_name) { $NtnxNetwork.vswitch_name } else { '--' }
                                        'Virtual Switch UUID' = if ($NtnxNetwork.virtual_switch_uuid) { $NtnxNetwork.virtual_switch_uuid } else { '--' }
                                        'VLAN ID' = if ($NtnxNetwork.vlan_id -eq 0) { 'Native VLAN (0)' } else { $NtnxNetwork.vlan_id }
                                        'Logical Timestamp' = $NtnxNetwork.logical_timestamp
                                        'IPAM Enabled' = if ($NtnxNetwork.ip_config.ipam_enabled) { 'Yes' } else { 'No' }
                                        'Network Address' = if ($NtnxNetwork.ip_config.network_address) { $NtnxNetwork.ip_config.network_address } else { '--' }
                                        'Prefix Length' = if ($NtnxNetwork.ip_config.prefix_length -gt 0) { $NtnxNetwork.ip_config.prefix_length } else { '--' }
                                        'Default Gateway' = if ($NtnxNetwork.ip_config.default_gateway) { $NtnxNetwork.ip_config.default_gateway } else { '--' }
                                        'DHCP Server Address' = if ($NtnxNetwork.ip_config.dhcp_server_address) { $NtnxNetwork.ip_config.dhcp_server_address } else { '--' }
                                        'Assigned IPs' = if ($NtnxNetwork.ip_config.assigned_ips -ge 0) { $NtnxNetwork.ip_config.assigned_ips } else { '--' }
                                        'Free IPs' = if ($NtnxNetwork.ip_config.free_ips -ge 0) { $NtnxNetwork.ip_config.free_ips } else { '--' }
                                        'MAC Addresses Count' = if ($NtnxNetwork.ip_config.num_macs -ge 0) { $NtnxNetwork.ip_config.num_macs } else { '--' }
                                    }

                                    # Health check styling
                                    if ($Healthcheck.Network.IPAM -and !$NtnxNetwork.ip_config.ipam_enabled -and $NtnxNetwork.ip_config.network_address) {
                                        $NetworkConfig | Set-Style -Style Warning -Property 'IPAM Enabled'
                                    }
                                    if ($Healthcheck.Network.Gateway -and $NtnxNetwork.ip_config.ipam_enabled -and !$NtnxNetwork.ip_config.default_gateway) {
                                        $NetworkConfig | Set-Style -Style Warning -Property 'Default Gateway'
                                    }

                                    $TableParams = @{
                                        Name = "Network Configuration - $($NtnxNetwork.name)"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $NetworkConfig | Table @TableParams

                                    # DHCP Options (if available)
                                    if ($NtnxNetwork.ip_config.dhcp_options -and ($NtnxNetwork.ip_config.dhcp_options.PSObject.Properties | Measure-Object).Count -gt 0) {
                                        Section -Style Heading4 -ExcludeFromTOC 'DHCP Options' {
                                            $DhcpOptions = [PSCustomObject]@{
                                                'Domain Name' = if ($NtnxNetwork.ip_config.dhcp_options.domain_name) { $NtnxNetwork.ip_config.dhcp_options.domain_name } else { '--' }
                                                'DNS Servers' = if ($NtnxNetwork.ip_config.dhcp_options.domain_name_servers) { $NtnxNetwork.ip_config.dhcp_options.domain_name_servers } else { '--' }
                                                'Domain Search' = if ($NtnxNetwork.ip_config.dhcp_options.domain_search) { $NtnxNetwork.ip_config.dhcp_options.domain_search } else { '--' }
                                            }

                                            $TableParams = @{
                                                Name = "DHCP Options - $($NtnxNetwork.name)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $DhcpOptions | Table @TableParams
                                        }
                                    }

                                    # IP Pools (InfoLevel 3 and if pools exist)
                                    if ($InfoLevel.Network -ge 3 -and $NtnxNetwork.ip_config.pool -and $NtnxNetwork.ip_config.pool.Count -gt 0) {
                                        Section -Style Heading4 -ExcludeFromTOC 'IP Pools' {
                                            $IpPools = foreach ($pool in $NtnxNetwork.ip_config.pool) {
                                                [PSCustomObject]@{
                                                    'IP Range' = $pool.range
                                                    'Total IPs' = $pool.num_total_ips
                                                    'Free IPs' = $pool.num_free_ips
                                                    'Used IPs' = $pool.num_total_ips - $pool.num_free_ips
                                                    'Utilization %' = if ($pool.num_total_ips -gt 0) {
                                                        [math]::Round((($pool.num_total_ips - $pool.num_free_ips) / $pool.num_total_ips * 100), 1)
                                                    } else { 0 }
                                                }
                                            }

                                            # Health check for pool utilization
                                            if ($Healthcheck.Network.PoolUtilization) {
                                                $IpPools | Where-Object { $_.'Utilization %' -gt 90 } | Set-Style -Style Critical -Property 'Utilization %'
                                                $IpPools | Where-Object { $_.'Utilization %' -gt 80 -and $_.'Utilization %' -le 90 } | Set-Style -Style Warning -Property 'Utilization %'
                                            }

                                            $TableParams = @{
                                                Name = "IP Pools - $($NtnxNetwork.name)"
                                                ColumnWidths = 30, 15, 15, 15, 25
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $IpPools | Table @TableParams
                                        }
                                    }
                                }
                            }
                        }
                        #endregion Networks Detailed
                    }
                } else {
                    Write-PScriboMessage -IsWarning "No AHV networks found."
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "Network Section: $($_.Exception.Message)"
        }
    }

    end {}
}