function Invoke-AsBuiltReport.Nutanix.PrismElement {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Nutanix Prism infrastucture in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Nutanix Prism infrastucture in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        1.3.0
        Author:         Tim Carman
        Twitter:        @tpcarman
        Github:         tpcarman
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Nutanix.PrismElement
    #>

    param (
        [String[]] $Target,
        [PSCredential] $Credential
    )

    # Import Report Configuration
    $Report = $ReportConfig.Report
    $InfoLevel = $ReportConfig.InfoLevel
    $Options = $ReportConfig.Options
    # Used to set values to TitleCase where required
    $TextInfo = (Get-Culture).TextInfo

    foreach ($NtnxPE in $Target) {
        #region API Collections & hashtable lookups
        Write-PScriboMessage "Performing common API reference calls & hashtable loopkup creation."
        $NtnxCluster = Get-NtnxApi -Version 2 -Uri '/cluster'
        $NtnxVMs = (Get-NtnxApi -Version 1 -Uri '/vms').entities
        $NtnxVirtualMachines = $NtnxVMs | Where-Object { ($_.controllervm -eq $false) -and ($_.runningOnNdfs -eq $true) } | Sort-Object vmName
        if ($NtnxVirtualMachines) {
            Try {
                Write-PScriboMessage "Creating VM hashtable lookup."
                $NtnxVirtualMachineLookup = @{}
                foreach ($NtnxVirtualMachine in $NtnxVirtualMachines) {
                    $NtnxVirtualMachineLookup.($NtnxVirtualMachine.uuid) = $NtnxVirtualMachine.vmName
                }
            } Catch {
                Write-PScriboMessage -IsWarning "Error creating VM hashtable lookup."
            }
        }

        $NtnxHosts = (Get-NtnxApi -Version 2 -Uri '/hosts').entities | Sort-Object Name
        if ($NtnxHosts) {
            Try {
                Write-PScriboMessage "Creating Host hashtable lookup."
                $NtnxHostLookup = @{}
                foreach ($NtnxHost in $NtnxHosts) {
                    $NtnxHostLookup.($NtnxHost.uuid) = $NtnxHost.hypervisor_address
                }
            } Catch {
                Write-PScriboMessage -IsWarning "Error creating Host hashtable lookup."
            }
        }

        $NtnxNetworks = (Get-NtnxApi -Version 2 -Uri '/networks').entities | Sort-Object Name
        if ($NtnxNetworks) {
            Try {
                Write-PScriboMessage "Creating Network hashtable lookup."
                $NtnxNetworkLookup = @{}
                $NtnxNetworkVlanLookup = @{}
                foreach ($NtnxNetwork in $NtnxNetworks) {
                    $NtnxNetworkLookup.($NtnxNetwork.uuid) = $NtnxNetwork.name
                    $NtnxNetworkVlanLookup.($NtnxNetwork.uuid) = $NtnxNetwork.vlan_id
                }
            } Catch {
                Write-PScriboMessage -IsWarning "Error creating Network hashtable lookup."
            }
        }

        $NtnxContainers = (Get-NtnxApi -Version 2 -Uri '/storage_containers').entities | Sort-Object Name
        if ($NtnxContainers) {
            Try {
                Write-PScriboMessage "Creating Container hashtable lookup."
                $NtnxContainerLookup = @{}
                foreach ($NtnxContainer in $NtnxContainers) {
                    $NtnxContainerLookup.($NtnxContainer.storage_container_uuid) = $NtnxContainer.Name
                }
            } Catch {
                Write-PScriboMessage -IsWarning "Error creating Container hashtable lookup."
            }
        }

        $NtnxStoragePools = (Get-NtnxApi -Version 1 -Uri '/storage_pools').entities | Sort-Object Name
        if ($NtnxStoragePools) {
            Try {
                Write-PScriboMessage "Creating Storage Pool hashtable lookup."
                $NtnxStoragePoolLookup = @{}
                foreach ($NtnxStoragePool in $NtnxStoragePools) {
                    foreach ($DiskUuid in $NtnxStoragePool.diskUuids) {
                        $NtnxStoragePoolLookup.($DiskUuid) = $NtnxStoragePool.name
                    }
                }
            } Catch {
                Write-PScriboMessage -IsWarning "Error creating Storage Pool hashtable lookup."
            }
        }
        #endregion API Collections & hashtable lookups

        Write-PScriboMessage "Generating report for $NtnxPE."
        if ($NtnxCluster) {
            Section -Style Heading1 $($NtnxCluster.Name) {
                Get-AbrNtnxCluster
                Get-AbrNtnxSystem
                Get-AbrNtnxHost
                Get-AbrNtnxNetwork
                Get-AbrNtnxStorage
                Get-AbrNtnxVM
                Get-AbrNtnxDataProtection
            }
        } else {
            Throw "Cluster information for $NtnxPE not found."
        }
    }
}