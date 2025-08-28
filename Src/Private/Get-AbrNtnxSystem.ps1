function Get-AbrNtnxSystem {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Nutanix system information.
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
        Write-PScriboMessage "System InfoLevel set at $($InfoLevel.System)."
    }

    process {
        try {
            if ($InfoLevel.System -gt 0) {
                Write-PScriboMessage "Performing System API reference calls"
                $NtnxHealthChecks = (Get-NtnxApi -Version 2 -Uri '/health_checks').entities | Sort-Object name
                $NtnxLicense = Get-NtnxApi -Version 1 -Uri '/license'
                $NtnxNfsWhitelist = Get-NtnxApi -Version 2 -Uri '/cluster/nfs_whitelist'
                $NtnxAuthConfig = Get-NtnxApi -Version 2 -Uri '/authconfig'
                $NtnxImagesConfig = (Get-NtnxApi -Version 2 -Uri '/images').entities | Sort-Object Name
                $NtnxSmtpConfig = Get-NtnxApi -Version 2 -Uri '/cluster/smtp'
                $NtnxAlertsConfig = Get-NtnxApi -Version 2 -Uri 'alerts/configuration'
                $NtnxSnmpConfig = Get-NtnxApi -Version 2 -Uri '/snmp'

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
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $NtnxNfsWhitelists | Table @TableParams
                        }
                    }
                    #endregion Global Filesystem Whitelists

                    #region Authentication
                    if ($NtnxAuthConfig) {
                        Section -Style Heading3 'Authentication' {
                            Section -Style Heading4 -ExcludeFromTOC 'Authentication Types' {
                                $AuthenticationTypes = [PSCustomObject]@{
                                    'Authentication Types' = $TextInfo.ToTitleCase(($NtnxAuthConfig.auth_type_list.Replace('_', ' ') -join ', ').ToLower())
                                }
                                $TableParams = @{
                                    Name = "Authentication Types - $($NtnxCluster.Name)"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $AuthenticationTypes | Table @TableParams
                            }
                            if ($NtnxAuthConfig.directory_list) {
                                Section -Style Heading4 -ExcludeFromTOC 'Directory List' {
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
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
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
                                    'Name' = $NtnxImage.name
                                    'Annotation' = $NtnxImage.annotation
                                    'Type' = Switch ($NtnxImage.image_type) {
                                        'DISK_IMAGE' { 'DISK' }
                                        'ISO_IMAGE' { 'ISO' }
                                    }
                                    'State' = $TextInfo.ToTitleCase(($NtnxImage.image_state).ToLower())
                                    'Size' = if ($null -ne $NtnxImage.vm_disk_size) { "$([math]::Round(($NtnxImage.vm_disk_size) / 1073741824, 2)) GiB" } else { '--' }
                                }
                            }
                            if ($Healthcheck.System.ImageState) {
                                $Images | Where-Object { $_.'State' -ne 'Active' } | Set-Style -Style Warning #-Property 'State'
                            }
                            $TableParams = @{
                                Name = "Image Configuration - $($NtnxCluster.Name)"
                                ColumnWidths = 20, 20, 20, 20, 20
                            }
                            if ($Report.ShowTableCaptions) {
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
                                'Username' = if ($null -ne $NtnxSmtpConfig.username) { $NtnxSmtpConfig.username } else { "None" }
                                'Password' = if ($null -ne $NtnxSmtpConfig.password) { $NtnxSmtpConfig.password } else { "None" }
                                'Secure Mode' = $TextInfo.ToTitleCase(($NtnxSmtpConfig.secure_mode).ToLower())
                                'From Email Address' = $NtnxSmtpConfig.from_email_address
                            }
                            $TableParams = @{
                                Name = "SMTP Server - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
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
                                'Email Every Alert' = if ($NtnxAlertsConfig.enable) { 'Yes' } else { 'No' }
                                'Email Daily Alert' = if ($NtnxAlertsConfig.enable_email_digest) { 'Yes' } else { 'No' }
                                'Nutanix Support Email' = $NtnxAlertsConfig.default_nutanix_email
                                'Additional Email Recipients' = $NtnxAlertsConfig.email_contact_list -join ', '
                            }
                            $TableParams = @{
                                Name = "Alert Email Configuration - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
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
                                'Enabled' = if ($NtnxSnmpConfig.enabled) { 'Yes' } else { 'No' }
                                'Transports' = if ($null -ne $NtnxSnmpConfig.snmp_transports) { $NtnxSnmpConfig.snmp_transports -join ',' } else { 'Not configured' }
                                'Users' = if ($null -ne $NtnxSnmpConfig.snmp_users) { $NtnxSnmpConfig.snmp_users -join ',' } else { 'Not configured' }
                                'Traps' = if ($null -ne $NtnxSnmpConfig.snmp_traps) { $NtnxSnmpConfig.snmp_traps -join ',' } else { 'Not configured' }
                            }
                            $TableParams = @{
                                Name = "SNMP Configuration - $($NtnxCluster.Name)"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
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
                    if ($NtnxLicense.LicenseDTO) {
                        $NtnxLicense = $NtnxLicense.LicenseDTO
                    }
                    if ($NtnxLicense) {
                        Section -Style Heading3 'Licensing' {
                            $Licensing = [PSCustomObject]@{
                                'Cluster' = $NtnxCluster.name
                                'License' = ($NtnxLicense.category).Replace('_',' ')
                            }
                            if ($Healthcheck.System.Licensing) {
                                $Licensing | Where-Object { $_.'License' -eq 'No License' } | Set-Style -Style Warning -Property 'License'
                            }
                            $TableParams = @{
                                Name = "Licensing - $($NtnxCluster.Name)"
                                ColumnWidths = 50, 50
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $Licensing | Table @TableParams

                            if ($InfoLevel.System -gt 2) {
                                #region Licensing Features
                                Section -Style Heading4 -ExcludeFromTOC 'Features' {
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
                                    if ($Report.ShowTableCaptions) {
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
                                    ColumnWidths = 25, 25, 25, 25
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $HealthChecks | Table @TableParams
                            }
                            #endregion Health Checks Summary Information

                            #region Health Checks Comprehensive Information
                            if ($InfoLevel.System -eq 4) {
                                foreach ($NtnxHealthCheck in $NtnxHealthChecks) {
                                    Section -Style Heading4 -ExcludeFromTOC "$($NtnxHealthCheck.name)" {
                                        $HealthChecksFull = [PSCustomObject]@{
                                            'Health Check' = $NtnxHealthCheck.name
                                            'Description' = $NtnxHealthCheck.description
                                            'Enabled' = if ($NtnxHealthCheck.enabled) { 'Yes' } else { 'No' }
                                            'Auto Resolve' = if ($NtnxHealthCheck.auto_resolve) { 'Yes' } else { 'No' }
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
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
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
        } catch {
            Write-PScriboMessage -IsWarning "System Section: $($_.Exception.Message)"
        }
    }

    end {}
}