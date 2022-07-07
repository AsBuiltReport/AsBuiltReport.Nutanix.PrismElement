function Get-NtnxApi {

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [Int] $Version,

        [Parameter(
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [String] $Uri
    )

    Begin {
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

        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        $auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + $password ))
        $api_v1 = "https://" + $NtnxPE + ":9440/PrismGateway/services/rest/v1"
        $api_v2 = "https://" + $NtnxPE + ":9440/PrismGateway/services/rest/v2.0"
        $headers = @{
            'Accept'        = 'application/json'
            'Authorization' = "Basic $auth"
            'Content-Type'  = 'application/json'
        }
    }

    Process {
        Try {
            # Check PowerShell version
            if ($PSVersionTable.PSVersion.Major -eq "7") {
                Switch ($Version) {
                    '1' { Invoke-RestMethod -Method Get -Uri ($api_v1 + $uri) -Headers $headers -SkipCertificateCheck }
                    '2' { Invoke-RestMethod -Method Get -Uri ($api_v2 + $uri) -Headers $headers -SkipCertificateCheck }
                }
            } elseif ($PSVersionTable.PSVersion.Major -eq "5") {
                Switch ($Version) {
                    '1' { Invoke-RestMethod -Method Get -Uri ($api_v1 + $uri) -Headers $headers }
                    '2' { Invoke-RestMethod -Method Get -Uri ($api_v2 + $uri) -Headers $headers }
                }
            } else {
                Throw
            }
        } Catch {
            Write-Verbose -Message "Error with API reference call to $(($URI).TrimStart('/'))"
            Write-Verbose -Message $_
        }
    }

    End {}
}