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
        #region Workaround for SelfSigned Cert and force TLS 1.2

        if ($PSVersionTable.PSEdition -ne 'Core') {

            Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

        }


        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        #endregion Workaround for SelfSigned Cert and force TLS 1.2

        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        $auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + $password ))
        $api_v1 = "https://" + $NtnxPE + ":9440/PrismGateway/services/rest/v1"
        $api_v2 = "https://" + $NtnxPE + ":9440/PrismGateway/services/rest/v2.0"
        #$api_v2 = "https://" + $NtnxPE + ":9440/api/nutanix/v2.0" # New API endpoint as of AOS 6.0
        $headers = @{
            'Accept' = 'application/json'
            'Authorization' = "Basic $auth"
            'Content-Type' = 'application/json'
        }
    }

    Process {
        Try {
            Write-PScriboMessage -Message "Performing API reference call to $(($URI).TrimStart('/')) [$NtnxPE]"
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
            Write-Verbose -Message "Error with API reference call to $(($URI).TrimStart('/')) [$NtnxPE]"
            Write-Verbose -Message $_
        }
    }

    End {}
}