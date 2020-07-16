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
            
            Switch ($Version) {
                '1' { Invoke-RestMethod -Method Get -Uri ($api_v1 + $uri) -Headers $headers }
                '2' { Invoke-RestMethod -Method Get -Uri ($api_v2 + $uri) -Headers $headers }
            }
        } Catch {
            Write-PScriboMessage "Error with API reference call to $(($URI).TrimStart('/'))"
            Write-PScriboMessage $_
        }
    }

    End {}
}