#################################################
# HelloID-Conn-Prov-Target-Xedule-students-Import
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-SDB-IdentityError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            $httpErrorObj.FriendlyMessage = $errorDetailsObject.detail
        } catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function ConvertTo-HelloIDAccountObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $AccountObject
    )
    process {
        $helloidAcountObject = [PSCustomObject]@{
            emailAddressType = $AccountObject.emails.type
            emailAddress     = $AccountObject.emails.value
            NameFormatted    = $AccountObject.name.formatted
            userName         = $AccountObject.userName
            employeeNumber   = $AccountObject.'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'.employeeNumber
            isEmailPrimary   = $AccountObject.emails.primary
        }
        Write-Output $helloidAcountObject
    }
}
#endregion

try {
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $($actionContext.Configuration.AccessToken)")
    $headers.Add('Accept', 'application/json')
    Write-Information 'Starting account data import'

    $count = 100
    $startIndex = 1
    $importedAccounts = @()
    do {
        $splatGetUsers = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users?startIndex=$startIndex&count=$count"
            Method  = 'Get'
            Headers = $headers
        }

        $response = Invoke-RestMethod @splatGetUsers

        if ($response.Resources) {
            $importedAccounts += $response.Resources
        }

        $totalResults = $response.totalResults
        $startIndex += $count
    } while ($importedAccounts.Count -lt $totalResults)


    # Map the imported data to the account field mappings
    foreach ($importedAccount in $importedAccounts) {
        $data = ConvertTo-HelloIDAccountObject -AccountObject $importedAccount

        Write-Output @{
            AccountReference = $importedAccount.Id
            DisplayName      = $importedAccount.name.formatted
            UserName         = $importedAccount.userName
            Enabled          = $importedAccount.active
            Data             = $data
        }
    }
    Write-Information 'Account data import completed'
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-SDB-IdentityError -ErrorObject $ex
        Write-Warning "Could not import SDB-Identity account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        Write-Warning "Could not import SDB-Identity account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}
