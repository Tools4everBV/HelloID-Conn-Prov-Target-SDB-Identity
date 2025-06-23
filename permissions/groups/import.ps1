################################################################
# HelloID-Conn-Prov-Target-SDB-Identity-ImportPermission-Group
# PowerShell V2
################################################################

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
#endregion
try {
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $($actionContext.Configuration.AccessToken)")
    $headers.Add('Accept', 'application/json')

    Write-Information 'Starting permission data import'
    $count = 100
    $startIndex = 1
    $importedPermissions = @()
    do {
        $splatGetPermissions = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/groups?startIndex=$startIndex&count=$count"
            Method  = 'Get'
            Headers = $headers
        }
        $response = Invoke-RestMethod @splatGetPermissions

        if ($response.Resources) {
            $importedPermissions += $response.Resources
        }

        $totalResults = $response.totalResults
        $startIndex += $count
    } while ($importedPermissions.Count -lt $totalResults)

    # Map the imported data to the account field mappings
    foreach ($importedPermission in $importedPermissions) {
        $permission = @{
            DisplayName         = $importedPermission.displayName
            AccountReferences   = $importedPermission.members.value
            PermissionReference = @{
                Reference = $importedPermission.id
            }
        }

        $accountsBatchSize = 500
        $numberOfAccounts = $permission.members.count
        $batches = 0..($numberOfAccounts - 1) | Group-Object { [math]::Floor($_ / $accountsBatchSize ) }
        foreach ($batch in $batches) {
            $permission.AccountReferences = [array]($batch.Group | ForEach-Object { @($permission.members) })
            Write-Output $permission
        }
    }
    Write-Information 'Permission data import completed'
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-SDB-IdentityError -ErrorObject $ex
        Write-Warning "Could not import SDB-Identity permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        Write-Warning "Could not import SDB-Identity permission. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}