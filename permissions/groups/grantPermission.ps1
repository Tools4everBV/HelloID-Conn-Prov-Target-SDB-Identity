################################################################
# HelloID-Conn-Prov-Target-SDB-Identity-GrantPermission-Group
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

# Begin
try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $($actionContext.Configuration.AccessToken)")
    $headers.Add('Accept', 'application/json')

    Write-Information 'Verifying if a SDB-Identity account exists'
    $splatGetUser = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users/$($actionContext.References.Account)"
        Method  = 'GET'
        Headers = $headers
    }
    try {
        $correlatedAccount = Invoke-RestMethod @splatGetUser
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Information $_.Exception.Message
        } else {
            throw
        }
    }

    if ($null -ne $correlatedAccount) {
        $action = 'GrantPermission'
    } else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'GrantPermission' {
            # Make sure to test with special characters and if needed; add utf8 encoding.
            Write-Information "Granting SDB-Identity permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)]"
            [System.Collections.Generic.List[object]]$operations = @()

            $operations.Add(
                [PSCustomObject]@{
                    op    = 'add'
                    path  = 'members'
                    value = @(
                        [PSCustomObject]@{
                            value = $actionContext.References.Account
                        }
                    )
                }
            )
            $body = [ordered]@{
                schemas    = @(
                    'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                )
                Operations = $operations
            } | ConvertTo-Json -depth 10

            $splatGrantGroupMember = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Groups/$($actionContext.References.Permission.Reference)"
                Headers = $headers
                Body    = $body
                Method  = 'Patch'
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Grant SDB-Identity permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
                $null = Invoke-RestMethod @splatGrantGroupMember
            } else {
                Write-Information "[DryRun] Grant SDB-Identity permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Grant permission [$($actionContext.PermissionDisplayName)] was successful"
                    IsError = $false
                })
        }

        'NotFound' {
            Write-Information "SDB-Identity account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "SDB-Identity account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $true
                })
            break
        }
    }
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-SDB-IdentityError -ErrorObject $ex
        $auditMessage = "Could not grant SDB-Identity permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not grant SDB-Identity permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}