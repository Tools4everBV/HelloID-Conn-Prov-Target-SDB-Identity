#####################################################
# HelloID-Conn-Prov-Target-SDB-Identity-SubPermissions
# Grants/revokes All groups
# PowerShell V2
#####################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{}
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

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
#endregion functions

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
        $accountFound = $true
    } else {
        $accountFound = $false
    }

    Write-Information 'Retrieving permissions'
    $count = 100
    $startIndex = 1
    $retrievedPermissions = @()
    do {
        $splatGetPermissions = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/groups?startIndex=$startIndex&count=$count"
            Method  = 'Get'
            Headers = $headers
        }
        $response = Invoke-RestMethod @splatGetPermissions

        if ($response.Resources) {
            $retrievedPermissions += $response.Resources
        }

        $totalResults = $response.totalResults
        $startIndex += $count
    } while ($retrievedPermissions.Count -lt $totalResults)

    #region Define desired permissions
    $actionMessage = "calculating desired permission"

    # Group on ExternalId to check if group exists (as correlation property has to be unique for a group)
    $groupsGrouped = $retrievedPermissions | Select id, displayName | Group-Object displayName -AsHashTable -AsString

    $desiredPermissions = @{}
    if (-Not($actionContext.Operation -eq "revoke")) {
        # Example: Contract Based Logic:
        foreach ($contract in $personContext.Person.Contracts) {

            $actionMessage = "calulating group for resource: $($resource | ConvertTo-Json)"

            Write-Information "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {        
                # Get group to use objectGuid to avoid name change issues
                $correlationField = "displayName"
                # Example: department_<department externalId>
                $correlationValue = $contract.custom.SDBGroupName

                $group = $null
                $group = $groupsGrouped["$($correlationValue)"]

                if (($group | Measure-Object).count -eq 0) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "No Group found where [$($correlationField)] = [$($correlationValue)]"
                            IsError = $true
                        })
                }
                elseif (($group | Measure-Object).count -gt 1) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Multiple Groups found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the groups are unique."
                            IsError = $true
                        })
                }
                else {
                    # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                    $desiredPermissions["$($group.id)"] = $group.DisplayName
                }
            }
        }
    }
    #endregion Define desired permissions

    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))
    Write-Warning ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))

    #region Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {    
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No permissions defined") {
            #region Revoke permission
            # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PatchGroup
            $actionMessage = "revoking group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Create permission body
            $revokePermissionBody = [PSCustomObject]@{
                schemas    = @("urn:ietf:params:scim:api:messages:2.0:PatchOp")
                id         = $permission.Name
                operations = @(
                    @{
                        op    = "remove"
                        path  = "members"
                        value = @(
                            @{
                                value   = $actionContext.References.Account
                            }
                        )
                    }
                )
            }
    
            $revokePermissionSplatParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/scim/groups/$($permission.Name)"
                Method      = "PATCH"
                Body        = ($revokePermissionBody | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }

            Write-Information "SplatParams: $($revokePermissionSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $revokePermissionSplatParams['Headers'] = $headers

                $null = Invoke-RestMethod @revokePermissionSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Revoked group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would revoke group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Revoke permission
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }
    #endregion Compare current with desired permissions and revoke permissions

    #region Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            #region Grant permission
            # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PatchGroup
            $actionMessage = "granting group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Create permission body
            $grantPermissionBody = [PSCustomObject]@{
                schemas    = @("urn:ietf:params:scim:api:messages:2.0:PatchOp")
                id         = $permission.Name
                operations = @(
                    @{
                        op    = "add"
                        path  = "members"
                        value = @(
                            @{
                                value   = $actionContext.References.Account
                            }
                        )
                    }
                )
            }
    
            $grantPermissionSplatParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/scim/groups/$($permission.Name)"
                Method      = "PATCH"
                Body        = ($grantPermissionBody | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }

            Write-Information "SplatParams: $($grantPermissionSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $grantPermissionSplatParams['Headers'] = $headers

                $null = Invoke-RestMethod @grantPermissionSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Granted group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would grant group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Grant permission
        }    
    }
    #endregion Compare desired with current permissions and grant permissions
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-SDB-IdentityError -Error $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally { 
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No permissions defined"
                Reference   = [PSCustomObject]@{ Id = "No permissions defined" }
            })

        Write-Warning "Skipped granting permissions for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No permissions defined."
    }

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}