#####################################################
# HelloID-Conn-Prov-Target-SDB-Identity-Resources-Groups
# Creates groups dynamically based on HR data
# PowerShell V2
#####################################################

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
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorObjectConverted = $httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.detail) {
                $errorObjectDetail = [regex]::Matches($errorObjectConverted.detail, '{(.*)}').Value
                if ($null -ne $errorObjectDetail) {
                    try {
                        $errorDetailConverted = $errorObjectDetail | ConvertFrom-Json -ErrorAction Stop
                        if ($null -ne $errorDetailConverted) {
                            if ($null -ne $errorDetailConverted.Error.Message) {
                                $httpErrorObj.FriendlyMessage = $errorMessage + $errorDetailConverted.Error.Message
                            }
                            if ($null -ne $errorDetailConverted.title) {
                                $httpErrorObj.FriendlyMessage = $errorMessage + $errorDetailConverted.title
                            }
                        }
                    }
                    catch {
                        $httpErrorObj.FriendlyMessage = $errorObjectDetail
                    }
                }
                else {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.detail
                }

                if ($null -ne $errorObjectConverted.status) {
                    $httpErrorObj.FriendlyMessage = $httpErrorObj.FriendlyMessage + " (" + $errorObjectConverted.status + ")"
                }
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $ErrorObject
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

try {
    #headers
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $($actionContext.Configuration.AccessToken)")
    $headers.Add('Accept', 'application/json')

    #region Get Groups
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

    $groups = $retrievedPermissions | Select-Object id, displayName | Sort-Object displayName -unique
    $groups | Add-Member -MemberType NoteProperty -Name ExternalID -Value $null -Force

    foreach($group in $groups) {
        $externalIDValue = $group.displayName
        $index = $externalIDValue.IndexOf(" -")
            If($index -gt 0){
            $externalIDValue = $externalIDValue.SubString(0, $index)
            $group.ExternalID = $externalIDValue
            } else {
                $group.ExternalID = $null
            }

    }

    Write-Information "Queried Groups. Result count: $(($groups | Measure-Object).Count)"
    #endregion Get Groups

    #region Process resources
    # Ensure the resourceContext data is unique based on ExternalId and DisplayName
    # and always sorted in the same order (by ExternalId and DisplayName)
    $resourceData = $resourceContext.SourceData |
    Select-Object -Property ExternalId, Name -Unique | # Ensure uniqueness
    Sort-Object -Property @{Expression = { $_.ExternalId } }, Name # Ensure consistent order by sorting ExternalId as integer and then by DisplayName

    # Group on ExternalId to check if group exists (as correlation property has to be unique for a group)
    $groupsGrouped = $groups | Group-Object -Property externalId -AsHashTable -AsString

    foreach ($resource in $resourceData) {
        #region get group for resource
        $actionMessage = "querying group for resource: $($resource | ConvertTo-Json)"
 
        $correlationField = "externalId"
        $correlationValue = "OE: $($resource.ExternalId)"

        $correlatedResource = $null
        $correlatedResource = $groupsGrouped["$($correlationValue)"]
        #endregion get group for resource
        
        #region Calulate action
        if (($correlatedResource | Measure-Object).count -eq 0) {
            $actionResource = "CreateResource"
        }
        elseif (($correlatedResource | Measure-Object).count -eq 1) {
            $actionResource = "CorrelateResource"
        }
        #endregion Calulate action

        #region Process
        switch ($actionResource) {
            "CreateResource" {
                #region Create group
                # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PostGroupRequest
                $actionMessage = "creating group for resource: $($resource | ConvertTo-Json)"

                # Create account body and set with default properties
                $createGroupBody = [PSCustomObject]@{
                    schemas      = @("urn:ietf:params:scim:schemas:core:2.0:Group")
                    displayName = "$($resource.ExternalId) - $($resource.Name)"
                }

                $createGroupSplatParams = @{
                    Uri         = "$($actionContext.Configuration.BaseUrl)/scim/groups"
                    Method      = "POST"
                    Body        = ($createGroupBody | ConvertTo-Json -Depth 10)
                    ContentType = 'application/json; charset=utf-8'
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                Write-Information "SplatParams: $($createGroupSplatParams | ConvertTo-Json)"

                if (-Not($actionContext.DryRun -eq $true)) {
                    # Add header after printing splat
                    $createGroupSplatParams['Headers'] = $headers

                    $createGroupResponse = Invoke-RestMethod @createGroupSplatParams
                    $createdGroup = $createGroupResponse

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created group with id [$($createdGroup.id)], displayName [$($createdGroup.displayName)] and externalId [$($createdGroup.externalId)]  for resource: $($resource | ConvertTo-Json)."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create group with display_name [$($createGroupBody.display_name)] and external_id [$($createGroupBody.external_id)]  for resource: $($resource | ConvertTo-Json)."
                }
                #endregion Create group

                break
            }

            "CorrelateResource" {
                #region Correlate group
                $actionMessage = "correlating to group for resource: $($resource | ConvertTo-Json)"

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Information "Correlated to group with id [$($correlatedResource.id)] on [$($correlationField)] = [$($correlationValue)]."
                }
                else {
                    Write-Warning "DryRun: Would correlate to group with id [$($correlatedResource.id)] on [$($correlationField)] = [$($correlationValue)]."
                }
                #endregion Correlate group

                break
            }
        }
        #endregion Process
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-SDB-IdentityError -ErrorObject $ex
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
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}