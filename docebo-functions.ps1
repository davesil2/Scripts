<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER ClientID

.PARAMETER ClientSecret

.PARAMETER Credentials

.PARAMETER GrantType
#>
function Get-DoceboAuthToken {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$ClientID,
        [Parameter(Mandatory=$true)]
        [String]$ClientSecret,
        [Parameter(Mandatory=$true)]
        [pscredential]$Credentials,
        [string]$GrantType = 'password'
    )

    # configure URL to connect to
    [System.UriBuilder]$URI = ('https://{0}/oauth2/token' -f $FQDN)

    # configure body contents for assertion
    $Body = @{
        client_id       = $ClientID
        client_secret   = $ClientSecret
        grant_type      = $GrantType
    }

    if ($GrantType -eq 'password' -and $Credentials) {
        $Body += @{
            username = $Credentials.UserName
            password = $Credentials.GetNetworkCredential().Password
        }
    }

    $parameters = @{
        Method      = 'POST'
        URI         = $URI.Uri
        Body        = $Body
        ErrorAction = 'SilentlyContinue'
    }

    $Response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.access_token
    } else {
        Write-Error ('[ERROR] - An error occured authenticating')
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER Token

#>
function Get-DoceboUsers {
    param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [string]$Token,
        [switch]$ActiveUsers,
        [string]$SearchText
    )

    [System.UriBuilder]$URI = ('https://{0}/manage/v1/user' -f $FQDN)

    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    if ($ActiveUsers.ToBool()) {
        $Query.Add('active','true')
    }
    if ($SearchText) {
        $Query.Add('search_text',$SearchText)
    }
    $URI.Query = $Query.ToString()

    $headers = @{
        "Authorization"     = ('Bearer {0}' -f $Token)
        "Content-Type"      = 'application/json'
    }

    $body = @{
        not_paginated = 'true'
    }

    $parameters = @{
        Method      = 'GET'
        URI         = $URI.Uri
        Headers     = $Headers
        Body        = $Body
        ErrorAction = 'SilentlyContinue'
    }

     $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.data.items
    } else {
        Write-Error 'There was a problem retrieving the data'
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER Token

.PARAMETER UserID

#>
function Get-DoceboUserDetails {
    param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$UserID
    )
    
    [System.UriBuilder]$URI = ('https://{0}/manage/v1/user/{1}' -f $FQDN,$UserID)
    
    $headers = @{
        "Authorization"     = ('Bearer {0}' -f $Token)
        "Content-Type"      = 'application/json'
    }

    $parameters = @{
        Method      = 'GET'
        URI         = $URI.Uri
        Headers     = $headers
        ErrorAction = 'SilentlyContinue'
    }

    Write-Verbose ('[INFO] - URI for Query {0}' -f $uri.Uri)

    $response = Invoke-RestMethod @parameters

    if ($Response) {
        return $Response.data.user_data
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER Token

#>
function Get-DoceboBranches {
    param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$NodeID,
        [string]$SearchText,
        [string]$SearchType,
        [switch]$Flattened
    )

    # build uri
    [System.UriBuilder]$URI = ('https://{0}/manage/v1/orgchart' -f $FQDN)

    # configure query values
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    if ($NodeID) {
        $Query.Add('node_id',$NodeID)
    }
    if ($SearchText) {
        $Query.Add('search_text',$SearchText)
    }
    if ($SearchType) {
        $Query.Add('search_type',$SearchType)
    }
    if ($Flatten) {
        $Query.Add('flattened',$flatten.ToString())
    }
    $URI.Query = $Query.ToString()

    # set header config
    $headers = @{
        "Authorization"     = ('Bearer {0}' -f $Token)
        "Content-Type"      = 'application/json'
    }

    # setup parameters for execution
    $parameters = @{
        URI         = $uri.uri
        Method      = 'Get'
        ErrorAction = 'SilentlyContinue'
        Headers     = $Headers
        Body        = $body
    }

    Write-Verbose ('[INFO] - URI for Query {0}' -f $uri.Uri)

    $response = Invoke-RestMethod @parameters
    
    if ($response) {
        return $response.data.items
    }
}

function Disable-DoceboUser {
    param(
        [parameter(Mandatory=$true)]
        [String]$FQDN,
        [parameter(Mandatory=$true)]
        [String]$Token,
        [parameter(Mandatory=$true)]
        [String]$UserID
    )

    # build uri for execution
    [System.UriBuilder]$URI = ('https://{0}/manage/v1/user/change_status' -f $FQDN)

    # setup headers
    $headers = @{
        "Authorization"     = ('Bearer {0}' -f $Token)
        "Content-Type"      = 'application/json'
    }

    # set values for change
    $body = [pscustomobject]@{
        status      = 0
        user_ids    = $UserID
    }

    # setup parameters for execution
    $parameters = @{
        Method      = 'PUT'
        URI         = $URI.Uri
        Headers     = $headers
        Body        = ([system.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json)))
        ErrorAction = 'SilentlyContinue'
    }

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response
    }
}

function Update-DoceboUser {
    param(
        [parameter(Mandatory=$true)]
        [String]$FQDN,
        [parameter(Mandatory=$true)]
        [String]$Token,
        [parameter(Mandatory=$true)]
        [String]$UserID,
        [String]$FirstName,
        [String]$LastName,
        [String]$Email,
        [DateOnly]$ExpirationDate,
        [parameter(Mandatory=$false)]
        [String]$Role,
        [String]$Manager,
        [String]$ManagerID,
        [String]$BranchID,
        [String]$Location,
        [String]$Department,
        [String]$Division,
        [String]$Title,
        [String]$Function,
        [String]$EmploymentType,
        [String]$OvertimeStatus,
        [DateOnly]$HireDate,
        [String]$DisplayName,
        [String]$EmployeeNumber,
        [String]$AssociateID,
        [String]$EmployeeID
    )

    $DoceboUser = Get-DoceboUserDetails `
        -FQDN $FQDN `
        -Token $Token `
        -UserID $UserID

    $body = @()
    $additional_fields = @()

    if ($DoceboUser) {
        If ($DoceboUser.first_name -ne $FirstName) {
            $body += [pscustomobject]@{first_name = $FirstName}
        }
        if ($DoceboUser.last_name -ne $LastName) {
            $body += [pscustomobject]@{last_name = $LastName}
        }
        if ($DoceboUser.Email -ne $Email) {
            $body += [pscustomobject]@{email = $Email}
        }
        if ($DoceboUser.Expiration_Date -ne $ExpirationDate) {
            $body += [pscustomobject]@{expiration_date = $ExpirationDate}
        }
        if ($DoceboUser.field_1 -ne $Department) {
            $additional_fields += [pscustomobject]@{id = 1; value = $Department}
        }
        if ($DoceboUser.field_7 -ne $Location) {
            $additional_fields += [pscustomobject]@{id = 7; value = $Location}
        }
        if ($DoceboUser.field_8 -ne $Division) {
            $additional_fields += [pscustomobject]@{id = 8; value = $Division}
        }
        if ($DoceboUser.field_9 -ne $Title) {
            $additional_fields += [pscustomobject]@{id = 9; value = $Title}
        }
        if ($DoceboUser.field_10 -ne $Function) {
            $additional_fields += [pscustomobject]@{id = 10; value = $Function}
        }
        if ($DoceboUser.field_11 -ne $EmploymentType) {
            $additional_fields += [pscustomobject]@{id = 11; value = $EmploymentType}
        }
        if ($DoceboUser.field_12 -ne $OvertimeStatus) {
            $additional_fields += [pscustomobject]@{id = 12; value = $OvertimeStatus}
        }
        if ($DoceboUser.field_13 -ne $DisplayName) {
            $additional_fields += [pscustomobject]@{id = 13; value = $DisplayName}
        }
        if ($DoceboUser.field_15 -ne $EmployeeNumber) {
            $additional_fields += [pscustomobject]@{id = 15; value = $EmployeeNumber}
        }
        if ($DoceboUser.field_16 -ne $AssociateID) {
            $additional_fields += [pscustomobject]@{id = 16; value = $AssociateID}
        }
        if ($DoceboUser.field_17 -ne $EmployeeID) {
            $additional_fields += [pscustomobject]@{id = 17; value = $EmployeeID}
        }
        if ($DoceboUser.field_19 -ne $ManagerName) {
            $additional_fields += [pscustomobject]@{id = 19; value = $ManagerName}
        }
        if ($DoceboUser.manager_names.1 -ne $managerID) {
            $body += [pscustomobject]@{manager = [pscustomobject]@{1 = $managerID}}
        }
    }

    if ($body -or $additional_fields) {
        # build uri string
        [System.UriBuilder]$URI = ('https://{0}/manage/v1/user/{1}' -f $FQDN,$UserID)

        # build headers
        $headers = @{
            "Authorization"     = ('Bearer {0}' -f $Token)
            "Content-Type"      = 'application/json'
        }

        # generate full body if other fields are updated
        if ($additional_fields) {
            $body += [pscustomobject]@{additiona_fields = $additional_fields}
        }

        # assign parameters
        $parameters = @{
            Method      = 'PUT'
            URI         = $URI.Uri
            Headers     = $headers
            Body        = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json)))
            ErrorAction = 'silentlyContinue'
        }

        $response = Invoke-RestMethod @parameters

        if ($response) {
            return $response
        }
    }
}

function Get-DoceboBranchDetails {
    param(
        [String]$FQDN,
        [String]$Token,
        [String]$BranchID,
        [Switch]$UseSecondaryID,
        [Switch]$IncludePath
    )

    [System.UriBuilder]$URI = ('https://{0}/manage/v1/orgchart/{1}' -f $FQDN, $BranchID)

    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    if ($UseSecondaryID.ToBool()) {
        $Query.Add('use_secondary_identifier','true')
    }
    if ($IncludePath.ToBool()) {
        $Query.Add('include_path','true')
    }
    $URI.Query = $Query.ToString()

    $headers = @{
        "Authorization"     = ('Bearer {0}' -f $Token)
        "Content-Type"      = 'application/json'
    }

    $parameters = @{
        Method      = 'GET'
        URI         = $URI.Uri
        Headers     = $headers
        ErrorAction = 'Silentlycontinue'
    }

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.data
    }
}

function Move-DoceboUserBranch {
    param(
        $FQDN,
        $Token,
        $UserID,
        $BranchID
    )

    $Branch = Get-DoceboBranchDetails -FQDN $FQDN -Token $token -BranchID $BranchID -IncludePath

    if ($Branch) {
        [System.UriBuilder]$URI = ('https://{0}/manage/v1/user/move_to_branch' -f $FQDN)

        $headers = @{
            "Authorization"     = ('Bearer {0}' -f $Token)
            "Content-Type"      = 'application/json'
        }

        $body = @{
            user_ids    = @($UserID)
            branch_ids  = @($BranchID)
        }

        $parameters = @{
            Method      = 'GET'
            URI         = $URI.Uri
            Headers     = $headers
            Body        = ($body | convertto-json)
            ErrorAction = 'silentlycontinue'
        }

        $response = Invoke-RestMethod @parameters

        if ($response) {
            return $response.success
        }
    }
}