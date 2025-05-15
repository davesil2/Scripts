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
        Verbose     = $false
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
        [parameter(Mandatory=$true)]
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
        Verbose     = $false
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
        Verbose     = $false
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
        Verbose     = $false
    }

    Write-Verbose ('[INFO] - URI for Query {0}' -f $uri.Uri)

    $response = Invoke-RestMethod @parameters
    
    if ($response) {
        return $response.data.items
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
        Verbose     = $false
    }

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER Token

.PARAMETER UserID

.PARAMETER FirstName

.PARAMETER LastName

.PARAMETER Email

.PARAMETER ExpirationDate

.PARAMETER Role

.PARAMETER Manager

.PARAMETER ManagerID

.PARAMETER BranchID

.PARAMETER Location

.PARAMETER Department

.PARAMETER Division

.PARAMETER Title

.PARAMETER Function

.PARAMETER EmploymentType

.PARAMETER OvertimeStatus

.PARAMETER HireDate

.PARAMETER EmployeeNumber

.PARAMETER AssociateID

.PARAMETER EmployeeID

#>
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
        [String]$EmployeeNumber,
        [String]$AssociateID,
        [String]$EmployeeID,
        [validateset('yes','no')]
        [String]$PeopleManager
    )

    Write-Verbose ('[INFO] - Looking for User [{0}]' -f $DoceboUser.user_id)

    $DoceboUser = Get-DoceboUserDetails `
        -FQDN $FQDN `
        -Token $Token `
        -UserID $UserID

    $DoceboUser = Get-DoceboUsers `
        -FQDN $FQDN `
        -Token $Token `
        -SearchText $DoceboUser.username

    $body = [pscustomobject]@{}
    $additional_fields = @()

    if ($DoceboUser) {
        Write-Verbose ('[INFO] - Found Docebo User [{0}]' -f $DoceboUser.username)

        try {
            $DoceboHireDate = ([datetime]$DoceboUser.field_19).ToString('yyyy-MM-dd')
        } Catch {
            $DoceboHireDate = $null 
        }

        If ($DoceboUser.first_name -ne $FirstName) {
            $body | Add-Member -Name 'firstname' -Value $FirstName -MemberType NoteProperty
            Write-Verbose ('[INFO] - First Name in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.first_name,$FirstName)
        }
        if ($DoceboUser.last_name -ne $LastName) {
            $body | Add-Member -Name 'lastname' -Value $LastName -MemberType NoteProperty
            Write-Verbose ('[INFO] - Last Name in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.last_name,$LastName)
        }
        if ($DoceboUser.Email -ne $Email) {
            $body | Add-Member -Name 'email' -Value $Email -MemberType NoteProperty
            Write-Verbose ('[INFO] - Email in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.email,$Email)
        }
        if ($DoceboUser.Expiration_Date -ne $ExpirationDate) {
            $body | Add-Member -Name 'expiration_date' -Value $ExpirationDate -MemberType NoteProperty
            Write-Verbose ('[INFO] - Expiration Date in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.expiration_date,$ExpirationDate)
        }
        if ($DoceboUser.field_1 -ne $Department) {
            $additional_fields += [pscustomobject]@{id = 1; value = $Department}
            Write-Verbose ('[INFO] - Department in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.Department,$Department)
        }
        if ($DoceboUser.field_7 -ne $Location) {
            $additional_fields += [pscustomobject]@{id = 7; value = $Location}
            Write-Verbose ('[INFO] - Location in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_7,$Location)
        }
        if ($DoceboUser.field_8 -ne $Division) {
            $additional_fields += [pscustomobject]@{id = 8; value = $Division}
            Write-Verbose ('[INFO] - Division in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_8,$Division)
        }
        if ($DoceboUser.field_9 -ne $Title) {
            $additional_fields += [pscustomobject]@{id = 9; value = $Title}
            Write-Verbose ('[INFO] - Title in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.Title,$Title)
        }
        if ($DoceboUser.field_10 -ne $Function) {
            $additional_fields += [pscustomobject]@{id = 10; value = $Function}
            Write-Verbose ('[INFO] - Function in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_10,$Function)
        }
        if ($DoceboUser.field_11 -ne $EmploymentType) {
            $additional_fields += [pscustomobject]@{id = 11; value = $EmploymentType}
            Write-Verbose ('[INFO] - Employment Type in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_11,$EmploymentType)
        }
        if ($DoceboUser.field_12 -ne $OvertimeStatus) {
            $additional_fields += [pscustomobject]@{id = 12; value = $OvertimeStatus}
            Write-Verbose ('[INFO] - Overtime Status in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_12,$OvertimeStatus)
        }
        if ($DoceboUser.field_13 -ne $Manager) {
            $additional_fields += [pscustomobject]@{id = 13; value = $ADManager.DisplayName}
            Write-Verbose ('[INFO] - Manager Display Name in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_13,$Manager)
        }
        if ($DoceboUser.field_15 -ne $EmployeeNumber) {
            $additional_fields += [pscustomobject]@{id = 15; value = $EmployeeNumber}
            Write-Verbose ('[INFO] - Employee Number in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_15,$EmployeeNumber)
        }
        if ($DoceboUser.field_16 -ne $AssociateID) {
            $additional_fields += [pscustomobject]@{id = 16; value = $AssociateID}
            Write-Verbose ('[INFO] - Associate ID in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_16,$AssociateID)
        }
        if ($DoceboUser.field_17 -ne $EmployeeID) {
            $additional_fields += [pscustomobject]@{id = 17; value = $EmployeeID}
            Write-Verbose ('[INFO] - Employee ID in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_17,$EmployeeID)
        }
        if ($DoceboHireDate.ToString() -ne $HireDate -and $HireDate.ToString()) {
            $additional_fields += [pscustomobject]@{id = 19; value = $HireDate}
            Write-Verbose ('[INFO] - Manager Name in [Docebo: {0}] does not match provided [{1}]' -f $DoceboHireDate,$HireDate)
        }
        if ($DoceboUser.field_26 -ne $PeopleManager) {
            $additional_fields += [pscustomobject]@{id = 26; value = $PeopleManager}
            Write-Verbose ('[INFO] - People Manager State [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.field_26,$PeopleManager)
        }
        if ($DoceboUser.manager_names.'1'.manager_id -ne $managerID) {
            $body | Add-Member -Name manager -Value ([pscustomobject]@{'1' = $managerId}) -MemberType NoteProperty
            Write-Verbose ('[INFO] - Manager ID in [Docebo: {0}] does not match provided [{1}]' -f $DoceboUser.manager_names.'1'.manager_id,$ManagerID)
        }
    }

    if ((($body.psobject.Members | ?{$_.membertype -eq 'noteproperty'}).count -gt 1) -or $additional_fields) {
        # build uri string
        [System.UriBuilder]$URI = ('https://{0}/manage/v1/user/{1}' -f $FQDN,$UserID)

        # build headers
        $headers = @{
            "Authorization"     = ('Bearer {0}' -f $Token)
            "Content-Type"      = 'application/json'
        }

        # generate full body if other fields are updated
        if ($additional_fields) {
            $body | Add-Member -Name additional_fields -value $additional_fields -MemberType NoteProperty
        }

        Write-Verbose ('[INFO] - Update Info for Body [{0}]' -f ($body | out-string))

        # assign parameters
        $parameters = @{
            Method      = 'PUT'
            URI         = $URI.Uri
            Headers     = $headers
            Body        = ($body | ConvertTo-Json)
            ErrorAction = 'silentlyContinue'
            ContentType = 'application/json'
            Verbose     = $false
        }

        $response = Invoke-RestMethod @parameters

        if ($response) {
            #return $response
            return @{Changes=$body;Success=$response.data.success}
        }
    } else {
        return @{Changes='';Success=$true}
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER Token

.PARAMETER BranchID

.PARAMETER UseSecondaryID

.PARAMETER IncludePath

#>
function Get-DoceboBranchDetails {
    param(
        [parameter(Mandatory=$true)]
        [String]$FQDN,
        [parameter(Mandatory=$true)]
        [String]$Token,
        [parameter(Mandatory=$true)]
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
        Verbose     = $false
    }

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.data
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER Token

.PARAMETER UserID

.PARAMETER BranchID

#>
function Move-DoceboUserBranch {
    param(
        [parameter(Mandatory=$true)]
        $FQDN,
        [parameter(Mandatory=$true)]
        $Token,
        [parameter(Mandatory=$true)]
        $UserID,
        [parameter(Mandatory=$true)]
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
            Verbose     = $false
        }

        $response = Invoke-RestMethod @parameters

        if ($response) {
            return $response.success
        }
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER FQDN

.PARAMETER Token

.PARAMETER Code

.PARAMETER ParentID

.PARAMETER translations

#>
function New-DoceboBranch {
    param(
        $FQDN,
        $Token,
        $Code,
        $ParentID,
        $translations = @{all=$Code}
    )

    [System.UriBuilder]$URI = ('https://{0}/manage/v1/orgchart' -f $FQDN)

    $headers = @{
        "Authorization" = ('Bearer {0}' -f $Token)
        "Content-Type"  = 'application/json'
    }

    $body = @{
        code = $Code
        id_parent = $ParentID
        translations = $translations
    }

    $parameters = @{
        Method      = 'POST'
        URI         = $URI.Uri
        Headers     = $headers
        Body        = ($body | convertto-json)
        ErrorAction = 'silentlycontinue'
        ContentType = 'application/json'
        Verbose     = $false
    }

    $response = Invoke-RestMethod @parameters

    If ($response) {
        return $response.data
    }
}

function New-DoceboUser {
    param(
        [String]$FQDN,
        [String]$Token,
        [String]$Email,
        [String]$Password,
        [String]$FirstName,
        [String]$LastName,
        [String]$BranchID,
        [Switch]$Nofity
    )

    [System.UriBuilder]$URI = ('https://{0}/manage/v1/user' -f $FQDN)

    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }

    $body = @{
        email                   = $Email
        firstname               = $FirstName
        lastname                = $LastName
        email_validation_status = '1'
        send_notification_email = $Notify.ToString()
        select_orgchart         = @{$BranchID = 0}
    }
}